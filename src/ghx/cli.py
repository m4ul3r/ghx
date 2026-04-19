"""ghx CLI — declarative @command()-decorated parser tree.

Each command is registered with a single ``@command(*path, ...)`` decorator.
The framework walks the registry to build the argparse tree, adds common
options (``--format``, ``--out``, ``--instance``, ``-t/--target``, paging,
address filters), and binds the handler.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Any, Callable

from .output import DEFAULT_SPILL_TOKEN_LIMIT, write_output_result
from .paths import (
    bridge_registry_path,
    claude_skills_dir,
    instances_dir,
    repo_root,
)
from .transport import (
    BridgeError,
    choose_instance,
    list_instances,
    send_request,
    spawn_instance,
    _find_ghx_agent,
)
from .version import VERSION, build_id_for_file


# ---------------------------------------------------------------------------
# Help + parser base class
# ---------------------------------------------------------------------------


class _HelpFullAction(argparse.Action):
    """`--help-full` prints help for this parser and every subcommand beneath it."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest, nargs=0, default=default, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        if isinstance(parser, GhxArgumentParser):
            parser.print_full_help()
        else:
            parser.print_help()
        parser.exit()


class GhxArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Each parser plants a self-reference in its defaults; argparse applies
        # child-parser defaults after parent defaults, so `ns._parser` always
        # points to the deepest reached parser. Used by main() to print a
        # context-aware help when a command group is invoked without a
        # subcommand (e.g. `ghx target` prints target's help, not root's).
        self.set_defaults(_parser=self)
        self.add_argument(
            "--help-full",
            action=_HelpFullAction,
            help="Show help for this command and every subcommand",
        )

    def _iter_full_help_parsers(self):
        parsers: list[argparse.ArgumentParser] = [self]
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                for parser in action.choices.values():
                    if isinstance(parser, GhxArgumentParser):
                        parsers.extend(parser._iter_full_help_parsers())
                    else:
                        parsers.append(parser)
        return parsers

    def format_full_help(self) -> str:
        sections: list[str] = []
        seen: set[int] = set()
        for parser in self._iter_full_help_parsers():
            if id(parser) in seen:
                continue
            seen.add(id(parser))
            sections.append(parser.format_help().rstrip())
        return "\n\n".join(sections) + "\n"

    def print_full_help(self, file=None) -> None:
        if file is None:
            file = sys.stdout
        self._print_message(self.format_full_help(), file)


# ---------------------------------------------------------------------------
# Common option helpers
# ---------------------------------------------------------------------------


def _common_io_options(parser: argparse.ArgumentParser, *, default_format: str = "text") -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json", "ndjson"),
        default=None,
        help=f"Output format (default: {default_format}; env GHX_FORMAT)",
    )
    parser.set_defaults(_default_format=default_format)
    parser.add_argument(
        "--out",
        default=None,
        help="Write rendered output to PATH and print an envelope summary",
    )


def _instance_option(parser: argparse.ArgumentParser, *, is_root: bool = False) -> None:
    parser.add_argument(
        "--instance",
        default=os.environ.get("GHX_INSTANCE") if is_root else argparse.SUPPRESS,
        help="Bridge instance id (env: GHX_INSTANCE)",
    )


def _target_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-t",
        "--target",
        default=None,
        help="Target program selector (program_id, basename, filename, or 'active')",
    )


def _add_paged_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=None)


def _add_function_address_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--min-address", default=None,
                        help="Only include functions starting at or above this address")
    parser.add_argument("--max-address", default=None,
                        help="Only include functions starting at or below this address")


# ---------------------------------------------------------------------------
# Declarative command registration
# ---------------------------------------------------------------------------


_COMMANDS: list[dict[str, Any]] = []

_GROUP_HELP: dict[tuple[str, ...], str] = {
    ("skill",): "Install the bundled Claude Code skill",
    ("session",): "Manage ghx-agent daemon processes",
    ("target",): "Inspect loaded programs",
    ("function",): "Function inspection",
    ("types",): "Data type manager",
    ("symbol",): "Symbol mutations",
    ("comment",): "Comment mutations",
    ("proto",): "Function prototype get/set",
    ("local",): "Local variable rename/retype",
    ("struct",): "Structure edits",
    ("struct", "field"): "Operate on struct fields",
    ("bundle",): "Composite artifact exports",
    ("batch",): "Batch-apply multiple mutations in one transaction",
    ("py",): "Run Python inside the daemon",
}


def arg(*flags: str, **kwargs: Any) -> tuple[tuple[str, ...], dict[str, Any]]:
    """Argument spec for :func:`command`."""
    return (flags, kwargs)


def mutex(required: bool, *args: tuple[tuple[str, ...], dict[str, Any]]) -> tuple[
    bool, list[tuple[tuple[str, ...], dict[str, Any]]]
]:
    """Mutually-exclusive argument-group spec for :func:`command`."""
    return (required, list(args))


def command(
    *path: str,
    help: str = "",
    fmt: str = "text",
    target: bool = False,
    paged: bool = False,
    address_filter: bool = False,
    args: list[tuple[tuple[str, ...], dict[str, Any]]] | None = None,
    mutex_groups: list[tuple[bool, list[tuple[tuple[str, ...], dict[str, Any]]]]] | None = None,
) -> Callable:
    """Register a CLI command declaratively."""

    def decorator(fn: Callable[[argparse.Namespace], int]) -> Callable[[argparse.Namespace], int]:
        _COMMANDS.append(
            {
                "path": path,
                "handler": fn,
                "help": help,
                "fmt": fmt,
                "target": target,
                "paged": paged,
                "address_filter": address_filter,
                "args": args or [],
                "mutex_groups": mutex_groups or [],
            }
        )
        return fn

    return decorator


def _build_from_commands(root: GhxArgumentParser) -> None:
    """Populate *root* with subcommands from the ``_COMMANDS`` registry."""
    subparser_actions: dict[tuple[str, ...], argparse._SubParsersAction] = {}
    node_parsers: dict[tuple[str, ...], argparse.ArgumentParser] = {(): root}

    def _get_subparsers(parent: tuple[str, ...]) -> argparse._SubParsersAction:
        if parent not in subparser_actions:
            dest = "_".join(parent) + "_command" if parent else "command"
            subparser_actions[parent] = node_parsers[parent].add_subparsers(
                dest=dest, parser_class=GhxArgumentParser
            )
        return subparser_actions[parent]

    def _ensure_intermediate(path: tuple[str, ...]) -> argparse.ArgumentParser:
        if path in node_parsers:
            return node_parsers[path]
        if len(path) > 1:
            _ensure_intermediate(path[:-1])
        sub = _get_subparsers(path[:-1])
        parser = sub.add_parser(path[-1], help=_GROUP_HELP.get(path, ""))
        node_parsers[path] = parser
        return parser

    for spec in sorted(_COMMANDS, key=lambda s: len(s["path"])):
        path = spec["path"]
        parent = path[:-1]

        if parent:
            _ensure_intermediate(parent)

        if path in node_parsers:
            cmd = node_parsers[path]
        else:
            cmd = _get_subparsers(parent).add_parser(path[-1], help=spec["help"])
            node_parsers[path] = cmd

        _common_io_options(cmd, default_format=spec["fmt"])
        _instance_option(cmd)
        if spec["target"]:
            _target_option(cmd)
        if spec["address_filter"]:
            _add_function_address_args(cmd)
        if spec["paged"]:
            _add_paged_args(cmd)

        for flags, kwargs in spec["args"]:
            cmd.add_argument(*flags, **kwargs)

        for required, group_args in spec["mutex_groups"]:
            group = cmd.add_mutually_exclusive_group(required=required)
            for flags, kwargs in group_args:
                group.add_argument(*flags, **kwargs)

        cmd.set_defaults(func=spec["handler"])


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------


def _resolve_format(ns: argparse.Namespace, default: str | None = None) -> str:
    fmt = getattr(ns, "format", None)
    if fmt:
        return fmt
    return os.environ.get("GHX_FORMAT") or default or getattr(ns, "_default_format", "text")


def _resolve_out(ns: argparse.Namespace) -> Path | None:
    out = getattr(ns, "out", None)
    if out:
        return Path(out).expanduser()
    return None


def _resolve_spill_limit(ns: argparse.Namespace) -> int:
    env = os.environ.get("GHX_SPILL_TOKENS")
    if env:
        try:
            return int(env)
        except ValueError:
            pass
    return DEFAULT_SPILL_TOKEN_LIMIT


def _command_stem(ns: argparse.Namespace) -> str:
    parts: list[str] = []
    for attr in ("command", "_command"):
        v = getattr(ns, attr, None)
        if v:
            parts.append(str(v))
            break
    for attr in ("subcommand",):
        v = getattr(ns, attr, None)
        if v:
            parts.append(str(v))
    if not parts:
        parts = ["ghx"]
    return "-".join(parts).replace(" ", "_")


def _emit(result: Any, ns: argparse.Namespace, *, text_renderer=None) -> None:
    fmt = _resolve_format(ns)
    out_path = _resolve_out(ns)
    spill_limit = _resolve_spill_limit(ns)

    if fmt == "text" and text_renderer is not None:
        buf = io.StringIO()
        text_renderer(result, buf)
        rendered_value: Any = buf.getvalue()
    elif fmt == "text" and not isinstance(result, str):
        fmt = "json"
        rendered_value = result
    else:
        rendered_value = result

    rendered = write_output_result(
        rendered_value,
        fmt=fmt,
        out_path=out_path,
        stem=_command_stem(ns),
        spill_token_limit=spill_limit,
    )
    sys.stdout.write(rendered.rendered)


def _send(op: str, ns: argparse.Namespace, **params: Any) -> dict[str, Any]:
    """Shared request helper: cleans out Nones, passes target + instance."""
    payload = {k: v for k, v in params.items() if v is not None}
    return send_request(
        op,
        params=payload,
        target=getattr(ns, "target", None),
        instance_id=getattr(ns, "instance", None),
        timeout=getattr(ns, "_transport_timeout", None),
    )


# ---------------------------------------------------------------------------
# Shared text renderers
# ---------------------------------------------------------------------------


def _current_bridge_build_id() -> str | None:
    """Return the SHA-256 prefix of the current plugin/ghx_agent_bridge/bridge.py.

    Used by ``ghx doctor`` to detect a daemon running stale code. Returns
    None for non-editable installs where the plugin directory isn't present
    next to the installed ``ghx`` script.
    """
    try:
        bridge = (
            Path(__file__).resolve().parents[2]
            / "plugin"
            / "ghx_agent_bridge"
            / "bridge.py"
        )
        if not bridge.exists():
            return None
        return build_id_for_file(bridge)
    except Exception:
        return None


def _render_doctor(payload: dict[str, Any], out) -> None:
    out.write(f"ghx       {payload.get('ghx_version', '?')}\n")
    out.write(f"ghidra    {payload.get('ghidra_version', '?')}\n")
    out.write(f"install   {payload.get('ghidra_install_dir', '?')}\n")
    proj_kind = " [ephemeral]" if payload.get("project_ephemeral") else ""
    out.write(
        f"project   {payload.get('project_name', '?')} at "
        f"{payload.get('project_path', '?')}{proj_kind}\n"
    )
    out.write(f"instance  {payload.get('instance_id', '?')}  pid={payload.get('pid', '?')}\n")
    out.write(f"socket    {payload.get('socket_path', '?')}\n")
    if payload.get("stale"):
        out.write(
            f"WARN      daemon is running stale bridge code "
            f"(daemon={payload.get('plugin_build_id')}, "
            f"current={payload.get('plugin_build_id_current')}). "
            f"Run `ghx session stop` and retry to pick up new code.\n"
        )
    targets = payload.get("targets", []) or []
    out.write(f"targets   {len(targets)} loaded\n")
    for t in targets:
        marker = "*" if t.get("active") else " "
        out.write(
            f"  {marker} {t.get('program_id')}  {t.get('basename')}  "
            f"[{t.get('language')}]  size={t.get('size')}\n"
        )


def _render_mutation(result: dict[str, Any], out) -> None:
    status = result.get("status", "?")
    tag = "preview" if result.get("preview") else ("committed" if result.get("committed") else "aborted")
    out.write(f"{status}  ({tag})\n")
    out.write(f"  description  {result.get('description')}\n")
    before = result.get("before", {}) or {}
    after = result.get("after", {}) or {}
    obs = result.get("observed_after")
    for key in sorted(set(before) | set(after)):
        bv = before.get(key)
        av = after.get(key)
        if bv == av:
            continue
        out.write(f"  {key}: {bv!r} -> {av!r}\n")
    if obs is not None:
        out.write(f"  observed_after: {obs!r}\n")


def _render_function_text(result: dict[str, Any], out, header_suffix: str = "") -> None:
    fn = result.get("function", {})
    out.write(f"// {fn.get('name')} @ {fn.get('address')}{header_suffix}\n")
    text = result.get("text", "") or ""
    out.write(text)
    if not text.endswith("\n"):
        out.write("\n")


# ---------------------------------------------------------------------------
# Skill install
# ---------------------------------------------------------------------------


def _install_tree(source: Path, dest: Path, *, mode: str, force: bool) -> None:
    if not source.exists():
        raise BridgeError(f"source skill directory is missing: {source}")

    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists() or dest.is_symlink():
        if not force:
            raise BridgeError(
                f"destination already exists: {dest} (pass --force to overwrite)"
            )
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)

    if mode == "copy":
        shutil.copytree(source, dest)
    else:
        os.symlink(source, dest, target_is_directory=True)


@command(
    "skill", "install", help="Install the bundled Claude Code skill",
    fmt="json",
    args=[
        arg("--dest", type=Path, default=None,
            help="Custom install destination (default: ~/.claude/skills)"),
        arg("--mode", choices=("symlink", "copy"), default="symlink"),
        arg("--force", action="store_true"),
    ],
)
def cmd_skill_install(ns: argparse.Namespace) -> int:
    skills_root = repo_root() / "skills"
    if not skills_root.is_dir():
        print(f"ghx skill install: no skills directory at {skills_root}",
              file=sys.stderr)
        return 2

    results = []
    for source in sorted(skills_root.iterdir()):
        if not source.is_dir() or not (source / "SKILL.md").exists():
            continue
        dest_parent = ns.dest or claude_skills_dir()
        dest = dest_parent / source.name
        try:
            _install_tree(source, dest, mode=ns.mode, force=ns.force)
        except BridgeError as exc:
            print(f"ghx skill install: {exc}", file=sys.stderr)
            return 1
        results.append({
            "skill": source.name,
            "source": str(source),
            "destination": str(dest),
        })

    payload = {"installed": True, "mode": ns.mode, "skills": results}

    def _render(p, out):
        for entry in p["skills"]:
            out.write(
                f"installed  {entry['skill']}  "
                f"({p['mode']})  -> {entry['destination']}\n"
            )
        if not p["skills"]:
            out.write("(no SKILL.md entries found under skills/)\n")

    _emit(payload, ns, text_renderer=_render)
    return 0


# ---------------------------------------------------------------------------
# Lifecycle commands
# ---------------------------------------------------------------------------


@command("doctor", help="Report daemon + Ghidra versions and targets")
def cmd_doctor(ns: argparse.Namespace) -> int:
    try:
        response = send_request("doctor", instance_id=ns.instance)
    except BridgeError as exc:
        print(f"ghx doctor: {exc}", file=sys.stderr)
        return 1
    result = response["result"]
    current_id = _current_bridge_build_id()
    if current_id is not None:
        result["plugin_build_id_current"] = current_id
        daemon_id = result.get("plugin_build_id")
        result["stale"] = bool(daemon_id and daemon_id != current_id)
    _emit(result, ns, text_renderer=_render_doctor)
    return 0


@command("session", "list", help="List running ghx-agent instances")
def cmd_session_list(ns: argparse.Namespace) -> int:
    instances = list_instances()
    if not instances:
        print("(no running ghx-agent instances)")
        return 0
    for inst in instances:
        print(
            f"{inst.instance_id or 'default'}  pid={inst.pid}  "
            f"socket={inst.socket_path}  started={inst.started_at}"
        )
    return 0


@command(
    "session", "start", help="Start a new ghx-agent daemon",
    args=[
        arg("--project", default=None,
            help="Persistent Ghidra project directory (default: ephemeral under $GHX_CACHE_DIR/projects)"),
        arg("--project-name", default=None,
            help="Ghidra project name (default: ghx-<instance_id>)"),
        arg("--install-dir", default=None,
            help="Ghidra installation directory (default: $GHIDRA_INSTALL_DIR or /opt/ghidra_12.0.4_PUBLIC)"),
    ],
)
def cmd_session_start(ns: argparse.Namespace) -> int:
    extra: list[str] = []
    if ns.project:
        extra += ["--project", ns.project]
    if ns.project_name:
        extra += ["--project-name", ns.project_name]
    if ns.install_dir:
        extra += ["--install-dir", ns.install_dir]
    try:
        inst = spawn_instance(instance_id=ns.instance, extra_args=extra or None)
    except BridgeError as exc:
        print(f"ghx session start: {exc}", file=sys.stderr)
        return 1
    print(f"started ghx-agent  instance={inst.instance_id or 'default'}  pid={inst.pid}")
    print(f"socket  {inst.socket_path}")
    return 0


@command("session", "stop", help="Stop a running ghx-agent daemon")
def cmd_session_stop(ns: argparse.Namespace) -> int:
    try:
        inst = choose_instance(ns.instance, auto_start=False)
    except BridgeError as exc:
        print(f"ghx session stop: {exc}", file=sys.stderr)
        return 1

    try:
        send_request("shutdown", instance_id=ns.instance, timeout=5.0)
    except BridgeError:
        pass

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not inst.socket_path.exists():
            break
        time.sleep(0.1)
    else:
        try:
            os.kill(inst.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    print(f"stopped  instance={inst.instance_id or 'default'}  pid={inst.pid}")
    return 0


@command(
    "load",
    help="Import a binary into the daemon's project",
    fmt="text",
    args=[
        arg("path", help="Path to the binary file"),
        arg("--timeout", type=float, default=120.0,
            help="Request timeout in seconds (default: 120; first-load analysis can be slow)"),
    ],
)
def cmd_load(ns: argparse.Namespace) -> int:
    path = Path(ns.path).expanduser().resolve()
    if not path.exists():
        print(f"ghx load: file not found: {path}", file=sys.stderr)
        return 2
    try:
        response = send_request(
            "load_binary",
            params={"path": str(path)},
            instance_id=ns.instance,
            timeout=ns.timeout,
        )
    except BridgeError as exc:
        print(f"ghx load: {exc}", file=sys.stderr)
        return 1

    def _render(p, out):
        out.write(
            f"loaded  {p.get('basename')}  id={p.get('program_id')}  "
            f"[{p.get('language')}]  size={p.get('size')}\n"
        )

    _emit(response["result"], ns, text_renderer=_render)
    return 0


@command("close", help="Release a loaded program", target=True)
def cmd_close(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "close_binary", ns,
            selector=ns.target,
        )
    except BridgeError as exc:
        print(f"ghx close: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns,
          text_renderer=lambda p, o: o.write(f"closed  {p.get('program_id')}\n"))
    return 0


@command("target", "list", help="List loaded programs")
def cmd_target_list(ns: argparse.Namespace) -> int:
    try:
        response = send_request("list_targets", instance_id=ns.instance)
    except BridgeError as exc:
        print(f"ghx target list: {exc}", file=sys.stderr)
        return 1
    targets = response["result"] or []

    def _render(rows, out):
        if not rows:
            out.write("(no targets loaded)\n")
            return
        for t in rows:
            marker = "*" if t.get("active") else " "
            out.write(
                f"{marker} {t.get('program_id')}  {t.get('basename')}  "
                f"[{t.get('language')}]  size={t.get('size')}\n"
            )

    _emit(targets, ns, text_renderer=_render)
    return 0


@command("refresh", help="Re-run auto-analysis on the selected target", target=True)
def cmd_refresh(ns: argparse.Namespace) -> int:
    try:
        response = _send("refresh", ns)
    except BridgeError as exc:
        print(f"ghx refresh: {exc}", file=sys.stderr)
        return 1

    def _render(r, out):
        out.write(f"refreshed  {r.get('program_id')}\n")
        log = r.get("message_log") or ""
        if log.strip():
            out.write("--- analysis log ---\n")
            out.write(log)
            if not log.endswith("\n"):
                out.write("\n")

    _emit(response["result"], ns, text_renderer=_render)
    return 0


@command(
    "save", help="Persist the current program to its project domain file",
    target=True,
    args=[arg("path", nargs="?", default=None,
              help="Unused in v1 (Ghidra saves to the existing DomainFile path)")],
)
def cmd_save(ns: argparse.Namespace) -> int:
    try:
        response = _send("save_database", ns, path=ns.path)
    except BridgeError as exc:
        print(f"ghx save: {exc}", file=sys.stderr)
        return 1

    def _render(r, out):
        out.write(f"saved  {r.get('path')}  (id={r.get('program_id')})\n")

    _emit(response["result"], ns, text_renderer=_render)
    return 0


@command("target", "info", help="Describe a loaded program", target=True)
def cmd_target_info(ns: argparse.Namespace) -> int:
    try:
        response = _send("target_info", ns, selector=ns.target)
    except BridgeError as exc:
        print(f"ghx target info: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns)
    return 0


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


@command(
    "decompile", help="Decompile a function to C", target=True,
    args=[
        arg("identifier", help="Function name or hex address"),
        arg("--timeout", type=int, default=60,
            help="Decompiler timeout in seconds (default: 60)"),
        arg("--addresses", action="store_true",
            help="Prefix each line with its minimum source address"),
        arg("--lines", default=None, metavar="START:END",
            help="Slice the output to lines START:END (1-indexed; either endpoint optional)"),
    ],
)
def cmd_decompile(ns: argparse.Namespace) -> int:
    try:
        response = send_request(
            "decompile",
            params={
                "identifier": ns.identifier,
                "timeout": ns.timeout,
                "addresses": ns.addresses,
            },
            target=ns.target,
            instance_id=ns.instance,
            timeout=ns.timeout + 5.0,
        )
    except BridgeError as exc:
        print(f"ghx decompile: {exc}", file=sys.stderr)
        return 1
    result = response["result"]
    if ns.lines:
        result = dict(result)
        result["text"] = _slice_lines(result.get("text", ""), ns.lines)
    _emit(result, ns, text_renderer=_render_function_text)
    return 0


def _slice_lines(text: str, spec: str) -> str:
    """Slice ``text`` to the 1-indexed line range ``START:END``."""
    lines = text.splitlines(keepends=True)
    start_s, _, end_s = spec.partition(":")
    start = int(start_s) if start_s else 1
    end = int(end_s) if end_s else len(lines)
    start = max(start, 1)
    end = min(end, len(lines))
    if start > end:
        return ""
    return "".join(lines[start - 1:end])


@command(
    "function", "list", help="List functions",
    target=True, paged=True, address_filter=True,
)
def cmd_function_list(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "list_functions", ns,
            min_address=ns.min_address,
            max_address=ns.max_address,
            offset=ns.offset,
            limit=ns.limit,
        )
    except BridgeError as exc:
        print(f"ghx function list: {exc}", file=sys.stderr)
        return 1
    rows = response["result"] or []

    def _render(rows, out):
        if not rows:
            out.write("(no functions)\n")
            return
        for r in rows:
            flags = []
            if r.get("is_thunk"):
                flags.append("thunk")
            if r.get("is_external"):
                flags.append("ext")
            tag = f" [{','.join(flags)}]" if flags else ""
            out.write(f"{r['address']:>12}  {r['name']}  (size={r['size']}){tag}\n")

    _emit(rows, ns, text_renderer=_render)
    return 0


@command(
    "function", "search", help="Search functions by name",
    target=True, paged=True,
    args=[
        arg("query"),
        arg("--regex", action="store_true"),
    ],
)
def cmd_function_search(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "search_functions", ns,
            query=ns.query, regex=ns.regex,
            offset=ns.offset, limit=ns.limit,
        )
    except BridgeError as exc:
        print(f"ghx function search: {exc}", file=sys.stderr)
        return 1
    rows = response["result"] or []

    def _render(rows, out):
        for r in rows:
            out.write(f"{r['address']:>12}  {r['name']}\n")

    _emit(rows, ns, text_renderer=_render)
    return 0


@command(
    "function", "info", help="Show a function's metadata", target=True,
    args=[
        arg("identifier"),
        arg("-v", "--verbose", action="store_true",
            help="Include stack offsets, return type, frame size, thunked target, etc."),
    ],
)
def cmd_function_info(ns: argparse.Namespace) -> int:
    try:
        response = _send("function_info", ns, identifier=ns.identifier,
                         verbose=ns.verbose)
    except BridgeError as exc:
        print(f"ghx function info: {exc}", file=sys.stderr)
        return 1
    result = response["result"]

    def _render(r, out):
        fn = r["function"]
        out.write(f"function    {fn['name']} @ {fn['address']}\n")
        out.write(f"prototype   {r.get('prototype', '?')}\n")
        out.write(f"conv        {r.get('calling_convention', '?')}\n")
        out.write(f"size        {r.get('size', 0)}\n")
        out.write(f"xrefs       {r.get('xref_count', 0)}\n")
        if r.get("is_thunk"):
            out.write("flags       thunk\n")
        if ns.verbose:
            if r.get("return_type"):
                out.write(f"return      {r['return_type']}\n")
            if r.get("stack_frame_size") is not None:
                out.write(f"frame_size  {r['stack_frame_size']}\n")
            if r.get("no_return"):
                out.write("flags       no_return\n")
            if "thunked" in r:
                t = r["thunked"]
                ext = " (external)" if t.get("is_external") else ""
                out.write(f"thunked     {t['name']} @ {t['address']}{ext}\n")
        out.write(f"parameters  ({len(r.get('parameters', []))})\n")
        for p in r.get("parameters", []):
            out.write(f"  {p['type']} {p['name']}  [{p.get('storage') or '?'}]\n")
        out.write(f"locals      ({len(r.get('locals', []))})\n")
        for lv in r.get("locals", []):
            extra = ""
            if ns.verbose and lv.get("stack_offset") is not None:
                extra = f"  stack={lv['stack_offset']:+d}"
            out.write(
                f"  {lv['type']} {lv['name']}  [{lv.get('storage') or '?'}]{extra}\n"
            )

    _emit(result, ns, text_renderer=_render)
    return 0


@command(
    "il", help="Dump p-code (raw or high)", target=True,
    args=[
        arg("identifier"),
        arg("--form", choices=("raw", "high"), default="raw",
            help="raw p-code per instruction, or high p-code from decompiler (SSA-like)"),
    ],
)
def cmd_il(ns: argparse.Namespace) -> int:
    try:
        response = _send("il", ns, identifier=ns.identifier, form=ns.form)
    except BridgeError as exc:
        print(f"ghx il: {exc}", file=sys.stderr)
        return 1
    _emit(
        response["result"], ns,
        text_renderer=lambda r, o: _render_function_text(r, o, f"  (form={r.get('form')})"),
    )
    return 0


@command(
    "disasm", help="Dump a function's disassembly", target=True,
    args=[arg("identifier")],
)
def cmd_disasm(ns: argparse.Namespace) -> int:
    try:
        response = _send("disasm", ns, identifier=ns.identifier)
    except BridgeError as exc:
        print(f"ghx disasm: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_function_text)
    return 0


@command(
    "xrefs", help="Cross-references to an address, symbol, or struct field",
    target=True,
    args=[
        arg("identifier", nargs="?",
            help="Address or symbol; omit when using --field"),
        arg("--field", dest="field_spec", default=None,
            help="Struct field xref spec, e.g. Player.hp or Player.0x10"),
        arg("--in-function", default=None,
            help="Limit --field scan to a single function (much faster)"),
        arg("--timeout", type=int, default=30,
            help="Decompiler timeout per function for --field scans"),
    ],
)
def cmd_xrefs(ns: argparse.Namespace) -> int:
    if ns.field_spec is not None:
        type_name, sep, field_part = str(ns.field_spec).rpartition(".")
        if not sep or not type_name or not field_part:
            print("ghx xrefs: --field must be in the form Type.field_or_offset",
                  file=sys.stderr)
            return 2
        params: dict[str, Any] = {"type_name": type_name}
        try:
            int(field_part, 0)
            params["offset"] = field_part
        except ValueError:
            params["field"] = field_part
        if ns.in_function:
            params["in_function"] = ns.in_function
        params["timeout"] = ns.timeout
        try:
            response = send_request(
                "field_xrefs", params=params,
                target=ns.target, instance_id=ns.instance, timeout=None,
            )
        except BridgeError as exc:
            print(f"ghx xrefs: {exc}", file=sys.stderr)
            return 1
        result = response["result"]

        def _render_field(r, out):
            f = r.get("field", {})
            label = f.get("field_name") or f"+0x{f.get('offset', 0):x}"
            out.write(
                f"{f.get('type_name')}.{label}  "
                f"(type={f.get('field_type')}, offset=0x{f.get('offset', 0):x})\n"
            )
            out.write(f"scanned   {r.get('scanned_functions')} function(s)\n")
            refs = r.get("code_refs", [])
            out.write(f"code_refs ({len(refs)})\n")
            for x in refs:
                out.write(
                    f"  {x['address']:>12}  {x['function']:<32}  "
                    f"{x['opcode']:<8}  {x.get('disasm') or ''}\n"
                )

        _emit(result, ns, text_renderer=_render_field)
        return 0

    if not ns.identifier:
        print("ghx xrefs: provide an identifier or use --field", file=sys.stderr)
        return 2
    try:
        response = _send("xrefs", ns, identifier=ns.identifier)
    except BridgeError as exc:
        print(f"ghx xrefs: {exc}", file=sys.stderr)
        return 1
    result = response["result"]

    def _render(r, out):
        out.write(f"target   {r.get('target')}\n")
        incoming = r.get("incoming", []) or []
        outgoing = r.get("outgoing", []) or []
        out.write(f"incoming ({len(incoming)})\n")
        for x in incoming:
            func = x.get("function") or "-"
            out.write(
                f"  {x['address']:>12}  {func:<32}  {x.get('ref_type')}  "
                f"{x.get('disasm') or ''}\n"
            )
        if outgoing:
            out.write(f"outgoing ({len(outgoing)})\n")
            for x in outgoing:
                out.write(f"  {x['address']:>12}  {x.get('ref_type')}\n")

    _emit(result, ns, text_renderer=_render)
    return 0


_CRT_NOISE_PREFIXES = (
    "_ITM_", "__gmon_", "__libc_", "__cxa_", "__stack_chk_",
    "_dl_", "__GI_", "_IO_",
)
_CRT_NOISE_EXACT = {
    "UTF-8", "UTF-16", "UTF-32", "ASCII", "C", "POSIX",
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
}


def _looks_like_crt_noise(row: dict[str, Any]) -> bool:
    """Heuristic filter for CRT/locale strings (for `strings --no-crt`)."""
    value = str(row.get("value") or "").strip('"')
    if len(value) <= 1:
        return True
    if value in _CRT_NOISE_EXACT:
        return True
    if any(value.startswith(pfx) for pfx in _CRT_NOISE_PREFIXES):
        return True
    if len(value) <= 5 and "_" in value and value.islower():
        return True  # en_us, zh_cn, etc.
    if row.get("section") == ".text":
        return True
    return False


@command(
    "strings", help="List defined strings",
    target=True, paged=True,
    args=[
        arg("--query", default=None, help="substring filter (case-insensitive)"),
        arg("--min-length", type=int, default=1),
        arg("--section", default=None,
            help="Restrict to a specific section name (e.g. .rodata)"),
        arg("--no-crt", action="store_true",
            help="Heuristically drop CRT/locale/runtime noise strings"),
    ],
)
def cmd_strings(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "strings", ns,
            query=ns.query,
            min_length=ns.min_length,
            section=ns.section,
            offset=ns.offset,
            limit=ns.limit,
        )
    except BridgeError as exc:
        print(f"ghx strings: {exc}", file=sys.stderr)
        return 1
    rows = response["result"] or []
    if ns.no_crt:
        rows = [r for r in rows if not _looks_like_crt_noise(r)]

    def _render(rows, out):
        for r in rows:
            out.write(f"{r['address']:>12}  [{r.get('section') or '-'}]  {r['value']}\n")

    _emit(rows, ns, text_renderer=_render)
    return 0


@command("imports", help="List imported symbols + thunks", target=True)
def cmd_imports(ns: argparse.Namespace) -> int:
    try:
        response = _send("imports", ns)
    except BridgeError as exc:
        print(f"ghx imports: {exc}", file=sys.stderr)
        return 1
    rows = response["result"] or []

    def _render(rows, out):
        for r in rows:
            tag = " (thunk)" if r.get("is_thunk") else ""
            lib = r.get("library") or "-"
            out.write(f"{r['address']:>12}  {r['name']:<32}  [{lib}]{tag}\n")

    _emit(rows, ns, text_renderer=_render)
    return 0


@command(
    "sections", help="List memory blocks", target=True,
    args=[arg("--query", default=None)],
)
def cmd_sections(ns: argparse.Namespace) -> int:
    try:
        response = _send("sections", ns, query=ns.query)
    except BridgeError as exc:
        print(f"ghx sections: {exc}", file=sys.stderr)
        return 1
    rows = response["result"] or []

    def _render(rows, out):
        for r in rows:
            init = "init" if r.get("initialized") else "uninit"
            out.write(
                f"{r['start']:>12}-{r['end']:<12} {r.get('perms', '---'):<3} "
                f"{init:<6}  {r['name']}  (size={r['size']})\n"
            )

    _emit(rows, ns, text_renderer=_render)
    return 0


@command(
    "types", "list", help="List data types",
    target=True, paged=True,
    args=[arg("--query", default=None)],
)
def cmd_types(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "types", ns,
            query=ns.query,
            offset=ns.offset,
            limit=ns.limit,
        )
    except BridgeError as exc:
        print(f"ghx types list: {exc}", file=sys.stderr)
        return 1
    rows = response["result"] or []

    def _render(rows, out):
        for r in rows:
            size = r.get("size", -1)
            size_s = f"size={size}" if size >= 0 else "size=?"
            out.write(f"  {r.get('kind', '?'):<20}  {r['path']:<48}  {size_s}\n")

    _emit(rows, ns, text_renderer=_render)
    return 0


@command(
    "types", "show", help="Show a single data type", target=True,
    args=[arg("name")],
)
def cmd_types_show(ns: argparse.Namespace) -> int:
    try:
        response = _send("type_info", ns, name=ns.name)
    except BridgeError as exc:
        print(f"ghx types show: {exc}", file=sys.stderr)
        return 1
    result = response["result"]

    def _render(r, out):
        out.write(f"name    {r['name']}\n")
        out.write(f"path    {r['path']}\n")
        out.write(f"kind    {r.get('kind')}\n")
        out.write(f"size    {r.get('size')}\n")
        if "fields" in r:
            out.write(f"fields  ({len(r['fields'])})\n")
            for f in r["fields"]:
                comment = f"  // {f['comment']}" if f.get("comment") else ""
                offset = f.get("offset")
                off_s = f"+0x{offset:x}" if offset is not None else "   -  "
                out.write(
                    f"  {off_s:>6}  {f['type']:<20}  {f['name']:<24}  "
                    f"(size={f.get('size', '?')})" + comment + "\n"
                )
        if "values" in r:
            for v in r["values"]:
                out.write(f"  {v['name']:<24} = {v['value']}\n")
        if "base_type" in r:
            out.write(f"base    {r['base_type']}\n")

    _emit(result, ns, text_renderer=_render)
    return 0


@command(
    "types", "declare", help="Parse C declarations and add to the DataTypeManager",
    fmt="json", target=True,
    mutex_groups=[
        mutex(
            False,
            arg("--source", default=None, help="Inline C source"),
            arg("--file", default=None, help="Path to a .h/.c file to ingest"),
            arg("--stdin", action="store_true", help="Read declarations from stdin"),
        ),
    ],
    args=[arg("--preview", action="store_true")],
)
def cmd_types_declare(ns: argparse.Namespace) -> int:
    if ns.source is not None:
        source = ns.source
    elif ns.file:
        source = Path(ns.file).expanduser().read_text()
    elif ns.stdin:
        source = sys.stdin.read()
    else:
        source = sys.stdin.read()
    try:
        response = _send("types_declare", ns, source=source, preview=ns.preview)
    except BridgeError as exc:
        print(f"ghx types declare: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "callsites", help="List call sites that reach a function", target=True,
    args=[
        arg("callee", help="Callee function name or hex address"),
        arg("--within", default=None,
            help="Comma-separated caller names to restrict results"),
        arg("--within-file", default=None, type=Path,
            help="Path to a file with one caller name per line "
                 "(blank and #-prefixed lines ignored)"),
        arg("--context", type=int, default=0,
            help="Include N previous and N next instructions around each call"),
    ],
)
def cmd_callsites(ns: argparse.Namespace) -> int:
    within: list[str] = []
    if ns.within:
        within.extend(ns.within.split(","))
    if ns.within_file:
        path = Path(ns.within_file).expanduser()
        try:
            for raw in path.read_text().splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                within.append(line)
        except OSError as exc:
            print(f"ghx callsites: could not read --within-file {path}: {exc}",
                  file=sys.stderr)
            return 2
    try:
        response = _send(
            "callsites", ns,
            identifier=ns.callee,
            within=within or None,
            context=ns.context,
        )
    except BridgeError as exc:
        print(f"ghx callsites: {exc}", file=sys.stderr)
        return 1
    r = response["result"]

    def _render(r, out):
        callee = r["callee"]
        out.write(f"callee  {callee['name']} @ {callee['address']}\n")
        for s in r.get("callsites", []):
            caller = s.get("caller") or "-"
            ret = s.get("return_address") or "-"
            out.write(
                f"  {s['call_addr']:>12}  {caller:<32}  "
                f"(ret={ret})  {s.get('disasm') or ''}\n"
            )
            for prev in s.get("prev_ins", []) or []:
                out.write(f"    -  {prev['address']:>12}  {prev.get('disasm') or ''}\n")
            for nxt in s.get("next_ins", []) or []:
                out.write(f"    +  {nxt['address']:>12}  {nxt.get('disasm') or ''}\n")

    _emit(r, ns, text_renderer=_render)
    return 0


@command(
    "bundle", "function", help="Bundle decompile+disasm+proto+locals+xrefs",
    fmt="json", target=True,
    args=[arg("identifier")],
)
def cmd_bundle_function(ns: argparse.Namespace) -> int:
    try:
        response = _send("bundle_function", ns, identifier=ns.identifier)
    except BridgeError as exc:
        print(f"ghx bundle function: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns)
    return 0


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------


@command(
    "symbol", "rename", help="Rename a symbol (by name or address)",
    fmt="json", target=True,
    args=[
        arg("--kind", choices=("auto", "function", "data"), default="auto",
            help="Restrict to function symbols, data symbols, or auto-detect"),
        arg("--preview", action="store_true",
            help="Apply, capture diff, and roll back the transaction"),
        arg("identifier", help="Symbol name or hex address to rename"),
        arg("new_name", help="New symbol name"),
    ],
)
def cmd_symbol_rename(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "rename_symbol", ns,
            identifier=ns.identifier,
            new_name=ns.new_name,
            kind=ns.kind,
            preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx symbol rename: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


def _resolve_comment_address(ns: argparse.Namespace) -> str:
    """Pick the target address: --address wins, else --function.entry."""
    if getattr(ns, "address", None):
        return str(ns.address)
    func = getattr(ns, "function", None)
    if not func:
        raise BridgeError("comment: pass --address or --function")
    info = send_request("function_info", params={"identifier": func},
                        target=getattr(ns, "target", None),
                        instance_id=getattr(ns, "instance", None))
    return str(info["result"]["function"]["address"])


@command(
    "comment", "set", help="Set a comment at an address",
    fmt="json", target=True,
    args=[
        arg("--address", default=None, help="Target hex address"),
        arg("--function", default=None,
            help="Function name (comment is set on the function's entry point)"),
        arg("--kind", default="plate",
            choices=("plate", "pre", "post", "eol", "repeatable")),
        arg("--preview", action="store_true"),
        arg("comment", help="Comment text"),
    ],
)
def cmd_comment_set(ns: argparse.Namespace) -> int:
    try:
        address = _resolve_comment_address(ns)
        response = _send(
            "set_comment", ns,
            address=address, text=ns.comment, kind=ns.kind, preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx comment set: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "comment", "get", help="Get a comment at an address", target=True,
    args=[
        arg("--address", default=None),
        arg("--function", default=None),
        arg("--kind", default="plate",
            choices=("plate", "pre", "post", "eol", "repeatable")),
    ],
)
def cmd_comment_get(ns: argparse.Namespace) -> int:
    try:
        address = _resolve_comment_address(ns)
        response = _send("get_comment", ns, address=address, kind=ns.kind)
    except BridgeError as exc:
        print(f"ghx comment get: {exc}", file=sys.stderr)
        return 1
    r = response["result"]

    def _render(r, out):
        if r.get("text") is None:
            out.write(f"(no {r.get('kind')} comment at {r.get('address')})\n")
            return
        out.write(f"{r.get('address')} [{r.get('kind')}]\n{r['text']}\n")

    _emit(r, ns, text_renderer=_render)
    return 0


@command(
    "comment", "delete", help="Delete a comment at an address",
    fmt="json", target=True,
    args=[
        arg("--address", default=None),
        arg("--function", default=None),
        arg("--kind", default="plate",
            choices=("plate", "pre", "post", "eol", "repeatable")),
        arg("--preview", action="store_true"),
    ],
)
def cmd_comment_delete(ns: argparse.Namespace) -> int:
    try:
        address = _resolve_comment_address(ns)
        response = _send(
            "delete_comment", ns,
            address=address, kind=ns.kind, preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx comment delete: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "comment", "list", help="List comments",
    target=True, paged=True,
    args=[arg("--kinds", default=None,
              help="Comma-separated kinds to include (default: all)")],
)
def cmd_comment_list(ns: argparse.Namespace) -> int:
    kinds = ns.kinds.split(",") if ns.kinds else None
    try:
        response = _send("list_comments", ns, kinds=kinds)
    except BridgeError as exc:
        print(f"ghx comment list: {exc}", file=sys.stderr)
        return 1
    rows = response["result"] or []

    def _render(rows, out):
        for r in rows:
            out.write(f"{r['address']:>12}  [{r['kind']}]  {r['text']}\n")

    _emit(rows, ns, text_renderer=_render)
    return 0


@command(
    "proto", "get", help="Get a function's prototype", target=True,
    args=[arg("identifier")],
)
def cmd_proto_get(ns: argparse.Namespace) -> int:
    try:
        response = _send("get_prototype", ns, identifier=ns.identifier)
    except BridgeError as exc:
        print(f"ghx proto get: {exc}", file=sys.stderr)
        return 1
    r = response["result"]

    def _render(r, out):
        fn = r["function"]
        out.write(f"{fn['name']} @ {fn['address']}\n")
        out.write(f"  prototype  {r.get('prototype')}\n")
        if r.get("calling_convention"):
            out.write(f"  conv       {r.get('calling_convention')}\n")

    _emit(r, ns, text_renderer=_render)
    return 0


@command(
    "proto", "set", help="Apply a C prototype to a function",
    fmt="json", target=True,
    args=[
        arg("--preview", action="store_true"),
        arg("identifier", help="Function name or hex address"),
        arg("prototype", help="C signature, e.g. 'int f(int a, char *b)'"),
    ],
)
def cmd_proto_set(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "set_prototype", ns,
            identifier=ns.identifier, prototype=ns.prototype, preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx proto set: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "local", "list", help="List a function's locals + parameters", target=True,
    args=[arg("function", help="Function name or hex address")],
)
def cmd_local_list(ns: argparse.Namespace) -> int:
    try:
        response = _send("list_locals", ns, identifier=ns.function)
    except BridgeError as exc:
        print(f"ghx local list: {exc}", file=sys.stderr)
        return 1
    r = response["result"]

    def _render(r, out):
        fn = r["function"]
        out.write(f"{fn['name']} @ {fn['address']}\n")
        for lv in r.get("locals", []):
            tag = "param" if lv.get("is_parameter") else "local"
            out.write(
                f"  [{tag}]  {lv['type']:<20}  {lv['name']:<24}  [{lv.get('storage') or '?'}]\n"
            )

    _emit(r, ns, text_renderer=_render)
    return 0


@command(
    "local", "rename", help="Rename a local variable",
    fmt="json", target=True,
    args=[
        arg("--preview", action="store_true"),
        arg("function", help="Function name or hex address"),
        arg("variable", help="Existing local name"),
        arg("new_name", help="New local name"),
    ],
)
def cmd_local_rename(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "local_rename", ns,
            identifier=ns.function, name=ns.variable,
            new_name=ns.new_name, preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx local rename: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "local", "retype", help="Retype a local variable",
    fmt="json", target=True,
    args=[
        arg("--preview", action="store_true"),
        arg("function", help="Function name or hex address"),
        arg("variable", help="Existing local name"),
        arg("new_type", help="Target data type (e.g. 'char *', 'int[4]')"),
    ],
)
def cmd_local_retype(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "local_retype", ns,
            identifier=ns.function, name=ns.variable,
            type=ns.new_type, preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx local retype: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "struct", "show", help="Show a struct layout", target=True,
    args=[arg("struct_name", help="Struct type name")],
)
def cmd_struct_show(ns: argparse.Namespace) -> int:
    try:
        response = _send("type_info", ns, name=ns.struct_name, require_struct=True)
    except BridgeError as exc:
        print(f"ghx struct show: {exc}", file=sys.stderr)
        return 1

    def _render(r, out):
        out.write(f"struct  {r['name']}\n")
        out.write(f"path    {r['path']}\n")
        out.write(f"size    {r.get('size')}\n")
        if "fields" in r:
            out.write(f"fields  ({len(r['fields'])})\n")
            for f in r["fields"]:
                comment = f"  // {f['comment']}" if f.get("comment") else ""
                off_s = f"+0x{f.get('offset', 0):x}"
                out.write(
                    f"  {off_s:>6}  {f['type']:<20}  {f['name']:<24}  "
                    f"(size={f.get('size', '?')})" + comment + "\n"
                )

    _emit(response["result"], ns, text_renderer=_render)
    return 0


@command(
    "struct", "field", "set", help="Set or replace a struct field at an offset",
    fmt="json", target=True,
    args=[
        arg("--length", type=int, default=None),
        arg("--comment", default=None),
        arg("--no-overwrite", action="store_true",
            help="Insert instead of replace (shifts subsequent fields)"),
        arg("--preview", action="store_true"),
        arg("struct_name"),
        arg("offset", help="Byte offset into the struct (e.g. 0x10)"),
        arg("field_name"),
        arg("field_type"),
    ],
)
def cmd_struct_field_set(ns: argparse.Namespace) -> int:
    try:
        response = _send(
            "struct_field_set", ns,
            type_name=ns.struct_name, offset=ns.offset,
            field_name=ns.field_name, field_type=ns.field_type,
            length=ns.length, overwrite=not ns.no_overwrite,
            comment=ns.comment, preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx struct field set: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "struct", "field", "rename", help="Rename a struct field",
    fmt="json", target=True,
    args=[
        arg("--preview", action="store_true"),
        arg("--offset", default=None,
            help="Use offset instead of old_name to address the field"),
        arg("struct_name"),
        arg("old_name", nargs="?", default=None,
            help="Existing field name (omit if using --offset)"),
        arg("new_name"),
    ],
)
def cmd_struct_field_rename(ns: argparse.Namespace) -> int:
    if ns.old_name is None and ns.offset is None:
        print("ghx struct field rename: pass old_name or --offset", file=sys.stderr)
        return 2
    try:
        response = _send(
            "struct_field_rename", ns,
            type_name=ns.struct_name,
            name=ns.old_name, offset=ns.offset,
            new_name=ns.new_name, preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx struct field rename: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "struct", "field", "delete", help="Delete a struct field",
    fmt="json", target=True,
    args=[
        arg("--preview", action="store_true"),
        arg("--offset", default=None,
            help="Use offset instead of field_name to address the field"),
        arg("struct_name"),
        arg("field_name", nargs="?", default=None,
            help="Existing field name (omit if using --offset)"),
    ],
)
def cmd_struct_field_delete(ns: argparse.Namespace) -> int:
    if ns.field_name is None and ns.offset is None:
        print("ghx struct field delete: pass field_name or --offset", file=sys.stderr)
        return 2
    try:
        response = _send(
            "struct_field_delete", ns,
            type_name=ns.struct_name,
            name=ns.field_name, offset=ns.offset,
            preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx struct field delete: {exc}", file=sys.stderr)
        return 1
    _emit(response["result"], ns, text_renderer=_render_mutation)
    return 0


@command(
    "batch", "apply", help="Apply operations from a JSON manifest",
    fmt="json", target=True,
    args=[
        arg("manifest", help="Path to manifest JSON"),
        arg("--preview", action="store_true"),
    ],
)
def cmd_batch_apply(ns: argparse.Namespace) -> int:
    path = Path(ns.manifest).expanduser()
    try:
        manifest = json.loads(path.read_text())
    except Exception as exc:
        print(f"ghx batch apply: could not read manifest: {exc}", file=sys.stderr)
        return 2
    if isinstance(manifest, list):
        operations = manifest
    elif isinstance(manifest, dict) and isinstance(manifest.get("operations"), list):
        operations = manifest["operations"]
    else:
        print("ghx batch apply: manifest must be a list of operations or "
              "an object with 'operations': [...]", file=sys.stderr)
        return 2
    try:
        response = _send(
            "batch_apply", ns, operations=operations, preview=ns.preview,
        )
    except BridgeError as exc:
        print(f"ghx batch apply: {exc}", file=sys.stderr)
        return 1
    r = response["result"]

    def _render(r, out):
        tag = "preview" if r.get("preview") else ("committed" if r.get("committed") else "aborted")
        out.write(f"batch {tag}  ({len(r.get('results', []))} ops)\n")
        for i, row in enumerate(r.get("results", [])):
            mark = "!" if r.get("failed_index") == i else " "
            err = row.get("error")
            detail = f"  — {err}" if err else ""
            out.write(
                f" {mark} {i:>3}  {row.get('op', '?'):<24}  "
                f"{row.get('status')}{detail}\n"
            )

    _emit(r, ns, text_renderer=_render)
    return 0 if r.get("failed_index") is None else 1


@command(
    "py", "exec", help="Execute inline Python with Ghidra bindings", target=True,
    args=[
        arg("--mutate", action="store_true",
            help="Wrap execution in a Program transaction (default: read-only)"),
    ],
    mutex_groups=[
        mutex(
            False,
            arg("--code", default=None, help="Inline Python source"),
            arg("--script", default=None, help="Path to a Python script"),
            arg("--stdin", action="store_true",
                help="Read Python source from stdin"),
        ),
    ],
)
def cmd_py_exec(ns: argparse.Namespace) -> int:
    if ns.code is not None:
        code = ns.code
    elif ns.script is not None:
        code = Path(ns.script).expanduser().read_text()
    elif ns.stdin:
        code = sys.stdin.read()
    else:
        # Backwards-compat: if no source flag is given, read stdin.
        code = sys.stdin.read()
    try:
        response = _send("py_exec", ns, code=code, mutate=ns.mutate)
    except BridgeError as exc:
        print(f"ghx py exec: {exc}", file=sys.stderr)
        return 1
    r = response["result"]
    fmt = _resolve_format(ns)
    if fmt in ("json", "ndjson"):
        _emit(r, ns)
    else:
        stdout = r.get("stdout") or ""
        stderr = r.get("stderr") or ""
        if stdout:
            sys.stdout.write(stdout)
            if not stdout.endswith("\n"):
                sys.stdout.write("\n")
        if stderr:
            sys.stderr.write(stderr)
            if not stderr.endswith("\n"):
                sys.stderr.write("\n")
        if not r.get("ok"):
            sys.stderr.write(f"error: {r.get('error')}\n")
            return 1
        result = r.get("result")
        if result is not None:
            sys.stdout.write(f"result: {result!r}\n")
    return 0 if r.get("ok") else 1


# ---------------------------------------------------------------------------
# Parser + entry point
# ---------------------------------------------------------------------------


def build_parser() -> GhxArgumentParser:
    parser = GhxArgumentParser(
        prog="ghx",
        description="Agent-friendly Ghidra CLI (PyGhidra-backed daemon)",
    )
    parser.add_argument("--version", action="version", version=f"ghx {VERSION}")
    _instance_option(parser, is_root=True)
    _build_from_commands(parser)
    return parser


# Back-compat alias for tests + older imports.
_build_parser = build_parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    handler = getattr(ns, "func", None)
    if handler is None:
        # Command group invoked without a subcommand — print help for the
        # deepest reached parser, not the root.
        local_parser = getattr(ns, "_parser", parser)
        local_parser.print_help()
        return 2
    try:
        return handler(ns)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
