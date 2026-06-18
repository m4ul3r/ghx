from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import pins
from .paths import bridge_registry_path, bridge_socket_path, instances_dir


class BridgeError(RuntimeError):
    pass


TRANSIENT_SOCKET_ERRNOS = {
    errno.ECONNREFUSED,
    errno.ENOENT,
}

INSTANCE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


@dataclass(slots=True)
class BridgeInstance:
    pid: int
    socket_path: Path
    registry_path: Path
    plugin_name: str
    plugin_version: str
    started_at: str | None
    meta: dict[str, Any]
    instance_id: str | None = None


def instance_selector(instance: BridgeInstance) -> str:
    return instance.instance_id or "default"


def _format_instance_choices(instances: list[BridgeInstance]) -> str:
    lines = []
    for inst in instances:
        selector = instance_selector(inst)
        details = [f"pid={inst.pid}", f"socket={inst.socket_path}"]
        if inst.started_at:
            details.append(f"started={inst.started_at}")
        lines.append(f"- {selector} ({', '.join(details)})")
    return "\n".join(lines)


def _validate_instance_id(instance_id: str) -> None:
    if not INSTANCE_ID_RE.fullmatch(instance_id):
        raise BridgeError(
            "Invalid ghx instance id; use 1-64 letters, digits, dots, dashes, or underscores, "
            "starting with a letter or digit"
        )


def _is_managed_socket_path(path: Path) -> bool:
    try:
        return path.resolve().parent == instances_dir().resolve()
    except OSError:
        return False


def _purge_stale_registry(registry_path: Path) -> None:
    socket_path: Path | None = None
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        socket_value = payload.get("socket_path")
        if socket_value:
            socket_path = Path(str(socket_value))
    except (OSError, json.JSONDecodeError, AttributeError):
        socket_path = None

    with contextlib.suppress(OSError):
        registry_path.unlink()
    if socket_path is not None and _is_managed_socket_path(socket_path):
        with contextlib.suppress(OSError):
            socket_path.unlink()


def _socket_is_live(socket_path: Path, timeout: float = 0.2) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(socket_path))
        return True
    except OSError:
        return False


def _load_instance(path: Path) -> BridgeInstance | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        socket_path = Path(payload["socket_path"])
        pid = int(payload["pid"])
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None

    if not socket_path.exists():
        _purge_stale_registry(path)
        return None

    if not _socket_is_live(socket_path):
        _purge_stale_registry(path)
        return None

    return BridgeInstance(
        pid=pid,
        socket_path=socket_path,
        registry_path=path,
        plugin_name=str(payload.get("plugin_name", "ghx_agent_bridge")),
        plugin_version=str(payload.get("plugin_version", "0")),
        started_at=payload.get("started_at"),
        meta=payload,
        instance_id=payload.get("instance_id"),
    )


def list_instances() -> list[BridgeInstance]:
    instances: list[BridgeInstance] = []

    # Legacy fixed registry (reserved for a future GUI bridge)
    fixed_registry = bridge_registry_path()
    if fixed_registry.exists():
        instance = _load_instance(fixed_registry)
        if instance is not None:
            instances.append(instance)

    # Per-instance registries
    inst_dir = instances_dir()
    if inst_dir.is_dir():
        for reg_file in sorted(inst_dir.glob("*.json")):
            instance = _load_instance(reg_file)
            if instance is not None:
                instances.append(instance)

    return instances


def choose_instance(
    instance_id: str | None = None,
    *,
    auto_start: bool = True,
    spawn_missing_named: bool = False,
) -> BridgeInstance:
    instances = list_instances()
    if instance_id is not None:
        _validate_instance_id(instance_id)
        for inst in instances:
            if inst.instance_id == instance_id or instance_selector(inst) == instance_id:
                return inst
        if auto_start and spawn_missing_named:
            return spawn_instance(instance_id=instance_id)
        raise BridgeError(f"No ghx bridge instance found with id: {instance_id}")
    # No explicit selection: honour a sticky pin if it points at a live
    # instance. A stale/absent pin falls through to normal resolution.
    pinned = pins.get_instance()
    if pinned:
        for inst in instances:
            if inst.instance_id == pinned or instance_selector(inst) == pinned:
                return inst
    if len(instances) == 1:
        return instances[0]
    if instances:
        raise BridgeError(
            "Multiple ghx bridge instances are running; pass --instance <id> "
            "or set GHX_INSTANCE.\n"
            f"Instances:\n{_format_instance_choices(instances)}"
        )
    if auto_start:
        return spawn_instance()
    raise BridgeError("No running ghx bridge instances found")


def _send_request_to_instance(
    instance: BridgeInstance,
    op: str,
    *,
    params: dict[str, Any] | None = None,
    target: str | None = None,
    timeout: float | None = None,
    connect_retries: int = 4,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "op": op,
        "params": params or {},
    }
    if target is not None:
        payload["target"] = target

    encoded = (json.dumps(payload) + "\n").encode("utf-8")

    chunks: list[bytes] = []
    last_error: OSError | None = None
    for attempt in range(connect_retries):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect(str(instance.socket_path))
                sock.sendall(encoded)
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_WR)
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            break
        except OSError as exc:
            last_error = exc
            if exc.errno not in TRANSIENT_SOCKET_ERRNOS or attempt == connect_retries - 1:
                break
            time.sleep(0.05 * (attempt + 1))

    if last_error is not None and not chunks:
        if isinstance(last_error, TimeoutError):
            timeout_suffix = f" after {timeout:.1f}s" if timeout is not None else ""
            raise BridgeError(
                f"Timed out waiting for ghx bridge pid {instance.pid} at {instance.socket_path}"
                f"{timeout_suffix}"
            ) from last_error
        raise BridgeError(
            f"Failed to contact ghx bridge pid {instance.pid} at {instance.socket_path}: {last_error}"
        ) from last_error

    if last_error is not None and chunks:
        raise BridgeError(
            f"Connection to ghx bridge pid {instance.pid} at {instance.socket_path} "
            f"failed mid-response: {last_error}"
        ) from last_error

    if not chunks:
        alive = False
        try:
            os.kill(instance.pid, 0)
            alive = True
        except OSError:
            alive = False
        log_hint = ""
        if instance.instance_id:
            log_hint = _spawn_failure_detail(instances_dir() / f"{instance.instance_id}.log")
        state = "still running" if alive else "not running"
        raise BridgeError(
            f"ghx bridge pid {instance.pid} at {instance.socket_path} returned an empty "
            f"response (process {state}).{log_hint}"
        )

    try:
        response = json.loads(b"".join(chunks).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise BridgeError("ghx bridge returned invalid JSON") from exc

    if not isinstance(response, dict):
        raise BridgeError("ghx bridge returned a malformed response")

    if response.get("ok"):
        return response

    error = response.get("error") or "Unknown ghx bridge error"
    raise BridgeError(str(error))


_LOG_ERROR_MARKERS = (
    "Exception",
    "Error",
    "Caused by",
    "Traceback",
    "not permitted",
    "Errno",
)


def _read_log_tail(log_path: Path, *, max_lines: int = 15, max_chars: int = 2000) -> str:
    """Return a compact tail of a spawn log, for surfacing the cause of a crash.

    Keeps the last ``max_lines`` non-empty lines (the fatal error and any
    stack frames are near the end before the process exits), but always
    includes lines that match a known error marker even if they fall outside
    the tail window, so a Java exception header printed before its stack isn't
    lost. Truncated to ``max_chars`` total.
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    tail = lines[-max_lines:]
    marked = [ln for ln in lines if any(m in ln for m in _LOG_ERROR_MARKERS)]
    # Prepend any error-marked lines that aren't already in the tail window.
    extra = [ln for ln in marked if ln not in tail]
    selected = extra[-max_lines:] + tail if extra else tail
    rendered = "\n".join(selected)
    if len(rendered) > max_chars:
        rendered = "…\n" + rendered[-max_chars:]
    return rendered


def _spawn_failure_detail(log_path: Path) -> str:
    """Format the log tail as a suffix for a spawn BridgeError message."""
    tail = _read_log_tail(log_path)
    if not tail:
        return f" Check {log_path}"
    return f"\n--- last log lines ({log_path}) ---\n{tail}"


def _find_ghx_agent() -> list[str]:
    """Return the command to invoke ghx-agent."""
    exe_dir = Path(sys.executable).parent
    ghx_agent = exe_dir / "ghx-agent"
    if ghx_agent.exists():
        return [str(ghx_agent)]
    return [sys.executable, "-m", "ghx.headless"]


@contextlib.contextmanager
def _spawn_lock():
    inst_dir = instances_dir()
    inst_dir.mkdir(parents=True, exist_ok=True)
    lock_path = inst_dir / ".spawn.lock"
    with open(lock_path, "a+") as lock_file:  # noqa: SIM115
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _terminate_spawned(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2.0)


def spawn_instance(
    instance_id: str | None = None,
    *,
    timeout: float = 45.0,
    poll_interval: float = 0.3,
    extra_args: list[str] | None = None,
) -> BridgeInstance:
    """Spawn a new ghx-agent headless process and wait for it to register.

    JVM cold-start for PyGhidra typically takes 4-8s; the 45s default gives
    auto-analysis headroom on first boot.
    """
    with _spawn_lock():
        existing = list_instances()
        if instance_id is None:
            existing_selectors = {instance_selector(inst) for inst in existing}
            while True:
                candidate = secrets.token_hex(4)
                if candidate not in existing_selectors:
                    instance_id = candidate
                    break
        else:
            _validate_instance_id(instance_id)
            if instance_id == "default":
                raise BridgeError("Instance id 'default' is reserved")
            if any(inst.instance_id == instance_id or instance_selector(inst) == instance_id for inst in existing):
                raise BridgeError(f"Bridge instance already exists with id: {instance_id}")

        inst_dir = instances_dir()
        inst_dir.mkdir(parents=True, exist_ok=True)

        log_path = inst_dir / f"{instance_id}.log"
        log_file = open(log_path, "w")  # noqa: SIM115

        cmd = _find_ghx_agent() + ["--instance-id", instance_id]
        if extra_args:
            cmd = cmd + list(extra_args)
        proc = subprocess.Popen(
            cmd,
            start_new_session=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        log_file.close()

        reg_path = bridge_registry_path(instance_id)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if reg_path.exists():
                inst = _load_instance(reg_path)
                if inst is not None:
                    return inst
            if proc.poll() is not None:
                raise BridgeError(
                    f"ghx-agent (pid {proc.pid}, instance {instance_id}) exited "
                    f"with code {proc.returncode} before registering."
                    f"{_spawn_failure_detail(log_path)}"
                )
            time.sleep(poll_interval)

        _terminate_spawned(proc)
        raise BridgeError(
            f"Auto-started ghx-agent (pid {proc.pid}, instance {instance_id}) "
            f"did not register within {timeout:.0f}s."
            f"{_spawn_failure_detail(log_path)}"
        )


def send_request(
    op: str,
    *,
    params: dict[str, Any] | None = None,
    target: str | None = None,
    timeout: float | None = None,
    connect_retries: int = 4,
    instance_id: str | None = None,
    spawn_missing_named: bool = False,
) -> dict[str, Any]:
    instance = choose_instance(instance_id, spawn_missing_named=spawn_missing_named)
    return _send_request_to_instance(
        instance,
        op,
        params=params,
        target=target,
        timeout=timeout,
        connect_retries=connect_retries,
    )
