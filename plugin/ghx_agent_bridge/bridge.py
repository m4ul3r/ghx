"""ghx_agent_bridge.bridge - socket daemon backed by PyGhidra."""
from __future__ import annotations

import atexit
import contextlib
import errno
import json
import os
import re
import secrets
import signal
import socketserver
import sys
import threading
import time
import traceback
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghx.paths import (
    PLUGIN_NAME,
    bridge_registry_path,
    bridge_socket_path,
    instances_dir,
    projects_dir,
)
from ghx.version import VERSION, build_id_for_file


PLUGIN_BUILD_ID = build_id_for_file(Path(__file__).resolve())


# ---------------------------------------------------------------------------
# Response envelope + error types
# ---------------------------------------------------------------------------


def _json_response(*, ok: bool, result: Any = None, error: str | None = None) -> dict[str, Any]:
    return {"ok": ok, "result": result, "error": error}


class OperationFailure(RuntimeError):
    def __init__(
        self,
        status: str,
        message: str,
        *,
        requested: dict[str, Any] | None = None,
        observed: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.message = message
        self.requested = requested or {}
        self.observed = observed or {}


# ---------------------------------------------------------------------------
# Read/write lock (ported from bn_agent_bridge)
# ---------------------------------------------------------------------------


class _ReadWriteLock:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._readers = 0
        self._writer = False

    @contextlib.contextmanager
    def read(self):
        with self._condition:
            while self._writer:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @contextlib.contextmanager
    def write(self):
        with self._condition:
            while self._writer or self._readers:
                self._condition.wait()
            self._writer = True
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


READ_LOCKED_OPS: set[str] = {
    "list_targets",
    "target_info",
    "list_functions",
    "search_functions",
    "function_info",
    "decompile",
    "il",
    "disasm",
    "xrefs",
    "callsites",
    "field_xrefs",
    "strings",
    "imports",
    "sections",
    "types",
    "type_info",
    "get_prototype",
    "list_locals",
    "bundle_function",
    "read_bytes",
    "structured_il",
    "evidence_xrefs",
    "evidence_function",
    "evidence_init",
    "evidence_table",
    "evidence_message",
    "dataflow_defuse",
    "dataflow_callgraph",
    "dataflow_values",
    "taint_backward",
    "taint_forward",
}

WRITE_LOCKED_OPS: set[str] = {
    "load_binary",
    "close_binary",
    "save_database",
    "refresh",
    "create_function",
    "rename_symbol",
    "set_comment",
    "delete_comment",
    "list_comments",
    "get_comment",
    "py_exec",
    "set_prototype",
    "local_rename",
    "local_retype",
    "types_declare",
    "struct_field_set",
    "struct_field_rename",
    "struct_field_delete",
    "batch_apply",
}


# ---------------------------------------------------------------------------
# Target management
# ---------------------------------------------------------------------------


@dataclass
class ProgramHandle:
    program_id: str
    basename: str
    filename: str
    domain_file_path: str
    opened_at: str
    program: Any = field(repr=False)
    consumer: Any = field(repr=False)

    def describe(self) -> dict[str, Any]:
        prog = self.program
        try:
            language = str(prog.getLanguage().getLanguageID())
            arch = str(prog.getLanguage().getProcessor())
            compiler = str(prog.getCompilerSpec().getCompilerSpecID())
            endian = "little" if prog.getLanguage().isBigEndian() is False else "big"
        except Exception:
            language = arch = compiler = endian = "?"
        try:
            size = int(prog.getMemory().getSize())
        except Exception:
            size = 0
        entry_off = _program_entry_offset(prog)
        return {
            "program_id": self.program_id,
            "basename": self.basename,
            "filename": self.filename,
            "domain_file_path": self.domain_file_path,
            "opened_at": self.opened_at,
            "language": language,
            "arch": arch,
            "compiler": compiler,
            "endian": endian,
            "size": size,
            "entry": f"0x{entry_off:x}" if entry_off is not None else None,
        }


class TargetManager:
    def __init__(self, project: Any) -> None:
        self.project = project
        self._handles: dict[str, ProgramHandle] = {}
        self._active: str | None = None
        self._lock = threading.Lock()

    # ---- lifecycle ------------------------------------------------------

    def load_binary(self, path: str, quick: bool = False) -> ProgramHandle:
        import pyghidra
        from java.io import File  # type: ignore
        from java.lang import Object  # type: ignore

        src = Path(path).expanduser().resolve()
        if not src.exists():
            raise OperationFailure("not_found", f"binary not found: {src}")

        consumer = Object()
        monitor = pyghidra.task_monitor()

        builder = (
            pyghidra.program_loader()
            .project(self.project)
            .source(File(str(src)))
            .projectFolderPath("/")
        )
        try:
            load_results = builder.load()
        except Exception as exc:
            raise OperationFailure(
                "load_failed",
                f"Ghidra failed to import {src}: {exc}",
            ) from exc

        program = None
        domain_path = f"/{src.name}"
        try:
            primary = load_results.getPrimary()
            try:
                domain_file = primary.save(monitor)
                if domain_file is not None:
                    domain_path = str(domain_file.getPathname())
            except Exception as exc:
                raise OperationFailure(
                    "save_failed",
                    f"failed to persist {src.name} into project: {exc}",
                ) from exc
            program = load_results.getPrimaryDomainObject(consumer)
        finally:
            with contextlib.suppress(Exception):
                load_results.close()

        if not quick:
            try:
                pyghidra.analyze(program)
            except Exception as exc:
                with contextlib.suppress(Exception):
                    program.release(consumer)
                raise OperationFailure(
                    "analysis_failed",
                    f"auto-analysis failed for {src.name}: {exc}",
                ) from exc

        # Persist analysis results back into the project.
        with contextlib.suppress(Exception):
            df = program.getDomainFile()
            if df is not None and df.canSave():
                df.save(monitor)

        program_id = secrets.token_hex(4)
        handle = ProgramHandle(
            program_id=program_id,
            basename=src.name,
            filename=str(src),
            domain_file_path=domain_path,
            opened_at=datetime.now(timezone.utc).isoformat(),
            program=program,
            consumer=consumer,
        )
        with self._lock:
            self._handles[program_id] = handle
            self._active = program_id
        return handle

    def close(self, selector: str | None) -> dict[str, Any]:
        handle = self.resolve(selector, required=True)
        assert handle is not None
        with self._lock:
            self._handles.pop(handle.program_id, None)
            if self._active == handle.program_id:
                self._active = next(iter(self._handles), None)
        with contextlib.suppress(Exception):
            handle.program.release(handle.consumer)
        return {"program_id": handle.program_id, "closed": True}

    def close_all(self) -> dict[str, Any]:
        """Release every loaded program. Used both by the `close --all` op and
        by daemon shutdown (which ignores the return value)."""
        with self._lock:
            handles = list(self._handles.values())
            self._handles.clear()
            self._active = None
        closed: list[str] = []
        for h in handles:
            with contextlib.suppress(Exception):
                h.program.release(h.consumer)
            closed.append(h.program_id)
        return {"closed": closed, "count": len(closed)}

    # ---- resolution -----------------------------------------------------

    def resolve(self, selector: str | None, *, required: bool = False) -> ProgramHandle | None:
        with self._lock:
            if not self._handles:
                if required:
                    raise OperationFailure(
                        "no_target",
                        "no program is currently loaded; run `ghx load <binary>` first",
                    )
                return None

            if selector in (None, "", "active"):
                active_id = self._active or next(iter(self._handles))
                return self._handles[active_id]

            # Direct program_id match.
            if selector in self._handles:
                return self._handles[selector]

            # basename or domain_file_path or full filename.
            matches = [
                h
                for h in self._handles.values()
                if selector in (h.basename, h.domain_file_path, h.filename)
            ]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise OperationFailure(
                    "ambiguous_target",
                    f"selector '{selector}' matches {len(matches)} targets",
                )

        if required:
            raise OperationFailure("not_found", f"no target matches selector '{selector}'")
        return None

    def set_active(self, program_id: str) -> None:
        with self._lock:
            if program_id in self._handles:
                self._active = program_id

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            handles = list(self._handles.values())
            active = self._active
        return [
            {**h.describe(), "active": h.program_id == active}
            for h in handles
        ]


# ---------------------------------------------------------------------------
# Socket server
# ---------------------------------------------------------------------------


class BridgeHandler(socketserver.StreamRequestHandler):
    def _write_response(
        self,
        encoded: bytes,
        *,
        op: str | None = None,
        request_id: str | None = None,
    ) -> None:
        try:
            self.wfile.write(encoded)
        except OSError as exc:
            if exc.errno not in {errno.EPIPE, errno.ECONNRESET}:
                raise
            details = []
            if op:
                details.append(f"op={op}")
            if request_id:
                details.append(f"id={request_id}")
            suffix = f" ({', '.join(details)})" if details else ""
            print(f"[ghx] client disconnected before response could be delivered{suffix}", file=sys.stderr)

    def handle(self) -> None:
        raw = self.rfile.readline()
        if not raw:
            return
        op = None
        request_id = None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            response = _json_response(ok=False, error="Invalid JSON request")
        else:
            op = payload.get("op")
            request_id = payload.get("id")
            response = self.server.bridge.dispatch(payload)
        encoded = json.dumps(response, sort_keys=True, default=str).encode("utf-8")
        self._write_response(encoded, op=op, request_id=request_id)


class ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, socket_path: str, handler, bridge: "GhxBridge") -> None:
        self.bridge = bridge
        super().__init__(socket_path, handler)


# ---------------------------------------------------------------------------
# The bridge itself
# ---------------------------------------------------------------------------


class GhxBridge:
    def __init__(
        self,
        *,
        instance_id: str | None,
        install_dir: Path,
        project_path: Path,
        project_name: str,
        project: Any,
    ) -> None:
        self.instance_id = instance_id
        self.install_dir = install_dir
        self.project_path = project_path
        self.project_name = project_name
        self.project = project
        self.targets = TargetManager(project)
        self.socket_path = bridge_socket_path(instance_id)
        self.registry_path = bridge_registry_path(instance_id)
        self._server: ThreadedUnixServer | None = None
        self._thread: threading.Thread | None = None
        self._target_lock = _ReadWriteLock()
        self._shutdown_event = threading.Event()
        self._started_at: str | None = None
        self._last_active: str | None = None
        self._last_registry_write = 0.0
        self._registry_lock = threading.Lock()

    # ---- lifecycle ------------------------------------------------------

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()

        self._server = ThreadedUnixServer(str(self.socket_path), BridgeHandler, self)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._write_registry()
        print(f"[ghx] listening on {self.socket_path}", file=sys.stderr, flush=True)

    def stop(self) -> None:
        if self._server is not None:
            with contextlib.suppress(Exception):
                self._server.shutdown()
            with contextlib.suppress(Exception):
                self._server.server_close()
        self.targets.close_all()
        with contextlib.suppress(Exception):
            self.project.close()
        if self.socket_path.exists():
            with contextlib.suppress(OSError):
                self.socket_path.unlink()
        if self.registry_path.exists():
            with contextlib.suppress(OSError):
                self.registry_path.unlink()

    def _write_registry(self) -> None:
        ghidra_version = _read_ghidra_version(self.install_dir)

        if self._started_at is None:
            self._started_at = datetime.now(timezone.utc).isoformat()

        payload: dict[str, Any] = {
            "pid": os.getpid(),
            "socket_path": str(self.socket_path),
            "plugin_name": PLUGIN_NAME,
            "plugin_version": VERSION,
            "plugin_build_id": PLUGIN_BUILD_ID,
            "ghidra_version": ghidra_version,
            "ghidra_install_dir": str(self.install_dir),
            "project_path": str(self.project_path),
            "project_name": self.project_name,
            "started_at": self._started_at,
            "last_active": self._last_active or self._started_at,
        }
        if self.instance_id is not None:
            payload["instance_id"] = self.instance_id
        self.registry_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _touch_activity(self) -> None:
        """Record request activity; persist `last_active` to the registry at
        most every 15s so `instance prune --idle` has a real idle metric."""
        self._last_active = datetime.now(timezone.utc).isoformat()
        if time.monotonic() - self._last_registry_write < 15.0:
            return
        with self._registry_lock:
            if time.monotonic() - self._last_registry_write < 15.0:
                return
            self._last_registry_write = time.monotonic()
            with contextlib.suppress(Exception):
                self._write_registry()

    # ---- dispatch -------------------------------------------------------

    def dispatch(self, payload: dict[str, Any]) -> dict[str, Any]:
        op = payload.get("op")
        params = payload.get("params") or {}
        target = payload.get("target")
        self._touch_activity()
        try:
            lock: Any = contextlib.nullcontext()
            if op in WRITE_LOCKED_OPS:
                lock = self._target_lock.write()
            elif op in READ_LOCKED_OPS:
                lock = self._target_lock.read()
            with lock:
                result = self._run_op(op, params, target)
            return _json_response(ok=True, result=result)
        except OperationFailure as exc:
            return _json_response(
                ok=False,
                error=f"{exc.status}: {exc.message}",
                result={
                    "status": exc.status,
                    "message": exc.message,
                    "requested": exc.requested,
                    "observed": exc.observed,
                },
            )
        except Exception as exc:
            tb = traceback.format_exc()
            print(tb, file=sys.stderr, flush=True)
            return _json_response(ok=False, error=f"{type(exc).__name__}: {exc}")

    def _run_op(self, op: str | None, params: dict[str, Any], target: str | None) -> Any:
        if op == "doctor":
            return self._op_doctor()
        if op == "shutdown":
            self._shutdown_event.set()
            return {"shutting_down": True}
        if op == "list_targets":
            return self.targets.list()
        if op == "target_info":
            handle = self.targets.resolve(params.get("selector") or target, required=True)
            assert handle is not None
            return handle.describe()
        if op == "load_binary":
            path = params.get("path")
            if not path:
                raise OperationFailure("bad_request", "load_binary requires 'path'")
            quick = bool(params.get("quick", False))
            handle = self.targets.load_binary(str(path), quick=quick)
            return {"loaded": True, "analyzed": not quick, **handle.describe()}
        if op == "close_binary":
            if params.get("all"):
                return self.targets.close_all()
            return self.targets.close(params.get("selector") or target)
        if op == "decompile":
            return self._op_decompile(params, target)
        if op == "list_functions":
            return self._op_list_functions(params, target)
        if op == "search_functions":
            return self._op_search_functions(params, target)
        if op == "function_info":
            return self._op_function_info(params, target)
        if op == "il":
            return self._op_il(params, target)
        if op == "disasm":
            return self._op_disasm(params, target)
        if op == "structured_il":
            return self._op_structured_il(params, target)
        if op == "read_bytes":
            return self._op_read_bytes(params, target)
        if op == "create_function":
            return self._op_create_function(params, target)
        if op == "xrefs":
            return self._op_xrefs(params, target)
        if op == "strings":
            return self._op_strings(params, target)
        if op == "imports":
            return self._op_imports(params, target)
        if op == "sections":
            return self._op_sections(params, target)
        if op == "types":
            return self._op_types(params, target)
        if op == "type_info":
            return self._op_type_info(params, target)
        if op == "rename_symbol":
            return self._op_rename_symbol(params, target)
        if op == "set_comment":
            return self._op_set_comment(params, target)
        if op == "get_comment":
            return self._op_get_comment(params, target)
        if op == "delete_comment":
            return self._op_delete_comment(params, target)
        if op == "list_comments":
            return self._op_list_comments(params, target)
        if op == "py_exec":
            return self._op_py_exec(params, target)
        if op == "get_prototype":
            return self._op_get_prototype(params, target)
        if op == "set_prototype":
            return self._op_set_prototype(params, target)
        if op == "list_locals":
            return self._op_list_locals(params, target)
        if op == "local_rename":
            return self._op_local_rename(params, target)
        if op == "local_retype":
            return self._op_local_retype(params, target)
        if op == "types_declare":
            return self._op_types_declare(params, target)
        if op == "struct_field_set":
            return self._op_struct_field_set(params, target)
        if op == "struct_field_rename":
            return self._op_struct_field_rename(params, target)
        if op == "struct_field_delete":
            return self._op_struct_field_delete(params, target)
        if op == "callsites":
            return self._op_callsites(params, target)
        if op == "evidence_xrefs":
            return self._op_evidence_xrefs(params, target)
        if op == "evidence_function":
            return self._op_evidence_function(params, target)
        if op == "evidence_init":
            return self._op_evidence_init(params, target)
        if op == "evidence_table":
            return self._op_evidence_table(params, target)
        if op == "evidence_message":
            return self._op_evidence_message(params, target)
        if op == "dataflow_defuse":
            return self._op_dataflow_defuse(params, target)
        if op == "dataflow_callgraph":
            return self._op_dataflow_callgraph(params, target)
        if op == "dataflow_values":
            return self._op_dataflow_values(params, target)
        if op == "taint_backward":
            return self._op_taint_backward(params, target)
        if op == "taint_forward":
            return self._op_taint_forward(params, target)
        if op == "field_xrefs":
            return self._op_field_xrefs(params, target)
        if op == "bundle_function":
            return self._op_bundle_function(params, target)
        if op == "batch_apply":
            return self._op_batch_apply(params, target)
        if op == "refresh":
            return self._op_refresh(params, target)
        if op == "save_database":
            return self._op_save_database(params, target)

        raise OperationFailure("unknown_op", f"unknown op: {op!r}")

    # ---- ops -----------------------------------------------------------

    def _op_doctor(self) -> dict[str, Any]:
        ghidra_version = _read_ghidra_version(self.install_dir)
        ephemeral = self._project_is_ephemeral()
        return {
            "ok": True,
            "ghx_version": VERSION,
            "ghidra_version": ghidra_version,
            "ghidra_install_dir": str(self.install_dir),
            "project_path": str(self.project_path),
            "project_name": self.project_name,
            "project_ephemeral": ephemeral,
            "instance_id": self.instance_id,
            "pid": os.getpid(),
            "socket_path": str(self.socket_path),
            "targets": self.targets.list(),
            "plugin_build_id": PLUGIN_BUILD_ID,
        }

    def _project_is_ephemeral(self) -> bool:
        try:
            return self.project_path.resolve().is_relative_to(projects_dir().resolve())
        except Exception:
            return False

    def _op_decompile(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier") or params.get("name")
        if identifier is None:
            raise OperationFailure("bad_request", "decompile requires 'identifier'")
        timeout = int(params.get("timeout", 60))
        addresses = bool(params.get("addresses", False))

        func = _resolve_function(program, str(identifier))

        iface = DecompInterface()
        iface.setOptions(DecompileOptions())
        iface.openProgram(program)
        try:
            results = iface.decompileFunction(func, timeout, TaskMonitor.DUMMY)
            if not results.decompileCompleted():
                raise OperationFailure(
                    "decompile_failed",
                    f"decompilation did not complete: {results.getErrorMessage() or 'unknown error'}",
                )
            if addresses:
                text = _decompile_with_addresses(func, results)
            else:
                text = str(results.getDecompiledFunction().getC())
        finally:
            with contextlib.suppress(Exception):
                iface.dispose()

        return {
            "text": text,
            "function": {
                "name": str(func.getName()),
                "address": f"0x{int(func.getEntryPoint().getOffset()):x}",
            },
            "program_id": handle.program_id,
            "addresses": addresses,
        }


    # ---- read ops -------------------------------------------------------

    def _op_list_functions(self, params: dict[str, Any], target: str | None) -> list[dict[str, Any]]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else None
        lo_s = params.get("min_address")
        hi_s = params.get("max_address")
        include_externals = bool(params.get("include_externals"))
        program = handle.program

        lo = _parse_address(program, lo_s) if lo_s is not None else None
        hi = _parse_address(program, hi_s) if hi_s is not None else None

        items = []
        fm = program.getFunctionManager()
        iterator = fm.getFunctions(True)
        for fn in iterator:
            entry = fn.getEntryPoint()
            off = int(entry.getOffset())
            if lo is not None and off < lo:
                continue
            if hi is not None and off > hi:
                continue
            if not include_externals and _in_external_block(program, entry):
                continue
            items.append(_func_brief(fn))
        _sort_func_rows(items, str(params.get("sort") or "address"))
        if params.get("count"):
            return {"count": len(items)}
        if offset:
            items = items[offset:]
        if limit is not None:
            items = items[:limit]
        return items

    def _op_search_functions(self, params: dict[str, Any], target: str | None):
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        query = str(params.get("query", ""))
        regex = bool(params.get("regex", False))
        exact = bool(params.get("exact", False))
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else None
        include_externals = bool(params.get("include_externals"))
        program = handle.program

        lo_s = params.get("min_address")
        hi_s = params.get("max_address")
        lo = _parse_address(program, lo_s) if lo_s is not None else None
        hi = _parse_address(program, hi_s) if hi_s is not None else None

        if exact:
            def matches(name: str) -> bool:
                return name == query
        elif regex:
            import re as _re

            try:
                pattern = _re.compile(query, _re.IGNORECASE)
            except _re.error as exc:
                raise OperationFailure("invalid_regex", f"invalid regex: {exc}") from exc

            def matches(name: str) -> bool:
                return bool(pattern.search(name))
        else:
            needle = query.lower()

            def matches(name: str) -> bool:
                return needle in name.lower()

        items = []
        for fn in program.getFunctionManager().getFunctions(True):
            name = str(fn.getName())
            if not matches(name):
                continue
            entry = fn.getEntryPoint()
            off = int(entry.getOffset())
            if lo is not None and off < lo:
                continue
            if hi is not None and off > hi:
                continue
            if not include_externals and _in_external_block(program, entry):
                continue
            items.append(_func_brief(fn))
        _sort_func_rows(items, str(params.get("sort") or "address"))
        if params.get("count"):
            return {"count": len(items)}
        if offset:
            items = items[offset:]
        if limit is not None:
            items = items[:limit]
        return items

    def _op_function_info(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        identifier = params.get("identifier") or params.get("name")
        verbose = bool(params.get("verbose", False))
        if identifier is None:
            raise OperationFailure("bad_request", "function_info requires 'identifier'")
        fn = _resolve_function(handle.program, str(identifier))

        def _var_entry(v: Any, *, is_param: bool) -> dict[str, Any]:
            entry: dict[str, Any] = {
                "name": str(v.getName()),
                "type": str(v.getDataType().getName()),
                "storage": _storage_str(v),
            }
            if verbose:
                try:
                    entry["length"] = int(v.getLength())
                except Exception:
                    pass
                try:
                    entry["source"] = str(v.getSource())
                except Exception:
                    pass
                if not is_param:
                    try:
                        stack_off = v.getStackOffset()
                        entry["stack_offset"] = int(stack_off)
                    except Exception:
                        pass
                    try:
                        first_use = v.getFirstUseOffset()
                        entry["first_use_offset"] = int(first_use)
                    except Exception:
                        pass
            return entry

        parameters = [_var_entry(p, is_param=True) for p in fn.getParameters()]
        locals_ = [_var_entry(lv, is_param=False) for lv in fn.getLocalVariables()]

        rm = handle.program.getReferenceManager()
        xref_count = int(rm.getReferenceCountTo(fn.getEntryPoint()))

        result: dict[str, Any] = {
            "function": _func_brief(fn),
            "prototype": str(fn.getPrototypeString(True, False)),
            "calling_convention": (
                str(fn.getCallingConventionName()) if fn.getCallingConventionName() else None
            ),
            "size": int(fn.getBody().getNumAddresses()),
            "is_thunk": bool(fn.isThunk()),
            "is_external": bool(fn.isExternal()),
            "parameters": parameters,
            "locals": locals_,
            "xref_count": xref_count,
        }
        if verbose:
            try:
                result["return_type"] = str(fn.getReturnType().getName())
            except Exception:
                pass
            try:
                result["no_return"] = bool(fn.hasNoReturn())
            except Exception:
                pass
            try:
                result["stack_frame_size"] = int(fn.getStackFrame().getFrameSize())
            except Exception:
                pass
            if fn.isThunk():
                thunked = fn.getThunkedFunction(True)
                if thunked is not None:
                    result["thunked"] = {
                        "name": str(thunked.getName()),
                        "address": f"0x{int(thunked.getEntryPoint().getOffset()):x}",
                        "is_external": bool(thunked.isExternal()),
                    }
        return result

    def _op_il(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        identifier = params.get("identifier")
        form = str(params.get("form", "raw")).lower()
        if form not in ("raw", "high"):
            raise OperationFailure("bad_request", f"unknown il form: {form!r} (use raw|high)")
        if identifier is None:
            raise OperationFailure("bad_request", "il requires 'identifier'")

        raw = bool(params.get("raw", False))
        show_indirect = bool(params.get("indirect", False))

        program = handle.program
        fn = _resolve_function(program, str(identifier))

        # Collect (PcodeOp, address, index) uniformly for both forms, then
        # derive structured `ops` and the text rendering from one pass.
        collected: list[tuple[Any, int, int]] = []
        if form == "raw":
            listing = program.getListing()
            for ins in listing.getInstructions(fn.getBody(), True):
                addr = int(ins.getAddress().getOffset())
                for i, op in enumerate(ins.getPcode()):
                    collected.append((op, addr, i))
        else:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
            from ghidra.util.task import TaskMonitor  # type: ignore

            iface = DecompInterface()
            iface.setOptions(DecompileOptions())
            iface.openProgram(program)
            try:
                results = iface.decompileFunction(
                    fn, int(params.get("timeout", 60)), TaskMonitor.DUMMY
                )
                if not results.decompileCompleted():
                    raise OperationFailure(
                        "decompile_failed",
                        results.getErrorMessage() or "decompilation did not complete",
                    )
                high = results.getHighFunction()
                if high is None:
                    raise OperationFailure(
                        "decompile_failed",
                        "decompiler did not produce a high function",
                    )
                it = high.getPcodeOps()
                seq = 0
                while it.hasNext():
                    op = it.next()
                    target_addr = op.getSeqnum().getTarget()
                    off = int(target_addr.getOffset()) if target_addr is not None else 0
                    collected.append((op, off, seq))
                    seq += 1
            finally:
                with contextlib.suppress(Exception):
                    iface.dispose()

        ops = [_pcode_desc(op, addr, idx, program) for (op, addr, idx) in collected]

        lines: list[str] = []
        hidden = 0
        if raw:
            # Legacy: Ghidra's unformatted PcodeOp.toString (raw varnode tuples).
            for op, addr, _idx in collected:
                lines.append(f"{addr:08x}  {op}")
        else:
            for desc in ops:
                if not show_indirect and desc.get("op") == "INDIRECT":
                    hidden += 1
                    continue
                lines.append(f"{int(desc['address'], 16):08x}  {_format_pcode_line(desc)}")
            if hidden:
                lines.append(
                    f"; {hidden} INDIRECT op(s) hidden "
                    f"(call/store side-effects; --indirect to show)"
                )

        return {
            "function": _func_brief(fn),
            "form": form,
            "raw": raw,
            "op_count": len(ops),
            "hidden_indirect": hidden,
            "text": "\n".join(lines),
            "ops": ops,
        }

    def _op_disasm(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        identifier = params.get("identifier")
        if identifier is None:
            raise OperationFailure("bad_request", "disasm requires 'identifier'")
        program = handle.program
        fn = _resolve_function(program, str(identifier))

        lines: list[str] = []
        rows: list[dict[str, Any]] = []
        listing = program.getListing()
        for ins in listing.getInstructions(fn.getBody(), True):
            addr = int(ins.getAddress().getOffset())
            try:
                raw = bytes(ins.getBytes())
            except Exception:
                raw = b""
            mnem = str(ins)
            lines.append(f"{addr:08x}  {mnem}")
            rows.append(
                {
                    "address": f"0x{addr:x}",
                    "bytes_hex": raw.hex(),
                    "disasm": mnem,
                }
            )
        return {
            "function": _func_brief(fn),
            "text": "\n".join(lines),
            "instructions": rows,
        }

    def _op_structured_il(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Per-pcode-op structured IL (op, output, inputs) — the substrate for
        data-flow/taint tooling. ``form=raw`` emits per-instruction raw p-code;
        ``form=high`` emits the decompiler's high (SSA) p-code with HighVariable
        names attached to varnodes where available."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        identifier = params.get("identifier")
        form = str(params.get("form", "high")).lower()
        if form not in ("raw", "high"):
            raise OperationFailure("bad_request", f"unknown il form: {form!r} (use raw|high)")
        if identifier is None:
            raise OperationFailure("bad_request", "structured_il requires 'identifier'")
        program = handle.program
        fn = _resolve_function(program, str(identifier))

        ops: list[dict[str, Any]] = []
        if form == "raw":
            listing = program.getListing()
            for ins in listing.getInstructions(fn.getBody(), True):
                addr = int(ins.getAddress().getOffset())
                for i, op in enumerate(ins.getPcode()):
                    ops.append(_pcode_desc(op, addr, i, program))
        else:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
            from ghidra.util.task import TaskMonitor  # type: ignore

            iface = DecompInterface()
            iface.setOptions(DecompileOptions())
            iface.openProgram(program)
            try:
                results = iface.decompileFunction(fn, int(params.get("timeout", 60)), TaskMonitor.DUMMY)
                if not results.decompileCompleted():
                    raise OperationFailure(
                        "decompile_failed",
                        results.getErrorMessage() or "decompilation did not complete",
                    )
                high = results.getHighFunction()
                if high is None:
                    raise OperationFailure(
                        "decompile_failed",
                        "decompiler did not produce a high function",
                    )
                it = high.getPcodeOps()
                seq = 0
                while it.hasNext():
                    op = it.next()
                    tgt = op.getSeqnum().getTarget()
                    off = int(tgt.getOffset()) if tgt is not None else 0
                    ops.append(_pcode_desc(op, off, seq, program))
                    seq += 1
            finally:
                with contextlib.suppress(Exception):
                    iface.dispose()

        return {
            "function": _func_brief(fn),
            "form": form,
            "op_count": len(ops),
            "ops": ops,
        }

    def _op_read_bytes(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Read raw bytes from program memory at an address. Stops early at an
        unmapped boundary and reports how many bytes were actually read."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        addr_s = params.get("address")
        if addr_s is None:
            raise OperationFailure("bad_request", "read_bytes requires 'address'")
        length = int(params.get("length", 16))
        if length <= 0:
            raise OperationFailure("bad_request", "length must be positive")
        if length > 65536:
            raise OperationFailure("bad_request", "length too large (max 65536 bytes)")

        # Accept a numeric address, or fall back to a symbol/function name
        # (matching how `xrefs` resolves its identifier).
        try:
            off = _parse_address(program, addr_s)
        except OperationFailure:
            try:
                sym, _ = _resolve_symbol(program, str(addr_s))
                sym_addr = sym.getAddress()
            except OperationFailure:
                sym_addr = None
            if sym_addr is None:
                raise OperationFailure(
                    "bad_address", f"could not resolve address or symbol: {addr_s!r}"
                )
            off = int(sym_addr.getOffset())
        base = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
        mem = program.getMemory()
        out = bytearray()
        for i in range(length):
            try:
                b = mem.getByte(base.add(i))
            except Exception:
                break
            out.append(int(b) & 0xFF)
        ascii_repr = "".join(chr(c) if 32 <= c < 127 else "." for c in out)
        return {
            "address": f"0x{off:x}",
            "length_requested": length,
            "length_read": len(out),
            "bytes_hex": out.hex(),
            "ascii": ascii_repr,
        }

    def _op_xrefs(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        identifier = params.get("identifier")
        if identifier is None:
            raise OperationFailure("bad_request", "xrefs requires 'identifier'")
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else None
        program = handle.program

        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()

        # Resolve the identifier to one or more target addresses. A raw address
        # is a single target. A symbol NAME may match several functions (a .plt
        # thunk AND its EXTERNAL stub) — union references across all of them
        # instead of raising ambiguous_function, mirroring `_op_callsites` (and
        # matching `bn xrefs <name>`, which lists callers without complaint).
        matched_entries: set[int] = set()
        matched_fns: list[Any] = []
        try:
            off = _parse_address(program, identifier)
            target_addrs = [
                program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
            ]
        except Exception:
            matched_fns = _resolve_functions(program, str(identifier))
            if not matched_fns:
                raise OperationFailure(
                    "not_found", f"no function matches identifier: {identifier!r}"
                )
            target_addrs = [fn.getEntryPoint() for fn in matched_fns]
            matched_entries = {int(a.getOffset()) for a in target_addrs}
            off = int(target_addrs[0].getOffset())

        code_refs: list[dict[str, Any]] = []
        seen_from: set[int] = set()
        for addr in target_addrs:
            for ref in rm.getReferencesTo(addr):
                from_addr = ref.getFromAddress()
                from_off = int(from_addr.getOffset())
                if from_off in seen_from:
                    continue
                caller = fm.getFunctionContaining(from_addr)
                # Drop a matched thunk's own trampoline branch to its EXTERNAL
                # stub (the caller is itself one of the unioned targets).
                if (matched_entries and caller is not None
                        and int(caller.getEntryPoint().getOffset()) in matched_entries):
                    continue
                seen_from.add(from_off)
                ref_type = ref.getReferenceType()
                ins = listing.getInstructionAt(from_addr)
                code_refs.append(
                    {
                        "address": f"0x{from_off:x}",
                        "function": str(caller.getName()) if caller is not None else None,
                        "ref_type": str(ref_type),
                        "is_call": bool(ref_type.isCall()),
                        "disasm": str(ins) if ins is not None else None,
                    }
                )

        outgoing: list[dict[str, Any]] = []
        seen_out: set[tuple[int, str]] = set()
        for addr in target_addrs:
            for ref in rm.getReferencesFrom(addr):
                to = ref.getToAddress()
                key = (int(to.getOffset()), str(ref.getReferenceType()))
                if key in seen_out:
                    continue
                seen_out.add(key)
                outgoing.append(
                    {
                        "address": f"0x{int(to.getOffset()):x}",
                        "ref_type": str(ref.getReferenceType()),
                    }
                )

        code_refs.sort(key=lambda r: int(r["address"], 16))
        incoming_total = len(code_refs)
        paged = code_refs[offset:]
        if limit is not None:
            paged = paged[:limit]

        result: dict[str, Any] = {
            "target": f"0x{off:x}",
            "incoming": paged,
            "incoming_total": incoming_total,
            "outgoing": outgoing,
        }
        if len(matched_fns) > 1:
            # The name matched several thunks/symbols whose refs we unioned.
            result["matched_targets"] = [_func_brief(c) for c in matched_fns]
        return result

    def _op_strings(self, params: dict[str, Any], target: str | None):
        from ghidra.program.util import DefinedStringIterator  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        query = params.get("query")
        use_regex = bool(params.get("regex"))
        pattern = None
        needle = None
        if query is not None:
            if use_regex:
                try:
                    pattern = re.compile(str(query), re.IGNORECASE)
                except re.error as exc:
                    raise ValueError(f"invalid --regex pattern: {exc}")
            else:
                needle = str(query).lower()
        section_filter = params.get("section")
        section_needle = str(section_filter) if section_filter else None
        include_metadata = bool(params.get("include_metadata"))
        min_len = int(params.get("min_length", 1))
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else None
        want_count = bool(params.get("count"))

        program = handle.program
        memory = program.getMemory()

        rows: list[dict[str, Any]] = []
        for data in DefinedStringIterator.forProgram(program):
            try:
                value = str(data.getDefaultValueRepresentation())
            except Exception:
                value = ""
            length = int(data.getLength())
            if length < min_len:
                continue
            # Match against the decoded string content, not Ghidra's C-literal
            # representation (e.g. `u8"libc.so.6"`), so anchored regexes and
            # substring queries behave intuitively.
            content = _decoded_string_value(value)
            if pattern is not None:
                if not pattern.search(content):
                    continue
            elif needle and needle not in content.lower():
                continue
            addr = data.getAddress()
            off = int(addr.getOffset())
            block = memory.getBlock(addr)
            section = str(block.getName()) if block is not None else None
            # Default to the loaded image only. The ELF loader adds file-only
            # metadata blocks (.shstrtab, .gnu_debuglink, _elfSectionHeaders) in
            # overlay spaces where isLoaded() is False; bn never reports strings
            # there. An explicit --section names a block, so honor it regardless.
            if (not include_metadata and section_needle is None
                    and block is not None and not block.isLoaded()):
                continue
            if section_needle and section != section_needle:
                continue
            # bn returns the raw decoded string; Ghidra's
            # getDefaultValueRepresentation() decorates it (`u8"libc.so.6"`).
            # Expose the decoded content as `value` (parity), carry the original
            # representation as `repr`, and split out the encoding prefix.
            encoding = None
            for pfx in ("u8", "U", "L", "u"):
                if value.startswith(pfx + '"'):
                    encoding = pfx
                    break
            rows.append(
                {
                    "address": f"0x{off:x}",
                    "length": length,
                    "value": content,
                    "repr": value,
                    "encoding": encoding,
                    "section": section,
                }
            )
        rows.sort(key=lambda row: int(row["address"], 16))
        if want_count:
            return {"count": len(rows)}
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        return rows

    def _op_imports(self, params: dict[str, Any], target: str | None):
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program

        rows: list[dict[str, Any]] = []
        for sym in program.getSymbolTable().getExternalSymbols():
            addr = sym.getAddress()
            off = int(addr.getOffset()) if addr is not None else 0
            library = None
            parent = sym.getParentNamespace()
            if parent is not None:
                library = str(parent.getName())
            rows.append(
                {
                    "name": str(sym.getName()),
                    "address": f"0x{off:x}",
                    "library": library,
                    "is_thunk": False,
                    "kind": "external",
                }
            )

        # Also surface thunk entries - these are where the call actually lands.
        for fn in program.getFunctionManager().getFunctions(True):
            if not fn.isThunk():
                continue
            thunked = fn.getThunkedFunction(True)
            if thunked is None or not thunked.isExternal():
                continue
            off = int(fn.getEntryPoint().getOffset())
            rows.append(
                {
                    "name": str(fn.getName()),
                    "address": f"0x{off:x}",
                    "library": (
                        str(thunked.getParentNamespace().getName())
                        if thunked.getParentNamespace() is not None
                        else None
                    ),
                    "is_thunk": True,
                    "kind": "thunk",
                }
            )

        # Imported DATA/object symbols (stderr, stdout, optarg, ...) are not
        # returned by getExternalSymbols() — Ghidra models them as IMPORTED
        # Labels in the synthetic EXTERNAL block. bn lists them as imports, so
        # surface them too (deduped by name against the function externals).
        seen_names = {r["name"] for r in rows}
        ext_block = next(
            (b for b in program.getMemory().getBlocks()
             if str(b.getName()) == _EXTERNAL_BLOCK_NAME),
            None,
        )
        if ext_block is not None:
            from ghidra.program.model.address import AddressSet  # type: ignore
            from ghidra.program.model.symbol import SymbolType  # type: ignore

            st = program.getSymbolTable()
            fm = program.getFunctionManager()
            aset = AddressSet(ext_block.getStart(), ext_block.getEnd())
            it = st.getSymbols(aset, SymbolType.LABEL, True)
            while it.hasNext():
                sym = it.next()
                if str(sym.getSource()) != "IMPORTED":
                    continue
                addr = sym.getAddress()
                if addr is None or fm.getFunctionContaining(addr) is not None:
                    continue  # a function external, already covered
                name = str(sym.getName())
                if name in seen_names:
                    continue
                seen_names.add(name)
                rows.append(
                    {
                        "name": name,
                        "address": f"0x{int(addr.getOffset()):x}",
                        "library": None,
                        "is_thunk": False,
                        "kind": "data",
                    }
                )

        rows.sort(key=lambda row: (row["name"], int(row["address"], 16)))

        if params.get("summary"):
            by_library: dict[str, int] = {}
            by_kind: dict[str, int] = {}
            for r in rows:
                lib = r.get("library") or "(none)"
                by_library[lib] = by_library.get(lib, 0) + 1
                k = r.get("kind", "external")
                by_kind[k] = by_kind.get(k, 0) + 1
            return {
                "total": len(rows),
                "by_kind": by_kind,
                "by_library": dict(
                    sorted(by_library.items(), key=lambda kv: (-kv[1], kv[0]))
                ),
            }
        if params.get("count"):
            return {"count": len(rows)}
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else None
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        return rows

    def _op_sections(self, params: dict[str, Any], target: str | None):
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        query = params.get("query")
        needle = str(query).lower() if query else None
        rows: list[dict[str, Any]] = []
        for block in handle.program.getMemory().getBlocks():
            name = str(block.getName())
            if needle and needle not in name.lower():
                continue
            start = int(block.getStart().getOffset())
            end = int(block.getEnd().getOffset())
            perms = (
                ("r" if block.isRead() else "-")
                + ("w" if block.isWrite() else "-")
                + ("x" if block.isExecute() else "-")
            )
            rows.append(
                {
                    "name": name,
                    "start": f"0x{start:x}",
                    "end": f"0x{end:x}",
                    "size": int(block.getSize()),
                    "perms": perms,
                    "initialized": bool(block.isInitialized()),
                    "source": str(block.getSourceName()) if block.getSourceName() else None,
                }
            )
        rows.sort(key=lambda row: int(row["start"], 16))
        if params.get("count"):
            return {"count": len(rows)}
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else None
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        return rows

    def _op_types(self, params: dict[str, Any], target: str | None) -> list[dict[str, Any]]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        query = params.get("query")
        needle = str(query).lower() if query else None
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else 500

        dtm = handle.program.getDataTypeManager()
        rows: list[dict[str, Any]] = []
        it = dtm.getAllDataTypes()
        while it.hasNext():
            dt = it.next()
            name = str(dt.getName())
            path = str(dt.getPathName())
            if needle and needle not in name.lower() and needle not in path.lower():
                continue
            try:
                size = int(dt.getLength())
            except Exception:
                size = -1
            rows.append(
                {
                    "name": name,
                    "path": path,
                    "kind": type(dt).__name__,
                    "size": size,
                }
            )
        rows.sort(key=lambda row: row["path"].lower())
        if params.get("count"):
            return {"count": len(rows)}
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        return rows

    def _op_type_info(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.program.model.data import Structure, Union, Enum, TypeDef  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        name = params.get("name")
        if not name:
            raise OperationFailure("bad_request", "type_info requires 'name'")

        dtm = handle.program.getDataTypeManager()
        dt = _find_data_type(dtm, str(name))
        if dt is None:
            raise OperationFailure("not_found", f"type not found: {name!r}")

        info: dict[str, Any] = {
            "name": str(dt.getName()),
            "path": str(dt.getPathName()),
            "kind": type(dt).__name__,
            "size": int(dt.getLength()) if dt.getLength() >= 0 else -1,
        }

        if isinstance(dt, Structure):
            fields = []
            for comp in dt.getDefinedComponents():
                fields.append(
                    {
                        "offset": int(comp.getOffset()),
                        "name": (
                            str(comp.getFieldName())
                            if comp.getFieldName() is not None
                            else f"field_{comp.getOffset():x}"
                        ),
                        "type": str(comp.getDataType().getName()),
                        "size": int(comp.getLength()),
                        "comment": str(comp.getComment()) if comp.getComment() else None,
                    }
                )
            info["fields"] = fields
            info["packed"] = bool(dt.isPackingEnabled())
            info["alignment"] = int(dt.getAlignment())
        elif isinstance(dt, Union):
            fields = []
            for comp in dt.getDefinedComponents():
                fields.append(
                    {
                        "name": str(comp.getFieldName()) or f"field_{comp.getOrdinal()}",
                        "type": str(comp.getDataType().getName()),
                        "size": int(comp.getLength()),
                    }
                )
            info["fields"] = fields
        elif isinstance(dt, Enum):
            values = []
            for nm in dt.getNames():
                values.append({"name": str(nm), "value": int(dt.getValue(nm))})
            info["values"] = values
        elif isinstance(dt, TypeDef):
            info["base_type"] = str(dt.getBaseDataType().getName())

        return info

    # ---- mutations ------------------------------------------------------

    def _op_rename_symbol(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.program.model.symbol import SourceType  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier") or params.get("address")
        new_name = params.get("new_name")
        preview = bool(params.get("preview", False))
        kind_pref = str(params.get("kind", "auto")).lower()
        if kind_pref not in ("auto", "function", "data"):
            raise OperationFailure("bad_request", f"unknown --kind: {kind_pref}")
        if not identifier or not new_name:
            raise OperationFailure("bad_request", "rename_symbol requires 'identifier' and 'new_name'")

        sym, kind = _resolve_symbol(program, str(identifier))
        if kind_pref == "function" and kind != "function":
            raise OperationFailure(
                "kind_mismatch",
                f"--kind function requested but {identifier!r} resolved to a {kind} symbol",
            )
        if kind_pref == "data" and kind == "function":
            raise OperationFailure(
                "kind_mismatch",
                f"--kind data requested but {identifier!r} resolved to a function",
            )
        before_name = str(sym.getName())
        before_addr = sym.getAddress()
        before_addr_s = f"0x{int(before_addr.getOffset()):x}" if before_addr is not None else None

        def _apply() -> None:
            if kind == "function" and kind_pref != "data":
                fm = program.getFunctionManager()
                fn = fm.getFunctionAt(sym.getAddress())
                if fn is not None:
                    fn.setName(str(new_name), SourceType.USER_DEFINED)
                    return
            sym.setName(str(new_name), SourceType.USER_DEFINED)

        def _verify() -> tuple[bool, str]:
            after = str(sym.getName())
            if after == str(new_name):
                return True, after
            return False, after

        return _run_mutation(
            program,
            description=f"ghx:rename_symbol {before_name} -> {new_name}",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"name": before_name, "address": before_addr_s, "kind": kind},
            after={"name": str(new_name), "address": before_addr_s, "kind": kind},
        )

    def _op_create_function(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Create (and let Ghidra body-analyze) a function at an address that
        auto-analysis missed. Errors if a function already exists there."""
        from ghidra.app.cmd.function import CreateFunctionCmd  # type: ignore
        from ghidra.program.model.symbol import SourceType  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        addr_s = params.get("address")
        if addr_s is None:
            raise OperationFailure("bad_request", "create_function requires 'address'")
        name = params.get("name")
        preview = bool(params.get("preview", False))

        off = _parse_address(program, addr_s)
        entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
        fm = program.getFunctionManager()
        existing = fm.getFunctionAt(entry)
        if existing is not None:
            raise OperationFailure(
                "already_exists",
                f"a function already exists at 0x{off:x}: {existing.getName()}",
            )

        def _apply() -> None:
            cmd = CreateFunctionCmd(
                str(name) if name else None, entry, None, SourceType.USER_DEFINED
            )
            if not cmd.applyTo(program, TaskMonitor.DUMMY):
                raise OperationFailure(
                    "create_failed",
                    cmd.getStatusMsg() or f"could not create a function at 0x{off:x}",
                )

        def _verify() -> tuple[bool, Any]:
            fn = fm.getFunctionAt(entry)
            if fn is None:
                return False, None
            return True, {
                "name": str(fn.getName()),
                "address": f"0x{off:x}",
                "size": int(fn.getBody().getNumAddresses()),
            }

        return _run_mutation(
            program,
            description=f"ghx:create_function @ 0x{off:x}",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"exists": False, "address": f"0x{off:x}"},
            after={"exists": True, "name": name, "address": f"0x{off:x}"},
        )

    def _op_set_comment(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        addr_s = params.get("address")
        text = params.get("text")
        kind = str(params.get("kind", "plate")).lower()
        preview = bool(params.get("preview", False))
        if addr_s is None or text is None:
            raise OperationFailure("bad_request", "set_comment requires 'address' and 'text'")

        comment_type = _comment_type(kind)
        listing = program.getListing()
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
            _parse_address(program, addr_s)
        )
        before = listing.getComment(comment_type, addr)
        before_s = str(before) if before is not None else None

        def _apply() -> None:
            listing.setComment(addr, comment_type, str(text))

        def _verify() -> tuple[bool, str]:
            current = listing.getComment(comment_type, addr)
            current_s = str(current) if current is not None else ""
            return current_s == str(text), current_s

        return _run_mutation(
            program,
            description=f"ghx:set_comment[{kind}] @ {addr_s}",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"address": f"0x{int(addr.getOffset()):x}", "kind": kind, "text": before_s},
            after={"address": f"0x{int(addr.getOffset()):x}", "kind": kind, "text": str(text)},
        )

    def _op_delete_comment(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        addr_s = params.get("address")
        kind = str(params.get("kind", "plate")).lower()
        preview = bool(params.get("preview", False))
        if addr_s is None:
            raise OperationFailure("bad_request", "delete_comment requires 'address'")

        comment_type = _comment_type(kind)
        listing = program.getListing()
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
            _parse_address(program, addr_s)
        )
        before = listing.getComment(comment_type, addr)
        before_s = str(before) if before is not None else None

        def _apply() -> None:
            listing.setComment(addr, comment_type, None)

        def _verify() -> tuple[bool, str]:
            current = listing.getComment(comment_type, addr)
            return current is None, str(current) if current is not None else ""

        return _run_mutation(
            program,
            description=f"ghx:delete_comment[{kind}] @ {addr_s}",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"address": f"0x{int(addr.getOffset()):x}", "kind": kind, "text": before_s},
            after={"address": f"0x{int(addr.getOffset()):x}", "kind": kind, "text": None},
        )

    def _op_get_comment(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        addr_s = params.get("address")
        kind = str(params.get("kind", "plate")).lower()
        if addr_s is None:
            raise OperationFailure("bad_request", "get_comment requires 'address'")

        comment_type = _comment_type(kind)
        listing = program.getListing()
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
            _parse_address(program, addr_s)
        )
        text = listing.getComment(comment_type, addr)
        return {
            "address": f"0x{int(addr.getOffset()):x}",
            "kind": kind,
            "text": str(text) if text is not None else None,
        }

    def _op_list_comments(self, params: dict[str, Any], target: str | None) -> list[dict[str, Any]]:
        from ghidra.program.model.listing import CodeUnit  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        listing = program.getListing()
        memory = program.getMemory()

        kinds = params.get("kinds")
        if kinds:
            want = [str(k).lower() for k in kinds]
        else:
            want = ["plate", "pre", "post", "eol", "repeatable"]

        rows: list[dict[str, Any]] = []
        type_map = {
            "plate": CodeUnit.PLATE_COMMENT,
            "pre": CodeUnit.PRE_COMMENT,
            "post": CodeUnit.POST_COMMENT,
            "eol": CodeUnit.EOL_COMMENT,
            "repeatable": CodeUnit.REPEATABLE_COMMENT,
        }
        for kind in want:
            ctype = type_map.get(kind)
            if ctype is None:
                continue
            it = listing.getCommentAddressIterator(ctype, memory, True)
            while it.hasNext():
                addr = it.next()
                text = listing.getComment(ctype, addr)
                if text is None:
                    continue
                rows.append(
                    {
                        "address": f"0x{int(addr.getOffset()):x}",
                        "kind": kind,
                        "text": str(text),
                    }
                )
        rows.sort(key=lambda row: (int(row["address"], 16), row["kind"]))
        return rows

    # ---- prototypes -----------------------------------------------------

    def _op_get_prototype(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        identifier = params.get("identifier")
        if identifier is None:
            raise OperationFailure("bad_request", "get_prototype requires 'identifier'")
        fn = _resolve_function(handle.program, str(identifier))
        return {
            "function": _func_brief(fn),
            "prototype": str(fn.getPrototypeString(True, True)),
            "prototype_formal": str(fn.getPrototypeString(True, False)),
            "calling_convention": (
                str(fn.getCallingConventionName()) if fn.getCallingConventionName() else None
            ),
        }

    def _op_set_prototype(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd  # type: ignore
        from ghidra.app.util.parser import FunctionSignatureParser  # type: ignore
        from ghidra.program.model.symbol import SourceType  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier")
        proto_src = params.get("prototype")
        preview = bool(params.get("preview", False))
        if not identifier or not proto_src:
            raise OperationFailure(
                "bad_request", "set_prototype requires 'identifier' and 'prototype'"
            )

        fn = _resolve_function(program, str(identifier))
        before_proto = str(fn.getPrototypeString(True, True))

        dtm = program.getDataTypeManager()
        parser = FunctionSignatureParser(dtm, None)
        normalized = _normalize_proto_spacing(str(proto_src))
        try:
            signature = parser.parse(fn.getSignature(), normalized)
        except Exception as exc:
            raise OperationFailure(
                "parse_failed",
                f"failed to parse prototype: {exc}; "
                f"tried {normalized!r}",
            ) from exc
        if signature is None:
            raise OperationFailure("parse_failed", f"could not parse prototype: {proto_src!r}")

        def _apply() -> None:
            cmd = ApplyFunctionSignatureCmd(
                fn.getEntryPoint(), signature, SourceType.USER_DEFINED
            )
            if not cmd.applyTo(program):
                raise OperationFailure(
                    "apply_failed",
                    f"ApplyFunctionSignatureCmd failed: {cmd.getStatusMsg() or 'unknown error'}",
                )

        def _verify() -> tuple[bool, str]:
            # Compare parameter types + return type with what we parsed; the
            # rendered string varies by calling convention (e.g. "processEntry")
            # so a direct string comparison is too strict.
            after_raw = str(fn.getPrototypeString(True, False))
            expected_params = [
                str(signature.getArguments()[i].getDataType().getName())
                for i in range(len(signature.getArguments()))
            ]
            expected_ret = str(signature.getReturnType().getName())
            actual_params = [
                str(p.getDataType().getName()) for p in fn.getParameters()
            ]
            actual_ret = str(fn.getReturnType().getName())
            ok = actual_params == expected_params and actual_ret == expected_ret
            return ok, after_raw

        return _run_mutation(
            program,
            description=f"ghx:set_prototype {fn.getName()}",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"function": _func_brief(fn), "prototype": before_proto},
            after={"function": _func_brief(fn), "prototype": str(signature)},
        )

    # ---- locals ---------------------------------------------------------

    def _op_list_locals(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        identifier = params.get("identifier")
        if identifier is None:
            raise OperationFailure("bad_request", "list_locals requires 'identifier'")
        fn = _resolve_function(handle.program, str(identifier))

        rows: list[dict[str, Any]] = []
        for p in fn.getParameters():
            rows.append(
                {
                    "id": _var_id(p),
                    "name": str(p.getName()),
                    "type": str(p.getDataType().getName()),
                    "storage": _storage_str(p),
                    "is_parameter": True,
                }
            )
        for lv in fn.getLocalVariables():
            rows.append(
                {
                    "id": _var_id(lv),
                    "name": str(lv.getName()),
                    "type": str(lv.getDataType().getName()),
                    "storage": _storage_str(lv),
                    "is_parameter": False,
                }
            )
        return {"function": _func_brief(fn), "locals": rows}

    def _op_local_rename(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier")
        old = params.get("name")
        new = params.get("new_name")
        preview = bool(params.get("preview", False))
        if not identifier or not old or not new:
            raise OperationFailure(
                "bad_request",
                "local_rename requires 'identifier', 'name', and 'new_name'",
            )
        fn = _resolve_function(program, str(identifier))
        return _apply_local_mutation(
            program,
            fn,
            var_name=str(old),
            new_name=str(new),
            new_type=None,
            preview=preview,
        )

    def _op_local_retype(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier")
        name = params.get("name")
        new_type = params.get("type")
        preview = bool(params.get("preview", False))
        if not identifier or not name or not new_type:
            raise OperationFailure(
                "bad_request",
                "local_retype requires 'identifier', 'name', and 'type'",
            )
        fn = _resolve_function(program, str(identifier))
        return _apply_local_mutation(
            program,
            fn,
            var_name=str(name),
            new_name=None,
            new_type=str(new_type),
            preview=preview,
        )

    # ---- types declare --------------------------------------------------

    def _op_types_declare(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.app.util.cparser.C import CParser  # type: ignore
        from ghidra.program.model.data import DataTypeConflictHandler  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        source = params.get("source")
        preview = bool(params.get("preview", False))
        if not source:
            raise OperationFailure("bad_request", "types_declare requires 'source'")

        dtm = program.getDataTypeManager()
        parser = CParser(dtm, False, None)

        applied: list[dict[str, Any]] = []
        errors: list[str] = []

        def _apply() -> None:
            try:
                parser.parse(str(source))
            except Exception as exc:
                raise OperationFailure("parse_failed", f"CParser error: {exc}") from exc
            # getComposites()/getEnums() return Map<String, DataType>; iterate values().
            seen: set[str] = set()
            for dt in list(parser.getComposites().values()) + list(parser.getEnums().values()):
                path = str(dt.getPathName())
                if path in seen:
                    continue
                seen.add(path)
                added = dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
                applied.append({"name": str(added.getName()), "path": str(added.getPathName())})

        def _verify() -> tuple[bool, Any]:
            missing = [row["path"] for row in applied if dtm.getDataType(row["path"]) is None]
            return not missing, {"applied": applied, "missing": missing}

        return _run_mutation(
            program,
            description="ghx:types_declare",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"applied": [], "source": str(source)[:200]},
            after={"applied": applied, "errors": errors},
        )

    # ---- struct field edits --------------------------------------------

    def _op_struct_field_set(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.app.util.cparser.C import CParser  # type: ignore
        from ghidra.program.model.data import Structure  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        type_name = params.get("type_name")
        offset = params.get("offset")
        field_name = params.get("field_name")
        field_type_s = params.get("field_type")
        length = params.get("length")
        overwrite = bool(params.get("overwrite", True))
        comment = params.get("comment")
        preview = bool(params.get("preview", False))

        if not type_name or offset is None or not field_type_s:
            raise OperationFailure(
                "bad_request",
                "struct_field_set requires 'type_name', 'offset', 'field_type'",
            )

        offset = int(offset, 0) if isinstance(offset, str) else int(offset)

        dtm = program.getDataTypeManager()
        struct = _find_data_type(dtm, str(type_name))
        if struct is None or not isinstance(struct, Structure):
            raise OperationFailure("not_found", f"struct not found: {type_name!r}")

        field_dt = _resolve_data_type(dtm, str(field_type_s))
        length = int(length) if length is not None else field_dt.getLength()
        before_fields = _struct_fields(struct)

        def _apply() -> None:
            if overwrite:
                struct.replaceAtOffset(offset, field_dt, length, field_name, comment)
            else:
                struct.insertAtOffset(offset, field_dt, length, field_name, comment)

        def _verify() -> tuple[bool, Any]:
            comp = struct.getComponentContaining(offset)
            if comp is None:
                return False, None
            observed = {
                "offset": int(comp.getOffset()),
                "name": str(comp.getFieldName()) if comp.getFieldName() else None,
                "type": str(comp.getDataType().getName()),
            }
            ok = (
                observed["type"] == str(field_dt.getName())
                and (field_name is None or observed["name"] == field_name)
            )
            return ok, observed

        return _run_mutation(
            program,
            description=f"ghx:struct_field_set {type_name}+0x{offset:x}",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"type_name": str(type_name), "fields": before_fields},
            after={
                "type_name": str(type_name),
                "offset": offset,
                "field_name": field_name,
                "field_type": str(field_dt.getName()),
                "length": length,
            },
        )

    def _op_struct_field_rename(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.program.model.data import Structure  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        type_name = params.get("type_name")
        old_name = params.get("name")
        offset_arg = params.get("offset")
        new_name = params.get("new_name")
        preview = bool(params.get("preview", False))
        if not type_name or not new_name or (old_name is None and offset_arg is None):
            raise OperationFailure(
                "bad_request",
                "struct_field_rename requires 'type_name', 'new_name', and 'name' or 'offset'",
            )

        dtm = program.getDataTypeManager()
        struct = _find_data_type(dtm, str(type_name))
        if struct is None or not isinstance(struct, Structure):
            raise OperationFailure("not_found", f"struct not found: {type_name!r}")

        comp = None
        if offset_arg is not None:
            offset = int(offset_arg, 0) if isinstance(offset_arg, str) else int(offset_arg)
            comp = struct.getComponentContaining(offset)
        else:
            for c in struct.getDefinedComponents():
                if c.getFieldName() and str(c.getFieldName()) == str(old_name):
                    comp = c
                    break
        if comp is None:
            raise OperationFailure("not_found", f"field not found in {type_name}")
        before = str(comp.getFieldName()) if comp.getFieldName() else None
        ordinal = int(comp.getOrdinal())

        def _apply() -> None:
            comp.setFieldName(str(new_name))

        def _verify() -> tuple[bool, Any]:
            c = struct.getComponent(ordinal)
            current = str(c.getFieldName()) if c.getFieldName() else None
            return current == str(new_name), current

        return _run_mutation(
            program,
            description=f"ghx:struct_field_rename {type_name}+0x{int(comp.getOffset()):x}",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"type_name": str(type_name), "name": before, "offset": int(comp.getOffset())},
            after={"type_name": str(type_name), "name": str(new_name), "offset": int(comp.getOffset())},
        )

    def _op_struct_field_delete(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.program.model.data import Structure  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        type_name = params.get("type_name")
        name = params.get("name")
        offset_arg = params.get("offset")
        preview = bool(params.get("preview", False))
        if not type_name or (name is None and offset_arg is None):
            raise OperationFailure(
                "bad_request",
                "struct_field_delete requires 'type_name' and 'name' or 'offset'",
            )

        dtm = program.getDataTypeManager()
        struct = _find_data_type(dtm, str(type_name))
        if struct is None or not isinstance(struct, Structure):
            raise OperationFailure("not_found", f"struct not found: {type_name!r}")

        comp = None
        if offset_arg is not None:
            offset = int(offset_arg, 0) if isinstance(offset_arg, str) else int(offset_arg)
            comp = struct.getComponentContaining(offset)
        else:
            for c in struct.getDefinedComponents():
                if c.getFieldName() and str(c.getFieldName()) == str(name):
                    comp = c
                    break
        if comp is None:
            raise OperationFailure("not_found", f"field not found in {type_name}")
        ordinal = int(comp.getOrdinal())
        before_name = str(comp.getFieldName()) if comp.getFieldName() else None
        before_offset = int(comp.getOffset())

        def _apply() -> None:
            struct.delete(ordinal)

        def _verify() -> tuple[bool, Any]:
            # After delete, either the ordinal shifts or the field at that offset
            # is now different. Compare by name.
            for c in struct.getDefinedComponents():
                if c.getFieldName() and str(c.getFieldName()) == (before_name or ""):
                    return False, "still present"
            return True, "removed"

        return _run_mutation(
            program,
            description=f"ghx:struct_field_delete {type_name}+0x{before_offset:x}",
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"type_name": str(type_name), "name": before_name, "offset": before_offset},
            after={"type_name": str(type_name), "name": None, "offset": before_offset},
        )

    # ---- callsites + bundle --------------------------------------------

    def _op_callsites(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier") or params.get("callee")
        within = params.get("within") or []
        context = int(params.get("context", 0))
        if identifier is None:
            raise OperationFailure("bad_request", "callsites requires 'identifier'")

        # A libc name usually resolves to BOTH a .plt thunk and the EXTERNAL
        # symbol; union the real call sites across all of them instead of
        # erroring with ambiguous_function. The isCall() filter naturally drops
        # the thunk->external trampoline references.
        callees = _resolve_functions(program, str(identifier))
        if not callees:
            raise OperationFailure(
                "not_found", f"no function matches identifier: {identifier!r}"
            )
        fm = program.getFunctionManager()
        listing = program.getListing()
        rm = program.getReferenceManager()

        allowed_callers: set[str] | None = None
        if within:
            allowed_callers = {str(w) for w in within}

        # Entry offsets of all matched targets, so we can drop a thunk's own
        # internal trampoline branch to the EXTERNAL (caller == one of the
        # matched thunks) rather than report it as a real call site.
        callee_entries = {int(c.getEntryPoint().getOffset()) for c in callees}

        sites: list[dict[str, Any]] = []
        seen_calls: set[int] = set()
        for callee in callees:
            callee_name = str(callee.getName())
            for ref in rm.getReferencesTo(callee.getEntryPoint()):
                rtype = ref.getReferenceType()
                if not rtype.isCall():
                    continue
                from_addr = ref.getFromAddress()
                call_off = int(from_addr.getOffset())
                if call_off in seen_calls:
                    continue
                caller = fm.getFunctionContaining(from_addr)
                if caller is not None and int(caller.getEntryPoint().getOffset()) in callee_entries:
                    continue
                caller_name = str(caller.getName()) if caller is not None else None
                if allowed_callers and caller_name not in allowed_callers:
                    continue
                seen_calls.add(call_off)
                ins = listing.getInstructionAt(from_addr)
                return_addr = None
                if ins is not None:
                    try:
                        return_addr = ins.getMaxAddress().add(1)
                    except Exception:
                        return_addr = None
                return_str = (
                    f"0x{int(return_addr.getOffset()):x}" if return_addr is not None else None
                )
                site: dict[str, Any] = {
                    "callee": callee_name,
                    "caller": caller_name,
                    "call_addr": f"0x{call_off:x}",
                    "return_address": return_str,
                    # caller_static: the static return address (instruction after
                    # the call) used to map a stack return address back here.
                    "caller_static": return_str,
                    "ref_type": str(rtype),
                    "disasm": str(ins) if ins is not None else None,
                }
                if context > 0 and ins is not None:
                    site["prev_ins"] = _surrounding_instructions(listing, ins, -context)
                    site["next_ins"] = _surrounding_instructions(listing, ins, context)
                sites.append(site)

        sites.sort(key=lambda row: int(row["call_addr"], 16))
        result = {"callee": _func_brief(callees[0]), "callsites": sites}
        if len(callees) > 1:
            # Surface that the name matched several thunks/symbols we unioned.
            result["matched_targets"] = [_func_brief(c) for c in callees]
        return result

    def _op_evidence_xrefs(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Xrefs enriched with section/symbol context on top of `_op_xrefs`.
        Incoming refs already carry the containing function + disassembly; this
        adds the memory block (section/segment) for every ref and the
        destination symbol for outgoing refs."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        base = self._op_xrefs(params, target)

        for ref in base.get("incoming", []):
            try:
                off = int(ref["address"], 16)
            except (KeyError, ValueError, TypeError):
                continue
            ref["section"] = _block_name_for(program, off)
        for ref in base.get("outgoing", []):
            try:
                off = int(ref["address"], 16)
            except (KeyError, ValueError, TypeError):
                continue
            ref["section"] = _block_name_for(program, off)
            ref["symbol"] = _primary_symbol_name(program, off)

        try:
            toff = int(base["target"], 16)
            base["target_section"] = _block_name_for(program, toff)
            base["target_symbol"] = _primary_symbol_name(program, toff)
        except (KeyError, ValueError, TypeError):
            pass
        return base

    def _op_evidence_function(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Generic function evidence: thunk candidates, outgoing calls,
        instruction/IL volume, and argument hints — a one-shot triage summary."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier") or params.get("name")
        if identifier is None:
            raise OperationFailure("bad_request", "evidence_function requires 'identifier'")
        fn = _resolve_function(program, str(identifier))
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()

        calls: list[dict[str, Any]] = []
        instruction_count = 0
        for ins in listing.getInstructions(fn.getBody(), True):
            instruction_count += 1
            for ref in ins.getReferencesFrom():
                rtype = ref.getReferenceType()
                if not rtype.isCall():
                    continue
                to = ref.getToAddress()
                callee = fm.getFunctionAt(to) or fm.getFunctionContaining(to)
                calls.append(
                    {
                        "call_addr": f"0x{int(ins.getAddress().getOffset()):x}",
                        "target": str(callee.getName()) if callee is not None else None,
                        "target_addr": f"0x{int(to.getOffset()):x}",
                        "is_external": bool(callee.isExternal()) if callee is not None else None,
                    }
                )

        arg_hints = [
            {
                "name": str(p.getName()),
                "type": str(p.getDataType().getName()),
                "storage": _storage_str(p),
            }
            for p in fn.getParameters()
        ]

        result: dict[str, Any] = {
            "function": _func_brief(fn),
            "prototype": str(fn.getPrototypeString(True, False)),
            "calling_convention": (
                str(fn.getCallingConventionName()) if fn.getCallingConventionName() else None
            ),
            "section": _block_name_for(program, int(fn.getEntryPoint().getOffset())),
            "is_thunk": bool(fn.isThunk()),
            "is_external": bool(fn.isExternal()),
            "incoming_xref_count": int(rm.getReferenceCountTo(fn.getEntryPoint())),
            "instruction_count": instruction_count,
            "call_count": len(calls),
            "calls": calls,
            "arg_hints": arg_hints,
        }
        if fn.isThunk():
            thunked = fn.getThunkedFunction(True)
            if thunked is not None:
                result["thunked"] = {
                    "name": str(thunked.getName()),
                    "address": f"0x{int(thunked.getEntryPoint().getOffset()):x}",
                    "is_external": bool(thunked.isExternal()),
                }
        return result

    # Section names that hold ctor/dtor function pointers across toolchains.
    _INIT_SECTION_NAMES = (
        ".init_array", ".fini_array", ".preinit_array", ".ctors", ".dtors",
    )

    def _op_evidence_init(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Summarize constructor/destructor pointer sections (.init_array,
        .fini_array, .ctors, .dtors): walk each as a pointer array and resolve
        every slot to a function."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        ptr_size = int(program.getDefaultPointerSize())
        wanted = {n.lower() for n in self._INIT_SECTION_NAMES}
        limit = int(params["limit"]) if params.get("limit") is not None else None

        sections: list[dict[str, Any]] = []
        for block in program.getMemory().getBlocks():
            name = str(block.getName())
            if name.lower() not in wanted:
                continue
            start = int(block.getStart().getOffset())
            size = int(block.getSize())
            entries: list[dict[str, Any]] = []
            count = size // ptr_size if ptr_size else 0
            for i in range(count):
                slot_off = start + i * ptr_size
                value = _read_pointer(program, slot_off, ptr_size)
                if value is None:
                    continue
                entry = {"slot": f"0x{slot_off:x}", **_resolve_pointer_target(program, value)}
                entries.append(entry)
            full_count = len(entries)
            truncated = limit is not None and full_count > limit
            if truncated:
                entries = entries[:limit]
            sections.append(
                {
                    "name": name,
                    "start": f"0x{start:x}",
                    "size": size,
                    "pointer_size": ptr_size,
                    "count": full_count,
                    "shown": len(entries),
                    "truncated": truncated,
                    "entries": entries,
                }
            )
        return {"sections": sections, "section_count": len(sections)}

    def _op_evidence_table(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Interpret memory at an address as a pointer table / vtable: read
        consecutive pointers and resolve each, stopping at *count* or at the
        first unmapped slot (unless ``stop_on_unmapped`` is false)."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        addr_s = params.get("address")
        if addr_s is None:
            raise OperationFailure("bad_request", "evidence_table requires 'address'")
        count = int(params.get("count", 16))
        if count <= 0 or count > 4096:
            raise OperationFailure("bad_request", "count must be in 1..4096")
        stop_on_unmapped = bool(params.get("stop_on_unmapped", True))
        ptr_size = int(params.get("pointer_size", program.getDefaultPointerSize()))

        try:
            start = _parse_address(program, addr_s)
        except OperationFailure:
            sym, _ = _resolve_symbol(program, str(addr_s))
            sym_addr = sym.getAddress()
            if sym_addr is None:
                raise OperationFailure("bad_address", f"could not resolve: {addr_s!r}")
            start = int(sym_addr.getOffset())

        entries: list[dict[str, Any]] = []
        for i in range(count):
            slot_off = start + i * ptr_size
            value = _read_pointer(program, slot_off, ptr_size)
            if value is None:
                break
            resolved = _resolve_pointer_target(program, value)
            if stop_on_unmapped and resolved.get("kind") == "unmapped" and i > 0:
                break
            entries.append({"slot": f"0x{slot_off:x}", "index": i, **resolved})

        function_slots = sum(1 for e in entries if e.get("kind") == "function")
        return {
            "address": f"0x{start:x}",
            "pointer_size": ptr_size,
            "count": len(entries),
            "function_slots": function_slots,
            "looks_like_vtable": function_slots >= 2 and function_slots >= len(entries) - 1,
            "entries": entries,
        }

    def _op_evidence_message(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Surface message/type-name strings (C++ RTTI names, protobuf type
        names, etc.) with their cross-references and section context. With a
        ``query`` it matches that substring/regex; without one it falls back to
        a type-name heuristic (contains '::', or a dotted package.Type token)."""
        from ghidra.program.util import DefinedStringIterator  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        query = params.get("query")
        regex = bool(params.get("regex", False))
        limit = int(params.get("limit", 50))
        min_len = int(params.get("min_length", 3))

        if query:
            if regex:
                import re as _re

                try:
                    pattern = _re.compile(str(query))
                except Exception as exc:  # re.error
                    raise OperationFailure("invalid_regex", f"invalid regex: {exc}") from exc

                def matcher(value: str) -> bool:
                    return bool(pattern.search(value))
            else:
                needle = str(query).lower()

                def matcher(value: str) -> bool:
                    return needle in value.lower()
        else:
            def matcher(value: str) -> bool:
                if "::" in value:
                    return True
                token = value.strip().strip('"')
                return (
                    "." in token
                    and " " not in token
                    and len(token) >= 4
                    and token[:1].isalpha()
                )

        mem = program.getMemory()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()
        matches: list[dict[str, Any]] = []
        for data in DefinedStringIterator.forProgram(program):
            try:
                value = str(data.getDefaultValueRepresentation())
            except Exception:
                continue
            if int(data.getLength()) < min_len or not matcher(value):
                continue
            addr = data.getAddress()
            off = int(addr.getOffset())
            block = mem.getBlock(addr)
            xrefs: list[dict[str, Any]] = []
            for ref in rm.getReferencesTo(addr):
                from_addr = ref.getFromAddress()
                caller = fm.getFunctionContaining(from_addr)
                xrefs.append(
                    {
                        "from": f"0x{int(from_addr.getOffset()):x}",
                        "function": str(caller.getName()) if caller is not None else None,
                        "ref_type": str(ref.getReferenceType()),
                    }
                )
            matches.append(
                {
                    "address": f"0x{off:x}",
                    "value": value,
                    "length": int(data.getLength()),
                    "section": str(block.getName()) if block is not None else None,
                    "xref_count": len(xrefs),
                    "xrefs": xrefs,
                }
            )
            if len(matches) >= limit:
                break
        return {
            "matches": matches,
            "match_count": len(matches),
            "truncated": len(matches) >= limit,
        }

    # ---- data-flow (Tier A) --------------------------------------------

    @contextlib.contextmanager
    def _high_function(self, program: Any, fn: Any, timeout: int = 60):
        """Decompile *fn* and yield its HighFunction (SSA form), disposing the
        decompiler interface afterwards. Shared substrate for data-flow ops."""
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        iface = DecompInterface()
        iface.setOptions(DecompileOptions())
        iface.openProgram(program)
        try:
            results = iface.decompileFunction(fn, int(timeout), TaskMonitor.DUMMY)
            if not results.decompileCompleted():
                raise OperationFailure(
                    "decompile_failed",
                    results.getErrorMessage() or "decompilation did not complete",
                )
            high = results.getHighFunction()
            if high is None:
                raise OperationFailure(
                    "decompile_failed", "decompiler did not produce a high function"
                )
            yield high
        finally:
            with contextlib.suppress(Exception):
                iface.dispose()

    @staticmethod
    def _find_high_symbol(high: Any, var_name: str) -> Any:
        """Locate a HighSymbol by name in a HighFunction's local symbol map."""
        lsm = high.getLocalSymbolMap()
        it = lsm.getSymbols()
        while it.hasNext():
            sym = it.next()
            if str(sym.getName()) == var_name:
                return sym
        return None

    @staticmethod
    def _available_var_names(high: Any) -> list[str]:
        names: set[str] = set()
        it = high.getLocalSymbolMap().getSymbols()
        while it.hasNext():
            names.add(str(it.next().getName()))
        return sorted(names)

    def _op_dataflow_defuse(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """SSA def/use for a named variable: the definition site and every use
        site of each SSA instance of the variable, via HighFunction."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier")
        var_name = params.get("variable")
        if identifier is None or var_name is None:
            raise OperationFailure(
                "bad_request", "dataflow_defuse requires 'identifier' and 'variable'"
            )
        fn = _resolve_function(program, str(identifier))

        with self._high_function(program, fn, int(params.get("timeout", 60))) as high:
            sym = self._find_high_symbol(high, str(var_name))
            if sym is None:
                avail = self._available_var_names(high)
                raise OperationFailure(
                    "not_found",
                    f"no variable named {var_name!r}; available: {', '.join(avail[:40])}",
                )
            hv = sym.getHighVariable()
            if hv is None:
                raise OperationFailure(
                    "not_found",
                    f"variable {var_name!r} has no SSA high variable (optimized out?)",
                )
            instances: list[dict[str, Any]] = []
            for vn in hv.getInstances():
                definition = _high_pcode_desc(vn.getDef(), program)
                uses: list[dict[str, Any]] = []
                it = vn.getDescendants()
                while it.hasNext():
                    desc = _high_pcode_desc(it.next(), program)
                    if desc is not None:
                        uses.append(desc)
                instances.append(
                    {
                        "varnode": _varnode_desc(vn, program),
                        "definition": definition,
                        "use_count": len(uses),
                        "uses": uses,
                    }
                )
            dtype = None
            try:
                if hv.getDataType() is not None:
                    dtype = str(hv.getDataType().getName())
            except Exception:
                dtype = None
            return {
                "function": _func_brief(fn),
                "variable": str(var_name),
                "type": dtype,
                "instance_count": len(instances),
                "instances": instances,
            }

    def _op_dataflow_values(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Constants resolved at an address via Ghidra's SymbolicPropogator.
        HONEST SCOPE: this reports proven *constant* register values, not a full
        value-set (no ranges / multi-value sets — Ghidra has no native VSA)."""
        from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator  # type: ignore
        from ghidra.program.util import SymbolicPropogator  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier")
        addr_s = params.get("address")
        reg_name = params.get("register")
        if identifier is None or addr_s is None:
            raise OperationFailure(
                "bad_request", "dataflow_values requires 'identifier' and 'address'"
            )
        fn = _resolve_function(program, str(identifier))
        query_off = _parse_address(program, addr_s)
        query_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(query_off)
        if not fn.getBody().contains(query_addr):
            raise OperationFailure(
                "bad_request",
                f"address 0x{query_off:x} is not inside {fn.getName()}",
            )

        monitor = TaskMonitor.DUMMY
        sp = SymbolicPropogator(program)
        evaluator = ConstantPropagationContextEvaluator(monitor, True)
        sp.flowConstants(fn.getEntryPoint(), fn.getBody(), evaluator, True, monitor)

        if reg_name:
            reg = program.getRegister(str(reg_name))
            if reg is None:
                raise OperationFailure("not_found", f"unknown register: {reg_name!r}")
            registers = [reg]
        else:
            registers = [r for r in program.getLanguage().getRegisters() if r.isBaseRegister()]

        # Drop stack/frame/link/pc housekeeping registers (only meaningful in the
        # all-registers case; an explicit --register is always honoured).
        drop_frame = bool(params.get("no_frame")) and not reg_name

        mask = (1 << (8 * int(program.getDefaultPointerSize()))) - 1
        values: list[dict[str, Any]] = []
        seen: set[str] = set()
        for reg in registers:
            try:
                val = sp.getRegisterValue(query_addr, reg)
            except Exception:
                val = None
            if val is None:
                continue
            name = str(reg.getName())
            if drop_frame and name.lower() in _FRAME_REGISTER_NAMES:
                continue
            if name in seen:
                continue
            seen.add(name)
            try:
                raw = int(val.getValue())
            except Exception:
                continue
            rep = None
            with contextlib.suppress(Exception):
                rep = str(sp.getRegisterValueRepresentation(query_addr, reg))
            values.append(
                {
                    "register": name,
                    "value": f"0x{raw & mask:x}",
                    "value_dec": raw,
                    "repr": rep,
                }
            )
        values.sort(key=lambda x: x["register"])
        return {
            "function": _func_brief(fn),
            "address": f"0x{query_off:x}",
            "value_count": len(values),
            "values": values,
            "note": (
                "proven constants from Ghidra SymbolicPropogator; not a full "
                "value-set (single constants only, no ranges/multi-value)"
            ),
        }

    @staticmethod
    def _find_call_op(high: Any, target_off: int) -> Any:
        """The CALL/CALLIND high-pcode op at *target_off*, or None."""
        it = high.getPcodeOps()
        while it.hasNext():
            op = it.next()
            tgt = op.getSeqnum().getTarget()
            if (
                tgt is not None
                and int(tgt.getOffset()) == target_off
                and str(op.getMnemonic()) in ("CALL", "CALLIND")
            ):
                return op
        return None

    @staticmethod
    def _name_set(value: Any, default: tuple[str, ...]) -> set[str]:
        """Normalize a source/sink spec (list or comma string) to a name set."""
        if value is None or value == "":
            names: Any = default
        elif isinstance(value, list):
            names = value
        else:
            names = str(value).split(",")
        return {_normalize_fn_name(n.strip()) for n in names if str(n).strip()}

    @contextlib.contextmanager
    def _decompiler(self, program: Any):
        """A reusable DecompInterface for many functions (interprocedural taint),
        disposed at the end. Use `_decompile` to decompile + cache against it."""
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore

        iface = DecompInterface()
        iface.setOptions(DecompileOptions())
        iface.openProgram(program)
        try:
            yield iface
        finally:
            with contextlib.suppress(Exception):
                iface.dispose()

    @staticmethod
    def _decompile(iface: Any, fn: Any, timeout: int, state: dict[str, Any]) -> Any:
        """Decompile *fn* via a shared iface, caching the HighFunction and
        bounding the total decompile count (a runaway-call backstop)."""
        from ghidra.util.task import TaskMonitor  # type: ignore

        key = int(fn.getEntryPoint().getOffset())
        cache = state["cache"]
        if key in cache:
            return cache[key]
        if state["decompiles"] >= state.get("cap", 400):
            cache[key] = None
            return None
        state["decompiles"] += 1
        res = iface.decompileFunction(fn, timeout, TaskMonitor.DUMMY)
        high = res.getHighFunction() if res.decompileCompleted() else None
        cache[key] = high
        return high

    def _function_src_bufs(
        self, program: Any, high: Any, sources: set[str]
    ) -> tuple[list[dict[str, Any]], dict[int, str]]:
        """Source out-buffer sites in one function: each source call (read/recv/
        fgets/getline/...) and the buffer-identity keys of the buffer it writes,
        plus the function's stack-symbol map (for `&stackvar` resolution)."""
        stack_syms = _stack_symbol_map(high)
        src_bufs: list[dict[str, Any]] = []
        it = high.getPcodeOps()
        while it.hasNext():
            op = it.next()
            if str(op.getMnemonic()) not in ("CALL", "CALLIND"):
                continue
            callee = _callop_callee_name(program, op)
            if callee not in sources:
                continue
            buf_idx = _TAINT_SOURCE_OUTBUF.get(callee)
            if buf_idx is None:
                continue
            inputs = list(op.getInputs())
            slot = buf_idx + 1  # input[0] is the call target
            if slot >= len(inputs):
                continue
            keys = _buffer_keys(inputs[slot], stack_syms)
            if keys:
                src_bufs.append({
                    "name": callee,
                    "off": int(op.getSeqnum().getTarget().getOffset()),
                    "keys": keys,
                })
        return src_bufs, stack_syms

    def _arg_taint_origins(
        self, program: Any, high: Any, arg_vn: Any, sources: set[str],
        src_bufs: list[dict[str, Any]], stack_syms: dict[int, str], max_steps: int,
    ) -> tuple[list, list, set, list, bool]:
        """For one argument varnode, classify where its value comes from:
        source return values, source out-buffers it aliases, and the parameter
        indices of the containing function it derives from (the seam for
        interprocedural propagation)."""
        _, origins, truncated = _backward_slice(arg_vn, program, max_steps)
        returns: list[tuple] = []
        param_idxs: set[int] = set()
        for o in origins:
            kind = o.get("kind")
            if kind == "call_result":
                c = o.get("callee")
                if c and _normalize_fn_name(c) in sources:
                    returns.append((_normalize_fn_name(c), o.get("address")))
            elif kind == "parameter" and o.get("param_index") is not None:
                param_idxs.add(int(o["param_index"]))
        outbufs: list[tuple] = []
        if src_bufs:
            argkeys = _buffer_keys_expanded(arg_vn, stack_syms)
            if argkeys:
                for sb in src_bufs:
                    if sb["keys"] & argkeys:
                        outbufs.append((sb["name"], sb["off"]))
        return returns, outbufs, param_idxs, origins, truncated

    def _interproc_taint(
        self, program: Any, iface: Any, state: dict[str, Any], fn: Any,
        param_idx: int, ip_depth: int, sources: set[str], max_steps: int, timeout: int,
    ) -> list[dict[str, Any]]:
        """Walk UP the call graph from (fn, param_idx): at each caller, the
        actual argument passed for that parameter is checked for a source origin
        (return value or out-buffer written before the call); if it instead
        derives from the caller's OWN parameter, recurse one frame higher,
        bounded by ip_depth. Conservative — it relies on the decompiler's own
        arg/param model, so imperfect signatures cause MISSES, not false chains."""
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        results: list[dict[str, Any]] = []
        work: list[tuple] = [(fn, param_idx, ip_depth, [])]
        visited: set[tuple] = set()
        while work:
            cur_fn, pidx, depth, path = work.pop()
            vkey = (int(cur_fn.getEntryPoint().getOffset()), pidx)
            if vkey in visited:
                continue
            visited.add(vkey)
            for ref in rm.getReferencesTo(cur_fn.getEntryPoint()):
                if not ref.getReferenceType().isCall():
                    continue
                from_addr = ref.getFromAddress()
                from_off = int(from_addr.getOffset())
                caller = fm.getFunctionContaining(from_addr)
                if caller is None:
                    continue
                high = self._decompile(iface, caller, timeout, state)
                if high is None:
                    continue
                call_op = self._find_call_op(high, from_off)
                if call_op is None:
                    continue
                cin = list(call_op.getInputs())
                slot = pidx + 1  # input[0] is the call target
                if slot >= len(cin):
                    continue  # decompiler didn't model that arg -> conservative miss
                src_bufs, stack_syms = self._function_src_bufs(program, high, sources)
                returns, outbufs, pidxs, _, _ = self._arg_taint_origins(
                    program, high, cin[slot], sources, src_bufs, stack_syms, max_steps
                )
                frame = f"{caller.getName()}@0x{from_off:x}"
                for sname, saddr in returns:
                    results.append({
                        "source": sname, "source_at": saddr,
                        "via": "return_value", "frames": path + [frame],
                    })
                for sname, soff in outbufs:
                    if soff >= from_off:
                        continue  # source must write the buffer before passing it
                    results.append({
                        "source": sname, "source_at": f"0x{soff:x}",
                        "via": "out_buffer", "frames": path + [frame],
                    })
                if depth > 0:
                    for pj in pidxs:
                        work.append((caller, pj, depth - 1, path + [frame]))
        return results

    def _interproc_backward(
        self, program: Any, iface: Any, state: dict[str, Any], fn: Any,
        param_idx: int, ip_depth: int, max_steps: int, timeout: int,
    ) -> list[dict[str, Any]]:
        """Continue a backward slice ACROSS call boundaries: when a slice in *fn*
        reaches parameter *param_idx*, walk to each caller, slice the actual
        argument it passes, and collect those origins (tagged with the caller
        frame and path). Recurse up to ip_depth frames. Same conservative
        param->arg mapping as `_interproc_taint`: missing signatures under-report."""
        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        results: list[dict[str, Any]] = []
        seen_out: set[str] = set()
        work: list[tuple] = [(fn, param_idx, ip_depth, [])]
        visited: set[tuple] = set()
        while work:
            cur_fn, pidx, depth, path = work.pop()
            vkey = (int(cur_fn.getEntryPoint().getOffset()), pidx)
            if vkey in visited:
                continue
            visited.add(vkey)
            for ref in rm.getReferencesTo(cur_fn.getEntryPoint()):
                if not ref.getReferenceType().isCall():
                    continue
                from_addr = ref.getFromAddress()
                from_off = int(from_addr.getOffset())
                caller = fm.getFunctionContaining(from_addr)
                if caller is None or caller.isThunk():
                    continue
                high = self._decompile(iface, caller, timeout, state)
                if high is None:
                    continue
                call_op = self._find_call_op(high, from_off)
                if call_op is None:
                    continue
                cin = list(call_op.getInputs())
                slot = pidx + 1
                if slot >= len(cin):
                    continue  # decompiler didn't model that arg -> conservative
                _, origins, _ = _backward_slice(cin[slot], program, max_steps)
                frame = f"{caller.getName()}@0x{from_off:x}"
                frames = path + [frame]
                for o in origins:
                    rec = dict(o)
                    rec["frame"] = str(caller.getName())
                    rec["path"] = frames
                    dk = json.dumps(rec, sort_keys=True)
                    if dk not in seen_out:
                        seen_out.add(dk)
                        results.append(rec)
                    if (depth > 0 and o.get("kind") == "parameter"
                            and o.get("param_index") is not None):
                        work.append((caller, int(o["param_index"]), depth - 1, frames))
        return results

    def _op_taint_forward(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Forward taint: report source->sink chains. Intraprocedural by default,
        two ways: (a) return_value — a sink arg backward-slices to a source
        call's return value; (b) out_buffer — a sink arg refers to a buffer a
        preceding source call WROTE via an out-parameter (read/recv/fgets/
        getline/...). With interprocedural=True it also follows a sink arg that
        derives from a parameter UP the call graph (bounded by ip_depth) to a
        source in an ancestor frame, emitting a chain with the frame `path`.
        Cross-function propagation off => 0 chains is still not an all-clear."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        sources = self._name_set(params.get("sources"), _DEFAULT_TAINT_SOURCES)
        sinks = self._name_set(params.get("sinks"), _DEFAULT_TAINT_SINKS)
        scope_fn = params.get("function")
        max_steps = int(params.get("max_steps", 400))
        timeout = int(params.get("timeout", 60))
        interprocedural = bool(params.get("interprocedural"))
        ip_depth = int(params.get("ip_depth", 3))

        fm = program.getFunctionManager()
        rm = program.getReferenceManager()

        # Locate sink call sites cheaply, grouped by the calling function.
        sink_sites: dict[int, dict[str, Any]] = {}
        for fn in fm.getFunctions(True):
            if _normalize_fn_name(fn.getName()) not in sinks:
                continue
            sink_norm = _normalize_fn_name(fn.getName())
            for ref in rm.getReferencesTo(fn.getEntryPoint()):
                if not ref.getReferenceType().isCall():
                    continue
                from_addr = ref.getFromAddress()
                caller = fm.getFunctionContaining(from_addr)
                if caller is None:
                    continue
                # A thunk's body is just the trampoline branch to its target —
                # not a real sink use site. Skipping it avoids a spurious
                # (duplicate) chain through the sink's own .plt thunk, which
                # interprocedural propagation would otherwise walk up.
                if caller.isThunk():
                    continue
                key = int(caller.getEntryPoint().getOffset())
                entry = sink_sites.setdefault(key, {"fn": caller, "sites": []})
                entry["sites"].append((int(from_addr.getOffset()), sink_norm))

        if scope_fn:
            scope = _resolve_function(program, str(scope_fn))
            skey = int(scope.getEntryPoint().getOffset())
            sink_sites = {skey: sink_sites[skey]} if skey in sink_sites else {}

        chains: list[dict[str, Any]] = []
        scanned = 0
        ip_state = {"cache": {}, "decompiles": 0, "cap": 400}
        ip_cm = self._decompiler(program) if interprocedural else contextlib.nullcontext()
        with ip_cm as ip_iface:
            for info in sink_sites.values():
                caller = info["fn"]
                scanned += 1
                try:
                    with self._high_function(program, caller, timeout) as high:
                        src_bufs, stack_syms = self._function_src_bufs(
                            program, high, sources
                        )
                        seen_out: set[tuple] = set()
                        seen_ip: set[tuple] = set()
                        for call_off, sink_name in info["sites"]:
                            call_op = self._find_call_op(high, call_off)
                            if call_op is None:
                                continue
                            inputs = list(call_op.getInputs())
                            for arg_idx in range(1, len(inputs)):
                                returns, outbufs, param_idxs, origins, truncated = \
                                    self._arg_taint_origins(
                                        program, high, inputs[arg_idx], sources,
                                        src_bufs, stack_syms, max_steps,
                                    )
                                # (a) intra return_value chains.
                                for sname, saddr in returns:
                                    chains.append({
                                        "function": _func_brief(caller),
                                        "source": sname,
                                        "source_at": saddr,
                                        "sink": sink_name,
                                        "sink_at": f"0x{call_off:x}",
                                        "arg": arg_idx - 1,
                                        "via": "return_value",
                                        "origins": origins,
                                        "truncated": truncated,
                                    })
                                # (b) intra out_buffer chains: a preceding source
                                # call wrote this buffer (source_addr < sink).
                                for sname, soff in outbufs:
                                    if soff >= call_off:
                                        continue
                                    dedup = (soff, call_off, arg_idx - 1)
                                    if dedup in seen_out:
                                        continue
                                    seen_out.add(dedup)
                                    chains.append({
                                        "function": _func_brief(caller),
                                        "source": sname,
                                        "source_at": f"0x{soff:x}",
                                        "sink": sink_name,
                                        "sink_at": f"0x{call_off:x}",
                                        "arg": arg_idx - 1,
                                        "via": "out_buffer",
                                    })
                                # (c) interprocedural: the sink arg derives from a
                                # parameter — follow it up the call graph.
                                if interprocedural and param_idxs:
                                    for pidx in param_idxs:
                                        for r in self._interproc_taint(
                                            program, ip_iface, ip_state, caller,
                                            pidx, ip_depth, sources, max_steps, timeout,
                                        ):
                                            dk = (r["source"], r.get("source_at"),
                                                  call_off, arg_idx - 1, r["via"])
                                            if dk in seen_ip:
                                                continue
                                            seen_ip.add(dk)
                                            chains.append({
                                                "function": _func_brief(caller),
                                                "source": r["source"],
                                                "source_at": r.get("source_at"),
                                                "sink": sink_name,
                                                "sink_at": f"0x{call_off:x}",
                                                "arg": arg_idx - 1,
                                                "via": r["via"],
                                                "interprocedural": True,
                                                "ip_depth": len(r["frames"]),
                                                "path": [f"{caller.getName()}@0x{call_off:x}"]
                                                + r["frames"],
                                            })
                except OperationFailure:
                    # A decompile failure on one function must not abort the scan.
                    continue

        sink_callsite_count = sum(len(info["sites"]) for info in sink_sites.values())
        if interprocedural:
            note = (
                "interprocedural: sink arg -> source return_value/out_buffer in "
                "this function, OR (following a parameter up to ip_depth frames) "
                "a source in an ancestor frame. Bounded by the decompiler's "
                "arg/param model, so missed signatures under-report rather than "
                "fabricate; 0 chains is not an all-clear."
            )
        else:
            note = (
                "intraprocedural: sink arg -> source-call return_value OR a source "
                "out_buffer (read/recv/fgets/getline/..) written before the sink, "
                "within one function; cross-function propagation is NOT modeled "
                "(pass interprocedural=true), so 0 chains is not an all-clear."
            )
        if scope_fn and sink_callsite_count == 0:
            note = (
                f"function {scope_fn!r} contains no calls to any configured sink "
                f"({len(sinks)} sinks checked) — nothing to scan. " + note
            )
        # JSON output is key-sorted, so chain_count/chains already lead; the
        # signal-burying problem is the *size* of the sources/sinks echo. Render
        # them as compact single-line strings (one line each, not ~20-line
        # arrays) so they no longer dominate a `| tail`.
        result = {
            "chain_count": len(chains),
            "chains": chains,
            "scanned_functions": scanned,
            "sink_callsite_count": sink_callsite_count,
            "note": note,
            "source_count": len(sources),
            "sink_count": len(sinks),
            "sources_used": ", ".join(sorted(sources)),
            "sinks_used": ", ".join(sorted(sinks)),
        }
        if interprocedural:
            result["interprocedural"] = True
            result["ip_depth"] = ip_depth
        return result

    def _resolve_slice_start(
        self, high: Any, program: Any, at: Any, arg: Any, var_name: Any
    ) -> tuple[Any, dict[str, Any]]:
        """Resolve the varnode a backward slice starts from: either a named
        variable's representative, or the Nth argument of a call at an address."""
        if var_name:
            sym = self._find_high_symbol(high, str(var_name))
            if sym is None:
                avail = self._available_var_names(high)
                raise OperationFailure(
                    "not_found",
                    f"no variable named {var_name!r}; available: {', '.join(avail[:40])}",
                )
            hv = sym.getHighVariable()
            if hv is None:
                raise OperationFailure(
                    "not_found", f"variable {var_name!r} has no SSA high variable"
                )
            return hv.getRepresentative(), {"kind": "variable", "variable": str(var_name)}

        if at is not None:
            target_off = _parse_address(program, at)
            chosen = self._find_call_op(high, target_off)
            if chosen is None:
                raise OperationFailure("not_found", f"no call p-code op at 0x{target_off:x}")
            inputs = list(chosen.getInputs())
            arg_idx = int(arg) if arg is not None else 0
            slot = arg_idx + 1  # input[0] is the call target; args start at 1
            if slot < 1 or slot >= len(inputs):
                raise OperationFailure(
                    "bad_request",
                    f"arg index {arg_idx} out of range (call at 0x{target_off:x} "
                    f"has {len(inputs) - 1} args)",
                )
            return inputs[slot], {
                "kind": "call_arg",
                "address": f"0x{target_off:x}",
                "arg": arg_idx,
            }

        raise OperationFailure(
            "bad_request", "taint_backward requires either 'variable' or 'address'"
        )

    def _op_taint_backward(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Backward taint / slice: walk a sink argument (or a variable) back
        through SSA def-use chains to its origins (parameters, constants, loads,
        call results). Honest frontier-leaf classification; bounded by max_steps."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier")
        if identifier is None:
            raise OperationFailure("bad_request", "taint_backward requires 'identifier'")
        fn = _resolve_function(program, str(identifier))

        interprocedural = bool(params.get("interprocedural"))
        ip_depth = int(params.get("ip_depth", 3))
        max_steps = int(params.get("max_steps", 400))
        timeout = int(params.get("timeout", 60))

        with self._high_function(program, fn, timeout) as high:
            start, start_desc = self._resolve_slice_start(
                high, program, params.get("address"), params.get("arg"),
                params.get("variable"),
            )
            slice_ops, origins, truncated = _backward_slice(start, program, max_steps)
            result: dict[str, Any] = {
                "function": _func_brief(fn),
                "start": start_desc,
                "slice_len": len(slice_ops),
                "slice": slice_ops,
                "origin_count": len(origins),
                "origins": origins,
                "truncated": truncated,
            }

        # Interprocedural: where the slice bottomed out at a parameter of `fn`,
        # continue it in `fn`'s callers (the actual arg they pass), collecting
        # origins in ancestor frames with the call path.
        if interprocedural:
            param_idxs = {
                int(o["param_index"]) for o in origins
                if o.get("kind") == "parameter" and o.get("param_index") is not None
            }
            ip_origins: list[dict[str, Any]] = []
            if param_idxs:
                ip_state = {"cache": {}, "decompiles": 0, "cap": 400}
                with self._decompiler(program) as ip_iface:
                    for pidx in param_idxs:
                        ip_origins.extend(self._interproc_backward(
                            program, ip_iface, ip_state, fn, pidx,
                            ip_depth, max_steps, timeout,
                        ))
            result["interprocedural"] = True
            result["ip_depth"] = ip_depth
            result["interprocedural_origins"] = ip_origins
            result["interprocedural_origin_count"] = len(ip_origins)
        return result

    def _callgraph_walk(self, program: Any, root_fn: Any, depth: int, mode: str) -> list[dict[str, Any]]:
        """BFS the call graph from *root_fn* up to *depth* levels. mode is
        'callees' (outgoing) or 'callers' (incoming). Dedups by function."""
        fm = program.getFunctionManager()
        space = program.getAddressFactory().getDefaultAddressSpace()
        visited = {int(root_fn.getEntryPoint().getOffset())}
        frontier = [root_fn]
        nodes: list[dict[str, Any]] = []
        for level in range(1, depth + 1):
            next_frontier: list[Any] = []
            for fn in frontier:
                neighbors, _ = (
                    _direct_callees(program, fn) if mode == "callees"
                    else _direct_callers(program, fn)
                )
                for key, info in neighbors.items():
                    if key in visited:
                        continue
                    visited.add(key)
                    node = dict(info)
                    node["level"] = level
                    node["via"] = f"0x{int(fn.getEntryPoint().getOffset()):x}"
                    nodes.append(node)
                    nf = fm.getFunctionAt(space.getAddress(key))
                    if nf is not None and not nf.isExternal():
                        next_frontier.append(nf)
            frontier = next_frontier
            if not frontier:
                break
        nodes.sort(key=lambda n: (n["level"], int(n["address"], 16)))
        return nodes

    def _op_dataflow_callgraph(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        """Resolved call graph around a function: direct callees/callers, BFS to
        --depth. Indirect call targets are NOT resolved yet (needs value-set);
        their count is reported as `indirect_callsites` for honesty."""
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier")
        if identifier is None:
            raise OperationFailure("bad_request", "dataflow_callgraph requires 'identifier'")
        direction = str(params.get("direction", "both")).lower()
        if direction not in ("callees", "callers", "both"):
            raise OperationFailure(
                "bad_request", f"unknown direction: {direction!r} (use callees|callers|both)"
            )
        depth = int(params.get("depth", 1))
        if depth < 1 or depth > 5:
            raise OperationFailure("bad_request", "depth must be in 1..5")
        fn = _resolve_function(program, str(identifier))

        result: dict[str, Any] = {"function": _func_brief(fn), "depth": depth}
        if direction in ("callees", "both"):
            _, indirect = _direct_callees(program, fn)
            result["callees"] = self._callgraph_walk(program, fn, depth, "callees")
            result["indirect_callsites"] = indirect
        if direction in ("callers", "both"):
            result["callers"] = self._callgraph_walk(program, fn, depth, "callers")
        return result

    def _op_bundle_function(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        identifier = params.get("identifier")
        if identifier is None:
            raise OperationFailure("bad_request", "bundle_function requires 'identifier'")
        fn = _resolve_function(program, str(identifier))

        iface = DecompInterface()
        iface.setOptions(DecompileOptions())
        iface.openProgram(program)
        decompiled = None
        try:
            results = iface.decompileFunction(fn, 60, TaskMonitor.DUMMY)
            if results.decompileCompleted():
                decompiled = str(results.getDecompiledFunction().getC())
        finally:
            with contextlib.suppress(Exception):
                iface.dispose()

        listing = program.getListing()
        disasm_lines = []
        for ins in listing.getInstructions(fn.getBody(), True):
            disasm_lines.append(
                f"{int(ins.getAddress().getOffset()):08x}  {ins}"
            )

        rm = program.getReferenceManager()
        incoming = []
        for ref in rm.getReferencesTo(fn.getEntryPoint()):
            from_addr = ref.getFromAddress()
            caller = program.getFunctionManager().getFunctionContaining(from_addr)
            incoming.append(
                {
                    "address": f"0x{int(from_addr.getOffset()):x}",
                    "function": str(caller.getName()) if caller is not None else None,
                    "ref_type": str(ref.getReferenceType()),
                }
            )

        parameters = []
        for p in fn.getParameters():
            parameters.append(
                {
                    "name": str(p.getName()),
                    "type": str(p.getDataType().getName()),
                    "storage": _storage_str(p),
                }
            )
        locals_ = []
        for lv in fn.getLocalVariables():
            locals_.append(
                {
                    "name": str(lv.getName()),
                    "type": str(lv.getDataType().getName()),
                    "storage": _storage_str(lv),
                }
            )

        return {
            "function": _func_brief(fn),
            "prototype": str(fn.getPrototypeString(True, True)),
            "calling_convention": (
                str(fn.getCallingConventionName()) if fn.getCallingConventionName() else None
            ),
            "decompiled": decompiled,
            "disasm": "\n".join(disasm_lines),
            "parameters": parameters,
            "locals": locals_,
            "incoming_refs": incoming,
        }

    # ---- refresh + save -------------------------------------------------

    def _op_refresh(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        import pyghidra
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program

        messages: list[str] = []

        def _listener(manager, _cancelled):
            try:
                messages.append(str(manager.getMessageLog()))
            except Exception:
                pass

        with pyghidra.transaction(program, "ghx:refresh"):
            mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            mgr.reAnalyzeAll(None)
            mgr.addListener(_listener)
            mgr.startAnalysis(pyghidra.task_monitor(), True)

        return {
            "refreshed": True,
            "program_id": handle.program_id,
            "message_log": "".join(messages),
        }

    def _op_save_database(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        import pyghidra

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program

        # `save <path>`: export a Ghidra Zip File (.gzf) — the analyzed-program
        # archive, ghx's analog of bn's `save <path>.bndb`.
        out_path = params.get("path")
        if out_path:
            from ghidra.app.util.exporter import GzfExporter  # type: ignore
            from java.io import File  # type: ignore

            out = Path(str(out_path)).expanduser()
            if out.suffix.lower() != ".gzf":
                out = out.parent / (out.name + ".gzf")
            out.parent.mkdir(parents=True, exist_ok=True)
            exporter = GzfExporter()
            ok = exporter.export(File(str(out)), program, None, pyghidra.task_monitor())
            if not ok:
                detail = ""
                with contextlib.suppress(Exception):
                    detail = str(exporter.getMessageLog())
                raise OperationFailure("export_failed", f"gzf export failed: {detail}".strip())
            return {
                "saved": True,
                "exported": True,
                "format": "gzf",
                "program_id": handle.program_id,
                "path": str(out),
            }

        df = program.getDomainFile()
        if df is None:
            raise OperationFailure(
                "cannot_save",
                "program has no DomainFile (not attached to a project)",
            )
        if not df.canSave():
            raise OperationFailure(
                "cannot_save",
                f"DomainFile at {df.getPathname()} is not saveable",
            )
        try:
            df.save(pyghidra.task_monitor())
        except Exception as exc:
            raise OperationFailure(
                "save_failed", f"save failed: {exc}",
            ) from exc
        return {
            "saved": True,
            "program_id": handle.program_id,
            "path": str(df.getPathname()),
        }

    # ---- field_xrefs ----------------------------------------------------

    def _op_field_xrefs(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
        from ghidra.program.model.data import Structure  # type: ignore
        from ghidra.program.model.pcode import PcodeOp  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program

        type_name = params.get("type_name")
        field_arg = params.get("field")
        offset_arg = params.get("offset")
        in_function = params.get("in_function")
        timeout = int(params.get("timeout", 30))
        if not type_name or (field_arg is None and offset_arg is None):
            raise OperationFailure(
                "bad_request",
                "field_xrefs requires 'type_name' and 'field' or 'offset'",
            )

        dtm = program.getDataTypeManager()
        struct = _find_data_type(dtm, str(type_name))
        if struct is None or not isinstance(struct, Structure):
            raise OperationFailure("not_found", f"struct not found: {type_name!r}")

        comp = None
        if offset_arg is not None:
            off = int(offset_arg, 0) if isinstance(offset_arg, str) else int(offset_arg)
            comp = struct.getComponentContaining(off)
        else:
            for c in struct.getDefinedComponents():
                if c.getFieldName() and str(c.getFieldName()) == str(field_arg):
                    comp = c
                    break
        if comp is None:
            raise OperationFailure("not_found", f"field not found in {type_name}")

        field_offset = int(comp.getOffset())
        field_name = str(comp.getFieldName()) if comp.getFieldName() else None
        field_type = str(comp.getDataType().getName())
        struct_name = str(struct.getName())

        # Narrow to a single function when requested — speeds things up
        # dramatically for targeted auditing.
        fm = program.getFunctionManager()
        listing = program.getListing()
        if in_function:
            fn = _resolve_function(program, str(in_function))
            functions = [fn]
        else:
            functions = [
                f
                for f in fm.getFunctions(True)
                if not (f.isThunk() or f.isExternal())
            ]

        iface = DecompInterface()
        iface.setOptions(DecompileOptions())
        iface.openProgram(program)

        code_refs: list[dict[str, Any]] = []
        scanned = 0
        try:
            for fn in functions:
                scanned += 1
                try:
                    results = iface.decompileFunction(fn, timeout, TaskMonitor.DUMMY)
                except Exception:
                    continue
                if results is None or not results.decompileCompleted():
                    continue
                high = results.getHighFunction()
                if high is None:
                    continue

                it = high.getPcodeOps()
                while it.hasNext():
                    op = it.next()
                    opcode = op.getOpcode()
                    if opcode not in (PcodeOp.PTRSUB, PcodeOp.PTRADD):
                        continue
                    # PTRSUB / PTRADD take (base_pointer, constant_offset).
                    base_vn = op.getInput(0)
                    off_vn = op.getInput(1)
                    if base_vn is None or off_vn is None:
                        continue
                    if not off_vn.isConstant():
                        continue
                    off_val = int(off_vn.getOffset())
                    if off_val != field_offset:
                        continue
                    if not _varnode_references_struct(base_vn, struct_name):
                        continue
                    seq = op.getSeqnum()
                    target_addr = seq.getTarget() if seq is not None else None
                    if target_addr is None:
                        continue
                    site_addr = int(target_addr.getOffset())
                    ins = listing.getInstructionAt(target_addr)
                    code_refs.append(
                        {
                            "address": f"0x{site_addr:x}",
                            "function": str(fn.getName()),
                            "opcode": "PTRSUB" if opcode == PcodeOp.PTRSUB else "PTRADD",
                            "disasm": str(ins) if ins is not None else None,
                        }
                    )
        finally:
            with contextlib.suppress(Exception):
                iface.dispose()

        code_refs.sort(key=lambda row: (row["function"], int(row["address"], 16)))

        return {
            "field": {
                "type_name": struct_name,
                "field_name": field_name,
                "field_type": field_type,
                "offset": field_offset,
            },
            "code_refs": code_refs,
            "scanned_functions": scanned,
        }

    # ---- batch apply ----------------------------------------------------

    def _op_batch_apply(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        program = handle.program
        operations = params.get("operations")
        if not operations or not isinstance(operations, list):
            raise OperationFailure("bad_request", "batch_apply requires 'operations': list")
        preview = bool(params.get("preview", False))

        results: list[dict[str, Any]] = []
        failure_index: int | None = None
        tx = program.startTransaction("ghx:batch_apply")
        try:
            for idx, op_spec in enumerate(operations):
                if not isinstance(op_spec, dict):
                    failure_index = idx
                    results.append({"op": None, "status": "bad_op", "error": "op must be dict"})
                    break
                op_name = op_spec.get("op")
                op_params = op_spec.get("params") or {}
                try:
                    # Re-dispatch inside the open transaction without starting
                    # a new one: call the relevant single-op helper directly.
                    single = self._run_single_inner(op_name, op_params, target)
                    results.append({"op": op_name, "status": "ok", "result": single})
                except OperationFailure as exc:
                    failure_index = idx
                    results.append(
                        {
                            "op": op_name,
                            "status": exc.status,
                            "error": exc.message,
                        }
                    )
                    break
        finally:
            commit = failure_index is None and not preview
            program.endTransaction(tx, commit)

        # Inner ops each open their own nested transaction, so their native
        # "committed"/"preview" fields describe the nested state, not the
        # batch outcome. Rewrite them so nested readers see the batch's
        # final disposition.
        for row in results:
            inner = row.get("result")
            if isinstance(inner, dict):
                inner["committed"] = commit
                inner["preview"] = preview

        return {
            "committed": commit,
            "preview": preview,
            "failed_index": failure_index,
            "results": results,
        }

    def _run_single_inner(
        self, op_name: str | None, params: dict[str, Any], target: str | None
    ) -> Any:
        """Invoke a single op *without* opening its own transaction.

        Used by ``batch_apply`` so all ops share one transaction.  The op
        handlers themselves call ``_run_mutation`` which opens nested
        transactions — Ghidra allows nesting, so this is safe, but we
        short-circuit the preview/verify indirection by only supporting a
        curated whitelist.  Non-mutating ops are invoked directly.
        """
        if op_name == "rename_symbol":
            return self._op_rename_symbol(params, target)
        if op_name == "set_comment":
            return self._op_set_comment(params, target)
        if op_name == "delete_comment":
            return self._op_delete_comment(params, target)
        if op_name == "set_prototype":
            return self._op_set_prototype(params, target)
        if op_name == "local_rename":
            return self._op_local_rename(params, target)
        if op_name == "local_retype":
            return self._op_local_retype(params, target)
        if op_name == "struct_field_set":
            return self._op_struct_field_set(params, target)
        if op_name == "struct_field_rename":
            return self._op_struct_field_rename(params, target)
        if op_name == "struct_field_delete":
            return self._op_struct_field_delete(params, target)
        if op_name == "types_declare":
            return self._op_types_declare(params, target)
        raise OperationFailure("bad_op", f"op not allowed in batch: {op_name!r}")

    # ---- py_exec --------------------------------------------------------

    def _op_py_exec(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        import contextlib as _ctx
        import io as _io
        import jpype

        code = params.get("code")
        if not code:
            raise OperationFailure("bad_request", "py_exec requires 'code'")
        mutate = bool(params.get("mutate", False))

        handle = self.targets.resolve(params.get("target") or target, required=False)
        program = handle.program if handle else None

        scope = _build_py_exec_scope(self.project, program)
        scope["_ghx_mutate"] = mutate

        stdout_buf = _io.StringIO()
        stderr_buf = _io.StringIO()
        result_value: Any = None
        warnings_: list[str] = []

        def _run_block() -> None:
            nonlocal result_value
            with _ctx.redirect_stdout(stdout_buf), _ctx.redirect_stderr(stderr_buf):
                exec(compile(code, "<ghx.py_exec>", "exec"), scope, scope)
            result_value = scope.get("result")

        try:
            if mutate and program is not None:
                import pyghidra

                with pyghidra.transaction(program, "ghx:py_exec"):
                    _run_block()
            else:
                _run_block()
        except jpype.JException as jexc:  # type: ignore[attr-defined]
            return {
                "stdout": stdout_buf.getvalue(),
                "stderr": stderr_buf.getvalue(),
                "ok": False,
                "error": f"Java exception: {jexc.toString()}",
                "result": None,
            }
        except Exception as exc:
            return {
                "stdout": stdout_buf.getvalue(),
                "stderr": stderr_buf.getvalue(),
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "result": None,
            }

        return {
            "stdout": stdout_buf.getvalue(),
            "stderr": stderr_buf.getvalue(),
            "ok": True,
            "result": _normalize_py_result(result_value),
            "mutate": mutate,
            "warnings": warnings_,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_FRAME_REGISTER_NAMES = {
    # AArch64 / ARM
    "sp", "fp", "lr", "pc", "xzr", "wzr", "x29", "x30", "w29", "w30",
    # x86 / x86-64
    "rbp", "rsp", "rip", "ebp", "esp", "eip",
}


def _decoded_string_value(rep: str) -> str:
    """Strip Ghidra's C-literal decoration from a string representation.

    `getDefaultValueRepresentation()` yields things like ``"libc.so.6"`` or
    ``u8"libc.so.6"`` (encoding prefix + surrounding quotes). For querying we
    want the bare content so that substring filters and anchored regexes match
    the actual string, not the decoration.
    """
    s = rep
    for pfx in ("u8", "U", "L", "u"):
        if s.startswith(pfx + '"'):
            s = s[len(pfx):]
            break
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s


def _surrounding_instructions(listing: Any, base_ins: Any, n: int) -> list[dict[str, Any]]:
    """Return up to |n| instructions before (n<0) or after (n>0) *base_ins*."""
    if n == 0:
        return []
    rows: list[dict[str, Any]] = []
    cur = base_ins
    for _ in range(abs(n)):
        try:
            cur = cur.getPrevious() if n < 0 else cur.getNext()
        except Exception:
            cur = None
        if cur is None:
            break
        try:
            off = int(cur.getAddress().getOffset())
            rows.append({
                "address": f"0x{off:x}",
                "disasm": str(cur),
            })
        except Exception:
            break
    if n < 0:
        rows.reverse()
    return rows


def _decompile_with_addresses(func: Any, results: Any) -> str:
    """Render decompiler output with address prefixes per line.

    Walks the PrettyPrinter's ClangLine list and prefixes each line with the
    minimum address observed across its tokens. Lines with no address (the
    synthetic prototype/signature lines) render as 8 spaces.
    """
    try:
        from ghidra.app.decompiler import PrettyPrinter  # type: ignore

        printer = PrettyPrinter(func, results.getCCodeMarkup(), None)
        lines = printer.getLines()
    except Exception:
        return str(results.getDecompiledFunction().getC())

    out: list[str] = []
    for line in lines:
        min_off: int | None = None
        try:
            tokens = list(line.getAllTokens())
        except Exception:
            tokens = []
        for tok in tokens:
            try:
                a = tok.getMinAddress()
            except Exception:
                a = None
            if a is None:
                continue
            off = int(a.getOffset())
            if min_off is None or off < min_off:
                min_off = off
        prefix = f"{min_off:08x}  " if min_off is not None else " " * 10
        try:
            text = PrettyPrinter.getText(line)
        except Exception:
            text = "".join(str(t) for t in tokens)
        try:
            indent = str(line.getIndentString())
        except Exception:
            indent = ""
        out.append(f"{prefix}{indent}{text}")
    return "\n".join(out) + "\n"


def _read_ghidra_version(install_dir: Path) -> str:
    try:
        from pyghidra.version import ApplicationInfo

        props = Path(install_dir) / "Ghidra" / "application.properties"
        info = ApplicationInfo.from_file(props)
        return str(info.version)
    except Exception:
        return "?"


def _resolve_functions(program: Any, identifier: str) -> list[Any]:
    """All functions matching an identifier. A single hex address yields one
    function; a name may match several (a .plt thunk *and* the EXTERNAL symbol,
    or genuinely overloaded names). Callers that want to union across thunks
    (e.g. ``callsites``) use this instead of ``_resolve_function``."""
    fm = program.getFunctionManager()
    ident = identifier.strip()
    if ident.lower().startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in ident):
        with contextlib.suppress(Exception):
            addr = program.getAddressFactory().getAddress(ident)
            if addr is not None:
                fn = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
                if fn is not None:
                    return [fn]
    return [
        fn for fn in fm.getFunctions(True)
        if str(fn.getName()) == ident or str(fn.getName(True)) == ident
    ]


def _resolve_function(program: Any, identifier: str) -> Any:
    """Resolve a function by hex address or symbol name."""
    fm = program.getFunctionManager()
    ident = identifier.strip()

    # Try hex address first.
    if ident.lower().startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in ident):
        with contextlib.suppress(Exception):
            addr = program.getAddressFactory().getAddress(ident)
            if addr is not None:
                fn = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
                if fn is not None:
                    return fn

    # Fall back to symbol-table lookup by name.
    matches = []
    for fn in fm.getFunctions(True):
        if str(fn.getName()) == ident or str(fn.getName(True)) == ident:
            matches.append(fn)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        addrs = ", ".join(f"0x{int(f.getEntryPoint().getOffset()):x}" for f in matches)
        raise OperationFailure(
            "ambiguous_function",
            f"identifier '{identifier}' matches {len(matches)} functions: {addrs}",
        )
    raise OperationFailure("not_found", f"no function matches identifier: {identifier!r}")


def _parse_address(program: Any, value: Any) -> int:
    """Resolve a Python string/int into an integer offset (default address space)."""
    if isinstance(value, int):
        return int(value)
    s = str(value).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if all(c in "0123456789abcdefABCDEF" for c in s):
        return int(s, 16)
    addr = program.getAddressFactory().getAddress(s)
    if addr is None:
        raise OperationFailure("bad_address", f"could not parse address: {value!r}")
    return int(addr.getOffset())


# Ghidra's synthetic memory block holding external-linkage trampolines — the
# size-1 `is_thunk` stubs (memcpy, strtok, …) the ELF/PE loader manufactures so
# the disassembler has a branch target for imports. bn does not model these as
# functions, so `function list/search` hide them by default (parity).
_EXTERNAL_BLOCK_NAME = "EXTERNAL"


def _in_external_block(program: Any, entry: Any) -> bool:
    """True if `entry` lies in Ghidra's synthetic EXTERNAL block."""
    block = program.getMemory().getBlock(entry)
    return block is not None and str(block.getName()) == _EXTERNAL_BLOCK_NAME


def _func_brief(fn: Any) -> dict[str, Any]:
    entry = fn.getEntryPoint()
    return {
        "name": str(fn.getName()),
        "address": f"0x{int(entry.getOffset()):x}",
        "size": int(fn.getBody().getNumAddresses()),
        "is_thunk": bool(fn.isThunk()),
        "is_external": bool(fn.isExternal()),
    }


def _sort_func_rows(items: list[dict[str, Any]], sort: str) -> list[dict[str, Any]]:
    """Sort function-brief rows by 'address' (asc), 'name' (asc), or 'size'
    (desc — biggest first, the useful order for triage). Ties break on address."""
    if sort == "name":
        items.sort(key=lambda r: (r["name"].lower(), int(r["address"], 16)))
    elif sort == "size":
        items.sort(key=lambda r: (-int(r["size"]), int(r["address"], 16)))
    else:
        items.sort(key=lambda r: int(r["address"], 16))
    return items


def _storage_str(var: Any) -> str | None:
    try:
        storage = var.getVariableStorage()
        if storage is None:
            return None
        return str(storage)
    except Exception:
        return None


def _storage_id(storage: Any) -> str | None:
    """A stable handle for a variable's storage, dropping the ``:size`` suffix
    so it survives both renames and retypes (e.g. ``RDI``, ``Stack[-0x10]``)."""
    try:
        if storage is None:
            return None
        s = str(storage)
    except Exception:
        return None
    if not s:
        return None
    return s.rsplit(":", 1)[0] if ":" in s else s


def _var_id(var: Any) -> str | None:
    """Stable id for a stored Variable (parameter/local)."""
    try:
        return _storage_id(var.getVariableStorage())
    except Exception:
        return None


def _high_sym_storage(high_sym: Any) -> Any:
    """VariableStorage of a HighSymbol, or None."""
    try:
        return high_sym.getStorage()
    except Exception:
        return None


def _block_name_for(program: Any, off: int) -> str | None:
    """Name of the memory block (section/segment) containing an offset."""
    try:
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
        block = program.getMemory().getBlock(addr)
        return str(block.getName()) if block is not None else None
    except Exception:
        return None


def _primary_symbol_name(program: Any, off: int) -> str | None:
    """Primary symbol name at an offset, if any."""
    try:
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
        sym = program.getSymbolTable().getPrimarySymbol(addr)
        return str(sym.getName()) if sym is not None else None
    except Exception:
        return None


def _read_pointer(program: Any, off: int, size: int) -> int | None:
    """Read a little/big-endian pointer of *size* bytes at *off*. None if unmapped."""
    base = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)
    mem = program.getMemory()
    raw: list[int] = []
    for i in range(size):
        try:
            raw.append(int(mem.getByte(base.add(i))) & 0xFF)
        except Exception:
            return None
    big = bool(program.getLanguage().isBigEndian())
    order = raw if big else list(reversed(raw))
    value = 0
    for byte in order:
        value = (value << 8) | byte
    return value


def _resolve_pointer_target(program: Any, value: int) -> dict[str, Any]:
    """Classify what a pointer value points at: function, symbol, data, or unmapped."""
    out: dict[str, Any] = {"value": f"0x{value:x}"}
    try:
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(value)
    except Exception:
        out["kind"] = "unmapped"
        return out
    fm = program.getFunctionManager()
    fn = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
    if fn is not None:
        out["kind"] = "function"
        out["target"] = str(fn.getName())
        out["is_external"] = bool(fn.isExternal())
        return out
    sym = program.getSymbolTable().getPrimarySymbol(addr)
    if sym is not None:
        out["kind"] = "symbol"
        out["target"] = str(sym.getName())
        return out
    block = program.getMemory().getBlock(addr)
    if block is not None:
        out["kind"] = "data"
        out["section"] = str(block.getName())
        return out
    out["kind"] = "unmapped"
    return out


def _varnode_desc(vn: Any, program: Any = None) -> dict[str, Any] | None:
    """Compact JSON descriptor for a p-code Varnode (input or output)."""
    if vn is None:
        return None
    size = int(vn.getSize())
    d: dict[str, Any] = {"size": size, "offset": int(vn.getOffset())}
    try:
        d["space"] = str(vn.getAddress().getAddressSpace().getName())
    except Exception:
        pass
    if vn.isConstant():
        d["kind"] = "const"
        mask = (1 << (8 * size)) - 1 if size else None
        raw = int(vn.getOffset())
        d["value"] = f"0x{(raw & mask) if mask else raw:x}"
    elif vn.isRegister():
        d["kind"] = "register"
        if program is not None:
            try:
                reg = program.getRegister(vn.getAddress(), size)
                if reg is not None:
                    d["register"] = str(reg.getName())
            except Exception:
                pass
    elif vn.isUnique():
        d["kind"] = "unique"
    elif vn.isAddress():
        d["kind"] = "ram"
        if program is not None:
            try:
                sym = program.getSymbolTable().getPrimarySymbol(vn.getAddress())
                if sym is not None:
                    d["symbol"] = str(sym.getName())
            except Exception:
                pass
    else:
        d["kind"] = "other"
    # High-variable name, if present (high p-code form).
    try:
        hv = vn.getHigh()
        if hv is not None:
            nm = hv.getName()
            if nm and str(nm) not in ("UNNAMED", "null"):
                d["var"] = str(nm)
    except Exception:
        pass
    return d


def _pcode_desc(op: Any, addr: int, index: int, program: Any = None) -> dict[str, Any]:
    """Compact JSON descriptor for a single PcodeOp."""
    inputs: list[Any] = []
    try:
        for vn in op.getInputs():
            inputs.append(_varnode_desc(vn, program))
    except Exception:
        pass
    try:
        out = _varnode_desc(op.getOutput(), program)
    except Exception:
        out = None
    try:
        mnem = str(op.getMnemonic())
    except Exception:
        mnem = str(op)
    try:
        opcode = int(op.getOpcode())
    except Exception:
        opcode = None
    return {
        "index": int(index),
        "address": f"0x{int(addr):x}",
        "op": mnem,
        "opcode": opcode,
        "output": out,
        "inputs": inputs,
    }


def _high_pcode_desc(op: Any, program: Any = None) -> dict[str, Any] | None:
    """Describe a high (SSA) PcodeOp, deriving its address from the seqnum."""
    if op is None:
        return None
    try:
        tgt = op.getSeqnum().getTarget()
        off = int(tgt.getOffset()) if tgt is not None else 0
    except Exception:
        off = 0
    return _pcode_desc(op, off, 0, program)


def _signed_hex(v: int) -> str:
    """Render a (possibly 64-bit-unsigned) offset as a signed hex literal."""
    if v >= (1 << 63):
        v -= 1 << 64
    return f"-0x{-v:x}" if v < 0 else f"0x{v:x}"


def _fmt_vn(d: dict[str, Any] | None) -> str:
    """Render a varnode descriptor as a readable token, preferring the SSA
    HighVariable name, then a resolved register/symbol name, over the raw
    (space, offset, size) tuple that Ghidra's PcodeOp.toString emits."""
    if d is None:
        return "---"
    kind = d.get("kind")
    if kind == "const":
        return f"#{d.get('value')}"
    if d.get("var"):
        return str(d["var"])
    if kind == "register":
        return str(d.get("register") or f"reg+{d.get('offset')}")
    if kind == "unique":
        off = d.get("offset")
        return f"u{off:x}" if isinstance(off, int) else f"u:{off}"
    if kind == "ram":
        if d.get("symbol"):
            return str(d["symbol"])
        off = d.get("offset")
        return f"0x{off:x}" if isinstance(off, int) else f"ram:{off}"
    off = d.get("offset")
    space = d.get("space", "?")
    if isinstance(off, int):
        return f"{space}[{_signed_hex(off)}]"
    return f"{space}:{off}"


def _format_pcode_line(desc: dict[str, Any]) -> str:
    """Format a structured p-code descriptor as ``out = OP a, b`` with named
    varnodes — the readable analogue of Ghidra's raw PcodeOp.toString()."""
    out = desc.get("output")
    ins = ", ".join(_fmt_vn(v) for v in (desc.get("inputs") or []))
    lhs = f"{_fmt_vn(out)} = " if out is not None else ""
    body = f"{lhs}{desc.get('op')}"
    return f"{body} {ins}" if ins else body


def _classify_leaf(vn: Any, program: Any) -> dict[str, Any]:
    """Classify a backward-slice frontier leaf (a varnode with no SSA def)."""
    out: dict[str, Any] = {"varnode": _varnode_desc(vn, program)}
    hv = None
    try:
        hv = vn.getHigh()
    except Exception:
        hv = None
    if hv is not None:
        try:
            sym = hv.getSymbol()
            if sym is not None:
                out["name"] = str(sym.getName())
                if sym.isParameter():
                    out["kind"] = "parameter"
                    try:
                        out["param_index"] = int(sym.getCategoryIndex())
                    except Exception:
                        pass
                    return out
                if sym.isGlobal():
                    out["kind"] = "global"
                    return out
        except Exception:
            pass
    # No def and not a tracked symbol: an entry-state register/stack slot.
    out["kind"] = "input"
    return out


def _backward_slice(
    start: Any, program: Any, max_steps: int = 400
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Walk SSA def-use chains backward from *start*, collecting the slice ops
    and classifying frontier leaves (origins). Honest about truncation."""
    worklist = [start]
    seen: set[str] = set()
    slice_ops: list[dict[str, Any]] = []
    origins: list[dict[str, Any]] = []
    steps = 0
    while worklist and steps < max_steps:
        vn = worklist.pop()
        key = str(vn)
        if key in seen:
            continue
        seen.add(key)
        steps += 1

        if vn.isConstant():
            origins.append({"kind": "const", "value": f"0x{int(vn.getOffset()):x}"})
            continue
        defop = vn.getDef()
        if defop is None:
            origins.append(_classify_leaf(vn, program))
            continue

        mnem = str(defop.getMnemonic())
        desc = _high_pcode_desc(defop, program)
        if desc is not None:
            slice_ops.append(desc)
        inputs = list(defop.getInputs())

        if mnem in ("CALL", "CALLIND"):
            callee = None
            if inputs:
                try:
                    callee = _resolve_pointer_target(
                        program, int(inputs[0].getOffset())
                    ).get("target")
                except Exception:
                    callee = None
            origins.append(
                {
                    "kind": "call_result",
                    "address": desc["address"] if desc else None,
                    "callee": callee,
                }
            )
            continue
        if mnem == "LOAD":
            origins.append({"kind": "load", "address": desc["address"] if desc else None})
            # Keep slicing the pointer expression (input[1]) to learn its origin.
            if len(inputs) >= 2 and not inputs[1].isConstant():
                worklist.append(inputs[1])
            continue

        for inp in inputs:
            if inp.isConstant():
                origins.append({"kind": "const", "value": f"0x{int(inp.getOffset()):x}"})
            else:
                worklist.append(inp)

    truncated = steps >= max_steps and bool(worklist)
    # Dedup origins (constants in particular recur).
    deduped: list[dict[str, Any]] = []
    seen_origin: set[str] = set()
    for o in origins:
        k = json.dumps(o, sort_keys=True)
        if k in seen_origin:
            continue
        seen_origin.add(k)
        deduped.append(o)
    return slice_ops, deduped, truncated


_DEFAULT_TAINT_SOURCES = (
    "recv", "recvfrom", "read", "fread", "fgets", "gets", "getenv",
    "scanf", "fscanf", "sscanf", "readlink", "getline",
)
_DEFAULT_TAINT_SINKS = (
    "strcpy", "strcat", "sprintf", "vsprintf", "memcpy", "memmove", "gets",
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp",
    "strncpy", "strncat", "snprintf",
)


def _normalize_fn_name(name: Any) -> str:
    """Strip @plt/.plt suffixes and leading underscores so import/thunk names
    (`strcpy`, `_strcpy`, `strcpy@plt`) all match a configured source/sink."""
    n = str(name)
    for suffix in ("@plt", ".plt"):
        if n.endswith(suffix):
            n = n[: -len(suffix)]
    return n.lstrip("_")


# 0-based index of the out-buffer argument each source WRITES. The written
# buffer (not the return value) is the real taint origin for these. getline/
# getdelim take a `char **` in arg0; `_buffer_keys` resolves `&line` to the
# `line` variable, so the double indirection matches uniformly with direct
# pointers. Variadic scanf-family sources are intentionally absent (the buffer
# arg can't be picked statically).
_TAINT_SOURCE_OUTBUF: dict[str, int] = {
    "read": 1, "pread": 1, "recv": 1, "recvfrom": 1, "readlink": 1,
    "fgets": 0, "gets": 0, "fread": 0,
    "getline": 0, "getdelim": 0,
}


def _signed(val: int, size: int) -> int:
    """Interpret an unsigned varnode/const offset as a signed integer."""
    bits = size * 8
    if bits > 0 and val >= (1 << (bits - 1)):
        val -= 1 << bits
    return val


def _callop_callee_name(program: Any, op: Any) -> str | None:
    """Normalized callee name of a CALL/CALLIND high-pcode op, or None. input[0]
    of a direct CALL is the target address varnode."""
    try:
        inputs = op.getInputs()
        if not inputs:
            return None
        ca = inputs[0].getAddress()
        if ca is None:
            return None
        fm = program.getFunctionManager()
        fn = fm.getFunctionAt(ca) or fm.getFunctionContaining(ca)
        return _normalize_fn_name(fn.getName()) if fn is not None else None
    except Exception:
        return None


def _stack_symbol_map(high: Any) -> dict[int, str]:
    """{stack offset -> storage id} for a function's stack-backed symbols, so a
    `&stackvar` PTRSUB(frame, off) can be resolved to the variable living at
    that offset (the getline `&line` -> `line` case)."""
    out: dict[int, str] = {}
    try:
        it = high.getLocalSymbolMap().getSymbols()
    except Exception:
        return out
    while it.hasNext():
        sym = it.next()
        st = _high_sym_storage(sym)
        try:
            if st is not None and st.isStackStorage():
                out[int(st.getStackOffset())] = _storage_id(st)
        except Exception:
            continue
    return out


def _buffer_keys(vn: Any, stack_syms: dict[int, str]) -> set:
    """Identity keys for the memory buffer a varnode denotes, used to match a
    source's out-buffer argument against a sink argument within one function:

      (1) the variable's own storage  — a heap pointer held in a stack slot or
          register, and the value side of a getline double pointer (`line`);
      (2) a `&stackvar` address expression PTRSUB((register,_,_), OFF) — both as
          an address identity (matches `&buf` on both sides for stack arrays)
          and resolved through the stack-symbol map to the variable at OFF.

    Empirically the PTRSUB offset equals the Stack[OFF] storage offset on both
    x86-64 (frame reg 0x20) and AArch64 (0x8), so the resolution is arch-robust.
    """
    keys: set = set()
    if vn is None:
        return keys
    try:
        hv = vn.getHigh()
        sym = hv.getSymbol() if hv is not None else None
        if sym is not None:
            sid = _storage_id(_high_sym_storage(sym))
            if sid:
                keys.add(("stor", sid))
    except Exception:
        pass
    try:
        defop = vn.getDef()
        if defop is not None and str(defop.getMnemonic()) == "PTRSUB":
            ip = list(defop.getInputs())
            if len(ip) == 2 and ip[1].isConstant():
                off = _signed(int(ip[1].getOffset()), ip[1].getSize())
                keys.add(("addr", str(ip[0]), off))
                if off in stack_syms:
                    keys.add(("stor", stack_syms[off]))
    except Exception:
        pass
    return keys


def _buffer_keys_expanded(vn: Any, stack_syms: dict[int, str], depth: int = 3) -> set:
    """`_buffer_keys` plus a shallow walk through copies/casts and pointer+const
    arithmetic, so `buf + off` and renamed copies still match the source buffer.
    Deliberately does NOT cross PTRSUB bases, phi (MULTIEQUAL) merges, or
    non-constant additions — those would over-connect distinct buffers and the
    correctness bar is "no false chains"."""
    keys: set = set()
    seen: set[str] = set()
    work = [(vn, 0)]
    while work:
        v, d = work.pop()
        if v is None:
            continue
        vk = str(v)
        if vk in seen:
            continue
        seen.add(vk)
        keys |= _buffer_keys(v, stack_syms)
        if d >= depth:
            continue
        defop = v.getDef()
        if defop is None:
            continue
        mnem = str(defop.getMnemonic())
        ins = list(defop.getInputs())
        if mnem in ("COPY", "CAST"):
            if ins and not ins[0].isConstant():
                work.append((ins[0], d + 1))
        elif mnem in ("INT_ADD", "PTRADD"):
            nonconst = [i for i in ins if not i.isConstant()]
            if len(nonconst) == 1:
                work.append((nonconst[0], d + 1))
    return keys


def _direct_callees(program: Any, fn: Any) -> tuple[dict[int, dict[str, Any]], int]:
    """Resolved direct callees of *fn* (keyed by entry offset) plus a count of
    call sites whose target did not resolve to a function (indirect/unresolved)."""
    fm = program.getFunctionManager()
    out: dict[int, dict[str, Any]] = {}
    unresolved = 0
    for ins in program.getListing().getInstructions(fn.getBody(), True):
        for ref in ins.getReferencesFrom():
            if not ref.getReferenceType().isCall():
                continue
            callee = fm.getFunctionAt(ref.getToAddress())
            site = f"0x{int(ins.getAddress().getOffset()):x}"
            if callee is None:
                unresolved += 1
                continue
            key = int(callee.getEntryPoint().getOffset())
            node = out.setdefault(
                key,
                {
                    "name": str(callee.getName()),
                    "address": f"0x{key:x}",
                    "is_external": bool(callee.isExternal()),
                    "call_sites": [],
                },
            )
            node["call_sites"].append(site)
    return out, unresolved


def _direct_callers(program: Any, fn: Any) -> tuple[dict[int, dict[str, Any]], int]:
    """Resolved direct callers of *fn* (keyed by entry offset)."""
    fm = program.getFunctionManager()
    rm = program.getReferenceManager()
    out: dict[int, dict[str, Any]] = {}
    unresolved = 0
    for ref in rm.getReferencesTo(fn.getEntryPoint()):
        if not ref.getReferenceType().isCall():
            continue
        from_addr = ref.getFromAddress()
        caller = fm.getFunctionContaining(from_addr)
        site = f"0x{int(from_addr.getOffset()):x}"
        if caller is None:
            unresolved += 1
            continue
        key = int(caller.getEntryPoint().getOffset())
        node = out.setdefault(
            key,
            {
                "name": str(caller.getName()),
                "address": f"0x{key:x}",
                "is_external": bool(caller.isExternal()),
                "call_sites": [],
            },
        )
        node["call_sites"].append(site)
    return out, unresolved


def _resolve_symbol(program: Any, identifier: str) -> tuple[Any, str]:
    """Resolve a symbol by name or hex address, returning (symbol, kind)."""
    ident = identifier.strip()
    st = program.getSymbolTable()
    fm = program.getFunctionManager()

    # Try hex address.
    if ident.lower().startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in ident):
        with contextlib.suppress(Exception):
            addr = program.getAddressFactory().getAddress(ident)
            if addr is not None:
                fn = fm.getFunctionAt(addr)
                if fn is not None:
                    sym = fn.getSymbol()
                    if sym is not None:
                        return sym, "function"
                sym = st.getPrimarySymbol(addr)
                if sym is not None:
                    return sym, _sym_kind(sym)

    # Fall back to name lookup.
    # FunctionManager gives direct access to function symbols.
    matches_fn = []
    for fn in fm.getFunctions(True):
        if str(fn.getName()) == ident:
            matches_fn.append(fn)
    if len(matches_fn) == 1:
        sym = matches_fn[0].getSymbol()
        if sym is not None:
            return sym, "function"

    global_matches = list(st.getGlobalSymbols(ident))
    if len(global_matches) == 1:
        return global_matches[0], _sym_kind(global_matches[0])
    if len(global_matches) > 1:
        raise OperationFailure(
            "ambiguous_symbol",
            f"identifier '{identifier}' matches {len(global_matches)} global symbols",
        )
    if matches_fn:
        raise OperationFailure(
            "ambiguous_function",
            f"identifier '{identifier}' matches {len(matches_fn)} functions",
        )
    raise OperationFailure("not_found", f"no symbol matches identifier: {identifier!r}")


def _sym_kind(sym: Any) -> str:
    try:
        return str(sym.getSymbolType()).lower()
    except Exception:
        return "unknown"


def _comment_type(kind: str) -> int:
    from ghidra.program.model.listing import CodeUnit  # type: ignore

    mapping = {
        "plate": CodeUnit.PLATE_COMMENT,
        "pre": CodeUnit.PRE_COMMENT,
        "post": CodeUnit.POST_COMMENT,
        "eol": CodeUnit.EOL_COMMENT,
        "repeatable": CodeUnit.REPEATABLE_COMMENT,
    }
    if kind not in mapping:
        raise OperationFailure(
            "bad_request",
            f"unknown comment kind: {kind!r} (use plate|pre|post|eol|repeatable)",
        )
    return mapping[kind]


def _run_mutation(
    program: Any,
    *,
    description: str,
    apply,
    verify,
    preview: bool,
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    """Execute a mutation inside a Ghidra transaction with preview/verify semantics.

    - Opens a transaction, calls ``apply()``, runs ``verify()``.
    - If ``preview=True``: always endTransaction(commit=False); returns the
      diff plus a 'verified' flag.
    - Otherwise: commits iff ``apply`` did not raise AND verify says ok.
    """
    tx = program.startTransaction(description)
    committed = False
    applied_ok = True
    apply_error: str | None = None
    observed_after: Any = None
    verified = False
    try:
        try:
            apply()
        except OperationFailure:
            applied_ok = False
            raise
        except Exception as exc:
            applied_ok = False
            apply_error = f"{type(exc).__name__}: {exc}"
            raise OperationFailure("apply_failed", apply_error) from exc

        # Run verify even in preview so the caller can see what would land.
        ok, observed_after = verify()
        verified = bool(ok)
        committed = (not preview) and verified
    finally:
        program.endTransaction(tx, committed)

    return {
        "status": "verified" if verified else "verification_failed",
        "committed": committed,
        "preview": preview,
        "description": description,
        "before": before,
        "after": after,
        "observed_after": observed_after,
        "applied_ok": applied_ok,
    }


def _normalize_prototype(proto: str) -> str:
    """Collapse whitespace so two textually-equivalent C sigs compare equal."""
    return " ".join(str(proto).split())


_POINTER_GLUE_RE = re.compile(r"(\*+)(?=[A-Za-z_])")


def _normalize_proto_spacing(proto: str) -> str:
    """Insert a space between ``*`` and an identifier so FunctionSignatureParser
    tokenizes ``Item *item_new(...)`` correctly. The parser treats ``*name`` as
    a single token and fails; ``* name`` works. Whitespace around ``*`` is
    irrelevant in C type syntax, so this normalization is safe.
    """
    return _POINTER_GLUE_RE.sub(r"\1 ", proto)


def _resolve_data_type(dtm: Any, spec: str) -> Any:
    """Resolve a DataType from a short name, path, or type expression."""
    dt = _find_data_type(dtm, str(spec))
    if dt is not None:
        return dt
    try:
        from ghidra.util.data import DataTypeParser  # type: ignore

        parser = DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)
        parsed = parser.parse(str(spec))
        if parsed is not None:
            return parsed
    except Exception:
        pass
    raise OperationFailure("not_found", f"could not resolve data type: {spec!r}")


def _varnode_references_struct(vn: Any, struct_name: str) -> bool:
    """Return True if this Varnode's high variable is typed as the named struct
    (or pointer to it). Used by field_xrefs."""
    try:
        high = vn.getHigh()
        if high is None:
            return False
        dt = high.getDataType()
        if dt is None:
            return False
        # Walk through typedefs and pointers to find the underlying struct.
        return _data_type_matches_struct(dt, struct_name)
    except Exception:
        return False


def _data_type_matches_struct(dt: Any, struct_name: str, _depth: int = 0) -> bool:
    if dt is None or _depth > 6:
        return False
    try:
        name = str(dt.getName())
        if name == struct_name:
            return True
        # Pointer → element type.
        get_dt = getattr(dt, "getDataType", None)
        if callable(get_dt):
            return _data_type_matches_struct(get_dt(), struct_name, _depth + 1)
        # Typedef → base type.
        get_base = getattr(dt, "getBaseDataType", None)
        if callable(get_base):
            return _data_type_matches_struct(get_base(), struct_name, _depth + 1)
    except Exception:
        return False
    return False


def _struct_fields(struct: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for c in struct.getDefinedComponents():
        rows.append(
            {
                "offset": int(c.getOffset()),
                "name": str(c.getFieldName()) if c.getFieldName() else None,
                "type": str(c.getDataType().getName()),
                "size": int(c.getLength()),
            }
        )
    return rows


def _apply_local_mutation(
    program: Any,
    fn: Any,
    *,
    var_name: str,
    new_name: str | None,
    new_type: str | None,
    preview: bool,
) -> dict[str, Any]:
    """Rename and/or retype a local variable (or parameter)."""
    from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
    from ghidra.program.model.pcode import HighFunctionDBUtil  # type: ignore
    from ghidra.program.model.symbol import SourceType  # type: ignore
    from ghidra.util.task import TaskMonitor  # type: ignore

    dtm = program.getDataTypeManager()
    resolved_type = _resolve_data_type(dtm, new_type) if new_type else None

    iface = DecompInterface()
    iface.setOptions(DecompileOptions())
    iface.openProgram(program)
    try:
        results = iface.decompileFunction(fn, 60, TaskMonitor.DUMMY)
        if not results.decompileCompleted():
            raise OperationFailure(
                "decompile_failed",
                results.getErrorMessage() or "decompilation did not complete",
            )
        high = results.getHighFunction()
        if high is None:
            raise OperationFailure(
                "decompile_failed", "decompiler did not return a high function"
            )

        # First try the stored Variable, matching by name OR stable storage id.
        # Fall back to HighSymbol for decompiler-introduced locals that only
        # live in the HighFunction.
        match_var = None
        for cand in list(fn.getLocalVariables()) + list(fn.getParameters()):
            if str(cand.getName()) == var_name or _var_id(cand) == var_name:
                match_var = cand
                break

        high_sym = None
        sym_iter = high.getLocalSymbolMap().getSymbols()
        while sym_iter.hasNext():
            hs = sym_iter.next()
            if str(hs.getName()) == var_name or _storage_id(_high_sym_storage(hs)) == var_name:
                high_sym = hs
                break

        if match_var is None and high_sym is None:
            # Also check formal parameters on the HighFunction.
            try:
                for i in range(high.getFunctionPrototype().getNumParams()):
                    hs = high.getFunctionPrototype().getParam(i)
                    if hs is not None and str(hs.getName()) == var_name:
                        high_sym = hs
                        break
            except Exception:
                pass

        # Resolve the matched variable's actual current name (var_name may be a
        # stable id rather than the live name).
        if match_var is not None:
            resolved_name = str(match_var.getName())
        elif high_sym is not None:
            resolved_name = str(high_sym.getName())
        else:
            resolved_name = var_name

        before_state = {
            "name": resolved_name,
            "type": (
                str(match_var.getDataType().getName())
                if match_var is not None
                else (str(high_sym.getDataType().getName()) if high_sym is not None else None)
            ),
        }

        effective_new_name = new_name if new_name is not None else resolved_name
        effective_new_type = resolved_type if resolved_type is not None else (
            match_var.getDataType() if match_var is not None
            else (high_sym.getDataType() if high_sym is not None else None)
        )

        def _apply() -> None:
            if match_var is not None and high_sym is None:
                # Pure stored-variable path.
                if new_name is not None:
                    match_var.setName(effective_new_name, SourceType.USER_DEFINED)
                if resolved_type is not None:
                    match_var.setDataType(resolved_type, SourceType.USER_DEFINED)
                return
            if high_sym is None:
                raise OperationFailure(
                    "not_found",
                    f"variable {var_name!r} not found in {fn.getName()}",
                )
            HighFunctionDBUtil.updateDBVariable(
                high_sym,
                effective_new_name if new_name is not None else None,
                resolved_type,
                SourceType.USER_DEFINED,
            )

        def _verify() -> tuple[bool, Any]:
            for cand in list(fn.getLocalVariables()) + list(fn.getParameters()):
                if str(cand.getName()) == effective_new_name:
                    ok_type = (
                        resolved_type is None
                        or str(cand.getDataType().getName())
                        == str(resolved_type.getName())
                    )
                    return ok_type, {
                        "name": str(cand.getName()),
                        "type": str(cand.getDataType().getName()),
                    }
            # Fall through: may only exist on the HighFunction; that's still
            # a valid outcome for decompiler-introduced locals.
            return True, {"name": effective_new_name, "note": "only visible in HighFunction"}

        description = f"ghx:local_mutate {fn.getName()}:{resolved_name}"
        return _run_mutation(
            program,
            description=description,
            apply=_apply,
            verify=_verify,
            preview=preview,
            before={"function": _func_brief(fn), **before_state},
            after={
                "function": _func_brief(fn),
                "name": effective_new_name,
                "type": (
                    str(effective_new_type.getName())
                    if effective_new_type is not None
                    else before_state["type"]
                ),
            },
        )
    finally:
        with contextlib.suppress(Exception):
            iface.dispose()


def _build_py_exec_scope(project: Any, program: Any | None) -> dict[str, Any]:
    import jpype
    import ghidra  # type: ignore

    scope: dict[str, Any] = {
        "project": project,
        "currentProject": project,
        "program": program,
        "currentProgram": program,
        "result": None,
        "jpype": jpype,
        "ghidra": ghidra,
    }

    if program is not None:
        from ghidra.program.flatapi import FlatProgramAPI  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        flat = FlatProgramAPI(program)
        scope.update(
            {
                "flat": flat,
                "fpapi": flat,
                "listing": program.getListing(),
                "functionManager": program.getFunctionManager(),
                "symbolTable": program.getSymbolTable(),
                "referenceManager": program.getReferenceManager(),
                "dataTypeManager": program.getDataTypeManager(),
                "memory": program.getMemory(),
                "monitor": TaskMonitor.DUMMY,
                "get_function": lambda ident: _resolve_function(program, str(ident)),
                "addr": lambda s: program.getAddressFactory().getAddress(str(s)),
                "hexa": lambda a: f"0x{int(a.getOffset()):x}",
            }
        )

        def _decompile(fn_ident: Any, timeout: int = 60) -> str:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore

            fn = _resolve_function(program, str(fn_ident)) if isinstance(fn_ident, str) else fn_ident
            iface = DecompInterface()
            iface.setOptions(DecompileOptions())
            iface.openProgram(program)
            try:
                results = iface.decompileFunction(fn, timeout, TaskMonitor.DUMMY)
                if not results.decompileCompleted():
                    raise RuntimeError(results.getErrorMessage() or "decompile failed")
                return str(results.getDecompiledFunction().getC())
            finally:
                with contextlib.suppress(Exception):
                    iface.dispose()

        scope["decompile"] = _decompile

        def _to_address(value: Any) -> Any:
            if isinstance(value, str):
                return program.getAddressFactory().getAddress(value)
            get_off = getattr(value, "getOffset", None)
            if callable(get_off):
                return value  # already an Address
            if isinstance(value, int):
                return program.getAddressFactory().getDefaultAddressSpace().getAddress(value)
            raise TypeError(f"could not coerce to Address: {value!r}")

        def _define_data(addr: Any, dt: Any, *, clear: bool = True) -> Any:
            """Define typed data at *addr*, clearing any conflicting code unit
            that auto-analysis already laid down. Pass a DataType or a name
            resolvable via the DataTypeManager."""
            a = _to_address(addr)
            resolved = dt if hasattr(dt, "getLength") else _resolve_data_type(
                program.getDataTypeManager(), str(dt)
            )
            listing_local = program.getListing()
            if clear:
                try:
                    end = a.add(max(int(resolved.getLength()) - 1, 0))
                    listing_local.clearCodeUnits(a, end, False)
                except Exception:
                    # clearCodeUnits raises CancelledException under some
                    # configurations; swallow and let createData surface the
                    # real conflict.
                    pass
            return listing_local.createData(a, resolved)

        scope["define_data"] = _define_data
        scope["clear_data"] = lambda addr, length=1: program.getListing().clearCodeUnits(
            _to_address(addr), _to_address(addr).add(max(int(length) - 1, 0)), False
        )

    return scope


def _normalize_py_result(value: Any) -> Any:
    """Turn Java / Ghidra objects into JSON-serializable Python values.

    Strings, ints, floats, booleans, None pass through. Lists and dicts recurse.
    Anything else is coerced to ``str()`` with its class name for diagnostics.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_normalize_py_result(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _normalize_py_result(v) for k, v in value.items()}
    # Fall back to repr with type hint.
    try:
        text = str(value)
    except Exception:
        text = repr(value)
    return {"__str__": text, "__type__": type(value).__name__}


def _program_entry_offset(program: Any) -> int | None:
    """Return the program's primary entry-point offset, or None if unknown.

    Order of preference:

    1. A symbol named ``entry`` (Ghidra's ELF loader convention) or a common
       C-runtime entry name (``_start``, ``start``, ``main``).
    2. The first entry in ``SymbolTable.getExternalEntryPointIterator()`` as a
       fallback for formats that don't provide a named entry symbol.
    """
    for name in ("entry", "_start", "start", "main"):
        try:
            symbols = list(program.getSymbolTable().getSymbols(name))
        except Exception:
            continue
        for sym in symbols:
            addr = sym.getAddress()
            if addr is not None:
                return int(addr.getOffset())
    try:
        it = program.getSymbolTable().getExternalEntryPointIterator()
        if it.hasNext():
            addr = it.next()
            if addr is not None:
                return int(addr.getOffset())
    except Exception:
        pass
    return None


def _find_data_type(dtm: Any, name: str) -> Any:
    """Resolve a DataType by short name, full path, or case-insensitive match.

    Falls back to the built-in DataTypeManager so primitives like ``bool``,
    ``char``, ``int`` that don't live in the program's DTM are still findable.
    """
    direct = dtm.getDataType(name)
    if direct is not None:
        return direct
    if not name.startswith("/"):
        direct = dtm.getDataType("/" + name)
        if direct is not None:
            return direct
    # Scan the program DTM first.
    hit = _scan_dtm(dtm, name)
    if hit is not None:
        return hit
    # Fall back to the built-in DTM for primitives.
    try:
        from ghidra.program.model.data import BuiltInDataTypeManager  # type: ignore

        builtin = BuiltInDataTypeManager.getDataTypeManager()
    except Exception:
        return None
    direct = builtin.getDataType(name)
    if direct is not None:
        return direct
    if not name.startswith("/"):
        direct = builtin.getDataType("/" + name)
        if direct is not None:
            return direct
    return _scan_dtm(builtin, name)


def _scan_dtm(dtm: Any, name: str) -> Any:
    needle = name.lower()
    first_hit: Any = None
    try:
        it = dtm.getAllDataTypes()
    except Exception:
        return None
    while it.hasNext():
        dt = it.next()
        try:
            dt_name = str(dt.getName()).lower()
            dt_path = str(dt.getPathName()).lower()
        except Exception:
            continue
        if dt_name == needle or dt_path == needle:
            return dt
        if first_hit is None and needle in dt_path:
            first_hit = dt
    return first_hit


# ---------------------------------------------------------------------------
# Headless entry point
# ---------------------------------------------------------------------------


_bridge: GhxBridge | None = None


def start_headless(
    *,
    binaries: list[str] | None = None,
    instance_id: str | None = None,
    install_dir: Path,
    project_path: str | None = None,
    project_name: str | None = None,
) -> None:
    """Start the PyGhidra bridge in headless mode.

    Spins up the JVM, opens (or creates) a Ghidra project, binds a Unix
    socket, and blocks the calling thread until shutdown is requested.
    """
    global _bridge
    if _bridge is not None:
        return

    if instance_id is None:
        instance_id = secrets.token_hex(4)

    # Resolve project location (defaults to an ephemeral project keyed on instance_id).
    if project_path:
        proj_dir = Path(project_path).expanduser().resolve()
        if project_name is None:
            project_name = proj_dir.name
            proj_dir = proj_dir.parent
    else:
        proj_dir = projects_dir() / instance_id
        if project_name is None:
            project_name = f"ghx-{instance_id}"
    proj_dir.mkdir(parents=True, exist_ok=True)

    # Boot the JVM.  HeadlessPyGhidraLauncher caches and is idempotent.
    import pyghidra

    pyghidra.start(verbose=False, install_dir=install_dir)

    # Open/create the project.
    project = pyghidra.open_project(str(proj_dir), project_name, create=True)

    instances_dir().mkdir(parents=True, exist_ok=True)

    _bridge = GhxBridge(
        instance_id=instance_id,
        install_dir=install_dir,
        project_path=proj_dir,
        project_name=project_name,
        project=project,
    )
    _bridge.start()

    # Pre-load any binaries the user requested.
    if binaries:
        for path in binaries:
            try:
                handle = _bridge.targets.load_binary(path)
                print(f"[ghx] loaded {path} as {handle.program_id}", file=sys.stderr, flush=True)
            except Exception as exc:
                print(f"[ghx] failed to load {path}: {exc}", file=sys.stderr, flush=True)

    # Install signal handlers for graceful shutdown.
    def _handle_signal(signum, _frame):
        print(f"[ghx] received signal {signum}, shutting down", file=sys.stderr, flush=True)
        _bridge._shutdown_event.set()

    with contextlib.suppress(ValueError):
        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)

    try:
        _bridge._shutdown_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        _stop_bridge()


def _stop_bridge() -> None:
    global _bridge
    if _bridge is not None:
        _bridge.stop()
        _bridge = None


atexit.register(_stop_bridge)
