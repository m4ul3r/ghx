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
}

WRITE_LOCKED_OPS: set[str] = {
    "load_binary",
    "close_binary",
    "save_database",
    "refresh",
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

    def load_binary(self, path: str) -> ProgramHandle:
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

    def close_all(self) -> None:
        with self._lock:
            handles = list(self._handles.values())
            self._handles.clear()
            self._active = None
        for h in handles:
            with contextlib.suppress(Exception):
                h.program.release(h.consumer)

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
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        if self.instance_id is not None:
            payload["instance_id"] = self.instance_id
        self.registry_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # ---- dispatch -------------------------------------------------------

    def dispatch(self, payload: dict[str, Any]) -> dict[str, Any]:
        op = payload.get("op")
        params = payload.get("params") or {}
        target = payload.get("target")
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
            handle = self.targets.load_binary(str(path))
            return {"loaded": True, **handle.describe()}
        if op == "close_binary":
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
            items.append(_func_brief(fn))
        items.sort(key=lambda row: int(row["address"], 16))
        if offset:
            items = items[offset:]
        if limit is not None:
            items = items[:limit]
        return items

    def _op_search_functions(self, params: dict[str, Any], target: str | None) -> list[dict[str, Any]]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        query = str(params.get("query", ""))
        regex = bool(params.get("regex", False))
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else None
        program = handle.program

        if regex:
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
            if matches(name):
                items.append(_func_brief(fn))
        items.sort(key=lambda row: int(row["address"], 16))
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

        program = handle.program
        fn = _resolve_function(program, str(identifier))

        lines: list[str] = []
        if form == "raw":
            listing = program.getListing()
            for ins in listing.getInstructions(fn.getBody(), True):
                addr = int(ins.getAddress().getOffset())
                for op in ins.getPcode():
                    lines.append(f"{addr:08x}  {op}")
        else:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions  # type: ignore
            from ghidra.util.task import TaskMonitor  # type: ignore

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
                        "decompile_failed",
                        "decompiler did not produce a high function",
                    )
                it = high.getPcodeOps()
                while it.hasNext():
                    op = it.next()
                    target_addr = op.getSeqnum().getTarget()
                    off = int(target_addr.getOffset()) if target_addr is not None else 0
                    lines.append(f"{off:08x}  {op}")
            finally:
                with contextlib.suppress(Exception):
                    iface.dispose()

        return {
            "function": _func_brief(fn),
            "form": form,
            "text": "\n".join(lines),
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

    def _op_xrefs(self, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        identifier = params.get("identifier")
        if identifier is None:
            raise OperationFailure("bad_request", "xrefs requires 'identifier'")
        program = handle.program

        try:
            off = _parse_address(program, identifier)
        except Exception:
            fn = _resolve_function(program, str(identifier))
            off = int(fn.getEntryPoint().getOffset())
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(off)

        fm = program.getFunctionManager()
        rm = program.getReferenceManager()
        listing = program.getListing()

        code_refs: list[dict[str, Any]] = []
        for ref in rm.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            from_off = int(from_addr.getOffset())
            caller = fm.getFunctionContaining(from_addr)
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
        for ref in rm.getReferencesFrom(addr):
            to = ref.getToAddress()
            outgoing.append(
                {
                    "address": f"0x{int(to.getOffset()):x}",
                    "ref_type": str(ref.getReferenceType()),
                }
            )

        return {
            "target": f"0x{off:x}",
            "incoming": code_refs,
            "outgoing": outgoing,
        }

    def _op_strings(self, params: dict[str, Any], target: str | None) -> list[dict[str, Any]]:
        from ghidra.program.util import DefinedStringIterator  # type: ignore

        handle = self.targets.resolve(params.get("target") or target, required=True)
        assert handle is not None
        query = params.get("query")
        needle = str(query).lower() if query else None
        section_filter = params.get("section")
        section_needle = str(section_filter) if section_filter else None
        min_len = int(params.get("min_length", 1))
        offset = int(params.get("offset", 0))
        limit = int(params["limit"]) if params.get("limit") is not None else None

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
            if needle and needle not in value.lower():
                continue
            addr = data.getAddress()
            off = int(addr.getOffset())
            block = memory.getBlock(addr)
            section = str(block.getName()) if block is not None else None
            if section_needle and section != section_needle:
                continue
            rows.append(
                {
                    "address": f"0x{off:x}",
                    "length": length,
                    "value": value,
                    "section": section,
                }
            )
        rows.sort(key=lambda row: int(row["address"], 16))
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        return rows

    def _op_imports(self, params: dict[str, Any], target: str | None) -> list[dict[str, Any]]:
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
                }
            )
        rows.sort(key=lambda row: (row["name"], int(row["address"], 16)))
        return rows

    def _op_sections(self, params: dict[str, Any], target: str | None) -> list[dict[str, Any]]:
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
                    "name": str(p.getName()),
                    "type": str(p.getDataType().getName()),
                    "storage": _storage_str(p),
                    "is_parameter": True,
                }
            )
        for lv in fn.getLocalVariables():
            rows.append(
                {
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

        callee = _resolve_function(program, str(identifier))
        fm = program.getFunctionManager()
        listing = program.getListing()
        rm = program.getReferenceManager()

        allowed_callers: set[str] | None = None
        if within:
            allowed_callers = {str(w) for w in within}

        sites: list[dict[str, Any]] = []
        for ref in rm.getReferencesTo(callee.getEntryPoint()):
            rtype = ref.getReferenceType()
            if not rtype.isCall():
                continue
            from_addr = ref.getFromAddress()
            caller = fm.getFunctionContaining(from_addr)
            caller_name = str(caller.getName()) if caller is not None else None
            if allowed_callers and caller_name not in allowed_callers:
                continue
            ins = listing.getInstructionAt(from_addr)
            return_addr = None
            if ins is not None:
                try:
                    return_addr = ins.getMaxAddress().add(1)
                except Exception:
                    return_addr = None
            site: dict[str, Any] = {
                "callee": str(callee.getName()),
                "caller": caller_name,
                "call_addr": f"0x{int(from_addr.getOffset()):x}",
                "return_address": (
                    f"0x{int(return_addr.getOffset()):x}" if return_addr is not None else None
                ),
                "ref_type": str(rtype),
                "disasm": str(ins) if ins is not None else None,
            }
            if context > 0 and ins is not None:
                site["prev_ins"] = _surrounding_instructions(listing, ins, -context)
                site["next_ins"] = _surrounding_instructions(listing, ins, context)
            sites.append(site)

        sites.sort(key=lambda row: int(row["call_addr"], 16))
        return {"callee": _func_brief(callee), "callsites": sites}

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


def _func_brief(fn: Any) -> dict[str, Any]:
    entry = fn.getEntryPoint()
    return {
        "name": str(fn.getName()),
        "address": f"0x{int(entry.getOffset()):x}",
        "size": int(fn.getBody().getNumAddresses()),
        "is_thunk": bool(fn.isThunk()),
        "is_external": bool(fn.isExternal()),
    }


def _storage_str(var: Any) -> str | None:
    try:
        storage = var.getVariableStorage()
        if storage is None:
            return None
        return str(storage)
    except Exception:
        return None


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

        # First try the stored Variable.  Fall back to HighSymbol for
        # decompiler-introduced locals that only live in the HighFunction.
        match_var = None
        for cand in list(fn.getLocalVariables()) + list(fn.getParameters()):
            if str(cand.getName()) == var_name:
                match_var = cand
                break

        high_sym = None
        sym_iter = high.getLocalSymbolMap().getSymbols()
        while sym_iter.hasNext():
            hs = sym_iter.next()
            if str(hs.getName()) == var_name:
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

        before_state = {
            "name": var_name,
            "type": (
                str(match_var.getDataType().getName())
                if match_var is not None
                else (str(high_sym.getDataType().getName()) if high_sym is not None else None)
            ),
        }

        effective_new_name = new_name if new_name is not None else var_name
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

        description = f"ghx:local_mutate {fn.getName()}:{var_name}"
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
