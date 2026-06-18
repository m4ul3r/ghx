"""Transport-layer tests using a real Unix-socket echo server."""
from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
import time
from pathlib import Path

import pytest

from ghx import paths, pins, transport


def _fake_instance(instance_id: str) -> transport.BridgeInstance:
    return transport.BridgeInstance(
        pid=1,
        socket_path=Path(f"/tmp/{instance_id}.sock"),
        registry_path=Path(f"/tmp/{instance_id}.json"),
        plugin_name="ghx_agent_bridge",
        plugin_version="test",
        started_at=None,
        meta={},
        instance_id=instance_id,
    )


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline()
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        op = payload.get("op")
        response = self.server.responder(op, payload)
        try:
            self.wfile.write(json.dumps(response).encode("utf-8"))
        except BrokenPipeError:
            # Client closed the socket before we flushed; harmless during teardown.
            pass


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, sock_path: str, responder):
        self.responder = responder
        super().__init__(sock_path, _Handler)


def _write_registry(tmp_cache: Path, instance_id: str, sock_path: Path, pid: int) -> Path:
    path = paths.bridge_registry_path(instance_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "pid": pid,
                "socket_path": str(sock_path),
                "plugin_name": "ghx_agent_bridge",
                "plugin_version": "test",
                "started_at": "2026-04-18T00:00:00+00:00",
                "instance_id": instance_id,
            }
        )
    )
    return path


@pytest.fixture
def running_bridge(tmp_cache):
    """Spin up a fake Unix-socket bridge and register it."""
    instance_id = "abcd1234"
    sock_path = paths.bridge_socket_path(instance_id)
    sock_path.parent.mkdir(parents=True, exist_ok=True)

    def responder(op, payload):
        if op == "echo":
            return {"ok": True, "result": payload.get("params", {})}
        if op == "fail":
            return {"ok": False, "error": "forced_fail: nope"}
        return {"ok": False, "error": f"unknown op: {op}"}

    server = _Server(str(sock_path), responder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _write_registry(tmp_cache, instance_id, sock_path, pid=os.getpid())

    yield instance_id

    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


def test_list_instances_finds_registered(running_bridge, tmp_cache):
    inst = transport.list_instances()
    assert len(inst) == 1
    assert inst[0].instance_id == running_bridge


def test_send_request_round_trip(running_bridge):
    resp = transport.send_request(
        "echo",
        params={"hello": "world"},
        instance_id=running_bridge,
    )
    assert resp["ok"] is True
    assert resp["result"] == {"hello": "world"}


def test_send_request_bridges_error_into_exception(running_bridge):
    with pytest.raises(transport.BridgeError) as ei:
        transport.send_request("fail", instance_id=running_bridge)
    assert "forced_fail" in str(ei.value)


def test_choose_instance_raises_when_missing(tmp_cache):
    with pytest.raises(transport.BridgeError):
        transport.choose_instance("does-not-exist", auto_start=False)


def test_choose_instance_rejects_unsafe_instance_id(tmp_cache):
    with pytest.raises(transport.BridgeError):
        transport.choose_instance("../bad", auto_start=False)


def test_choose_instance_can_spawn_missing_named_instance(tmp_cache, monkeypatch):
    monkeypatch.setattr(transport, "list_instances", lambda: [])
    monkeypatch.setattr(
        transport,
        "spawn_instance",
        lambda instance_id=None, **_: _fake_instance(instance_id or "generated"),
    )

    inst = transport.choose_instance("named1", spawn_missing_named=True)
    assert inst.instance_id == "named1"


def test_choose_instance_honours_pin(tmp_cache, monkeypatch):
    insts = [_fake_instance("aaaa"), _fake_instance("bbbb")]
    monkeypatch.setattr(transport, "list_instances", lambda: insts)

    # With two live instances and no pin, selection is ambiguous -> error.
    with pytest.raises(transport.BridgeError):
        transport.choose_instance(None, auto_start=False)

    # A pin disambiguates.
    pins.set_instance("bbbb")
    assert transport.choose_instance(None, auto_start=False).instance_id == "bbbb"

    # An explicit id still overrides the pin.
    assert transport.choose_instance("aaaa", auto_start=False).instance_id == "aaaa"


def test_choose_instance_ignores_stale_pin(tmp_cache, monkeypatch):
    insts = [_fake_instance("aaaa")]
    monkeypatch.setattr(transport, "list_instances", lambda: insts)
    pins.set_instance("ghost")  # not among live instances

    # Stale pin is ignored; the single live instance is returned.
    assert transport.choose_instance(None, auto_start=False).instance_id == "aaaa"


def test_read_log_tail_surfaces_error_marker(tmp_path):
    log = tmp_path / "boot.log"
    # Java exception header printed early, then a long stack, then noise.
    lines = ["java.lang.IllegalArgumentException: Path element starting with '.' is not permitted"]
    lines += [f"\tat ghidra.framework.Frame{i}.run(Frame{i}.java:{i})" for i in range(40)]
    log.write_text("\n".join(lines) + "\n")

    tail = transport._read_log_tail(log)
    # The marked exception header survives even though it's far outside the tail window.
    assert "not permitted" in tail
    # And the tail end (recent stack frames) is present too.
    assert "Frame39" in tail


def test_read_log_tail_empty_log(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("   \n\n")
    assert transport._read_log_tail(log) == ""


def test_read_log_tail_missing_file(tmp_path):
    assert transport._read_log_tail(tmp_path / "nope.log") == ""


def test_spawn_failure_detail_includes_tail(tmp_path):
    log = tmp_path / "boot.log"
    log.write_text("Traceback (most recent call last):\nRuntimeError: boom\n")
    detail = transport._spawn_failure_detail(log)
    assert "RuntimeError: boom" in detail
    assert str(log) in detail


def test_spawn_failure_detail_falls_back_when_empty(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("")
    detail = transport._spawn_failure_detail(log)
    assert detail == f" Check {log}"


def test_purges_stale_registry_when_socket_missing(tmp_cache):
    # Write a registry pointing at a socket that doesn't exist.
    sock_path = tmp_cache / "instances" / "stale.sock"
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    # Don't create the socket itself.
    reg = _write_registry(tmp_cache, "stale", sock_path, pid=os.getpid())
    assert reg.exists()

    assert transport.list_instances() == []
    # list_instances purges the stale registry.
    assert not reg.exists()


def test_purges_stale_managed_socket_with_registry(tmp_cache):
    sock_path = paths.bridge_socket_path("stale")
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    sock_path.write_text("not a socket")
    reg = _write_registry(tmp_cache, "stale", sock_path, pid=os.getpid())
    assert reg.exists()
    assert sock_path.exists()

    assert transport.list_instances() == []
    assert not reg.exists()
    assert not sock_path.exists()
