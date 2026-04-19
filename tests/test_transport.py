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

from ghx import paths, transport


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
