"""End-to-end smoke test: boot the daemon, load a binary, decompile."""
from __future__ import annotations

import json
import os

import pytest

from ghx.transport import send_request


pytestmark = pytest.mark.integration


def test_load_decompile_rename_roundtrip(running_agent):
    # 1. Doctor -> healthy.
    doc = send_request("doctor", instance_id=running_agent)
    assert doc["ok"] is True
    assert doc["result"]["ghx_version"]
    assert doc["result"]["ghidra_version"] != "?"

    # 2. Load /bin/true - tiny, fast to analyze.
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    assert load["ok"] is True
    assert load["result"]["basename"] == "true"
    program_id = load["result"]["program_id"]

    # 3. List targets - should contain the loaded program.
    targets = send_request("list_targets", instance_id=running_agent)["result"]
    assert any(t["program_id"] == program_id for t in targets)

    # 4. Decompile entry - every ELF has one.
    dec = send_request(
        "decompile",
        params={"identifier": "entry"},
        target=program_id,
        instance_id=running_agent,
        timeout=60.0,
    )
    assert dec["ok"] is True
    assert "entry" in dec["result"]["text"].lower() or "libc_start_main" in dec["result"]["text"]

    # 5. Preview rename - should come back verified but not committed.
    preview = send_request(
        "rename_symbol",
        params={"identifier": "entry", "new_name": "ghx_entry", "preview": True},
        target=program_id,
        instance_id=running_agent,
    )
    assert preview["ok"] is True
    assert preview["result"]["status"] == "verified"
    assert preview["result"]["committed"] is False

    # 6. Verify the preview didn't stick.
    still_entry = send_request(
        "function_info",
        params={"identifier": "entry"},
        target=program_id,
        instance_id=running_agent,
    )
    assert still_entry["ok"] is True
    assert still_entry["result"]["function"]["name"] == "entry"

    # 7. Commit the rename.
    commit = send_request(
        "rename_symbol",
        params={"identifier": "entry", "new_name": "ghx_entry"},
        target=program_id,
        instance_id=running_agent,
    )
    assert commit["ok"] is True
    assert commit["result"]["committed"] is True

    # 8. Search confirms the rename stuck.
    found = send_request(
        "search_functions",
        params={"query": "ghx_entry"},
        target=program_id,
        instance_id=running_agent,
    )
    assert any(row["name"] == "ghx_entry" for row in found["result"])


def test_py_exec_read_only(running_agent):
    send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    r = send_request(
        "py_exec",
        params={
            "code": "result = currentProgram.getName()",
        },
        instance_id=running_agent,
    )
    assert r["ok"] is True
    assert r["result"]["ok"] is True
    assert r["result"]["result"] == "true"
