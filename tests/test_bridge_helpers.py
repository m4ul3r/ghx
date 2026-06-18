"""Unit coverage for bridge helpers that do not need a Ghidra JVM."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


PLUGIN_DIR = Path(__file__).resolve().parents[1] / "plugin"
if str(PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGIN_DIR))

from ghx_agent_bridge import bridge  # noqa: E402


class _Space:
    def __init__(self, name: str) -> None:
        self._name = name

    def getName(self) -> str:
        return self._name

    def __str__(self) -> str:
        return self._name


class _Address:
    def __init__(self, space: _Space, offset: int, rendered: str) -> None:
        self._space = space
        self._offset = offset
        self._rendered = rendered

    def getAddressSpace(self) -> _Space:
        return self._space

    def getOffset(self) -> int:
        return self._offset

    def __str__(self) -> str:
        return self._rendered


class _AddressFactory:
    def __init__(self, default_space: _Space) -> None:
        self._default_space = default_space

    def getDefaultAddressSpace(self) -> _Space:
        return self._default_space


class _Program:
    def __init__(self, default_space: _Space) -> None:
        self._factory = _AddressFactory(default_space)

    def getAddressFactory(self) -> _AddressFactory:
        return self._factory


def test_format_address_preserves_non_default_space():
    ram = _Space("ram")
    stack = _Space("stack")
    program = _Program(ram)

    assert bridge._format_address(program, _Address(ram, 0x401000, "00401000")) == "0x401000"
    assert (
        bridge._format_address(program, _Address(stack, -0x20, "Stack[-0x20]"))
        == "Stack[-0x20]"
    )


@pytest.mark.parametrize(
    ("op", "params", "expected_op", "expected_params"),
    [
        (
            "symbol.rename",
            {"identifier": "entry", "new_name": "demo_entry"},
            "rename_symbol",
            {"identifier": "entry", "new_name": "demo_entry"},
        ),
        (
            "local.rename",
            {"function": "entry", "variable": "local_8", "new_name": "buf"},
            "local_rename",
            {
                "function": "entry",
                "variable": "local_8",
                "identifier": "entry",
                "name": "local_8",
                "new_name": "buf",
            },
        ),
        (
            "local.retype",
            {"function": "entry", "variable": "local_8", "new_type": "char *"},
            "local_retype",
            {
                "function": "entry",
                "variable": "local_8",
                "identifier": "entry",
                "name": "local_8",
                "new_type": "char *",
                "type": "char *",
            },
        ),
        (
            "struct.field.rename",
            {"struct_name": "Demo", "old_name": "a", "new_name": "b"},
            "struct_field_rename",
            {
                "struct_name": "Demo",
                "type_name": "Demo",
                "old_name": "a",
                "name": "a",
                "new_name": "b",
            },
        ),
    ],
)
def test_normalize_batch_op_accepts_cli_vocabulary(op, params, expected_op, expected_params):
    normalized_op, normalized_params = bridge._normalize_batch_op(op, params)

    assert normalized_op == expected_op
    assert normalized_params == expected_params


def test_target_ambiguity_message_lists_disambiguating_selectors():
    manager = bridge.TargetManager(project=object())
    first = bridge.ProgramHandle(
        program_id="aaaa1111",
        basename="demo_app",
        filename="/tmp/a/demo_app",
        domain_file_path="/demo_app",
        opened_at="2026-06-18T00:00:00+00:00",
        program=object(),
        consumer=object(),
    )
    second = bridge.ProgramHandle(
        program_id="bbbb2222",
        basename="demo_app",
        filename="/tmp/b/demo_app",
        domain_file_path="/demo_app.0",
        opened_at="2026-06-18T00:00:01+00:00",
        program=object(),
        consumer=object(),
    )
    manager._handles = {first.program_id: first, second.program_id: second}

    with pytest.raises(bridge.OperationFailure) as exc:
        manager.resolve("demo_app", required=True)

    message = str(exc.value)
    assert "ambiguous_target" not in message
    assert "aaaa1111" in message
    assert "bbbb2222" in message
    assert "/demo_app" in message
    assert "/demo_app.0" in message
