"""Sanity checks for the argparse tree."""
from __future__ import annotations

import pytest

from ghx import cli


@pytest.fixture
def parser():
    return cli._build_parser()


def test_version_is_exposed(parser, capsys):
    with pytest.raises(SystemExit):
        parser.parse_args(["--version"])
    captured = capsys.readouterr()
    assert "ghx" in captured.out


@pytest.mark.parametrize(
    "argv",
    [
        ["doctor"],
        ["refresh"],
        ["save"],
        ["save", "/tmp/out.gpr"],
        ["skill", "install"],
        ["skill", "install", "--mode", "copy", "--force"],
        ["skill", "install", "--dest", "/tmp/skills"],
        ["session", "list"],
        ["session", "start"],
        ["session", "start", "--project", "/tmp/p", "--project-name", "n"],
        ["session", "stop"],
        ["load", "/bin/ls"],
        ["close"],
        ["target", "list"],
        ["target", "info"],
        ["decompile", "main"],
        ["decompile", "main", "--addresses"],
        ["decompile", "main", "--lines", "10:20"],
        ["function", "list"],
        ["function", "search", "main"],
        ["function", "info", "main"],
        ["function", "info", "main", "-v"],
        ["function", "info", "main", "--verbose"],
        ["il", "main", "--form", "raw"],
        ["il", "main", "--form", "high"],
        ["disasm", "main"],
        ["xrefs", "main"],
        ["xrefs", "--field", "Player.hp"],
        ["xrefs", "--field", "Player.0x10", "--in-function", "update"],
        ["strings"],
        ["strings", "--section", ".rodata", "--no-crt"],
        ["imports"],
        ["sections"],
        ["types", "list"],
        ["types", "show", "size_t"],
        ["types", "declare", "--source", "struct S { int x; };"],
        ["types", "declare", "--stdin"],
        ["symbol", "rename", "main", "ghx_main"],
        ["symbol", "rename", "main", "ghx_main", "--preview", "--kind", "function"],
        ["comment", "set", "--address", "0x400000", "hello"],
        ["comment", "set", "--function", "main", "--kind", "pre", "hi"],
        ["comment", "get", "--address", "0x400000"],
        ["comment", "delete", "--address", "0x400000"],
        ["comment", "list"],
        ["proto", "get", "main"],
        ["proto", "set", "main", "int main(int argc, char ** argv)"],
        ["proto", "set", "main", "int main(int a)", "--preview"],
        ["local", "list", "main"],
        ["local", "rename", "main", "v", "ctx"],
        ["local", "retype", "main", "v", "int"],
        ["local", "rename", "main", "v", "ctx", "--preview"],
        ["struct", "show", "S"],
        ["struct", "field", "set", "S", "0", "x", "int"],
        ["struct", "field", "set", "S", "0", "x", "int", "--preview", "--no-overwrite"],
        ["struct", "field", "rename", "S", "x", "y"],
        ["struct", "field", "rename", "S", "--offset", "0x10", "y"],
        ["struct", "field", "delete", "S", "x"],
        ["struct", "field", "delete", "S", "--offset", "0x10"],
        ["callsites", "strcpy"],
        ["callsites", "strcpy", "--context", "2"],
        ["callsites", "strcpy", "--within-file", "/tmp/whitelist.txt"],
        ["bundle", "function", "main"],
        ["batch", "apply", "/tmp/manifest.json"],
        ["py", "exec", "--code", "print(1)"],
        ["py", "exec", "--code", "x=1", "--mutate"],
        ["py", "exec", "--stdin"],
    ],
)
def test_parser_accepts_v1_commands(parser, argv):
    ns = parser.parse_args(argv)
    assert hasattr(ns, "func"), f"no callable bound for argv={argv}"


def test_common_flags_on_target_command(parser):
    # `function info` is a target-aware command: should accept --format, --out,
    # --instance, and -t together.
    ns = parser.parse_args([
        "function", "info", "main",
        "--format", "json", "--out", "/tmp/fi.json",
        "--instance", "xyz", "-t", "active",
    ])
    assert ns.format == "json"
    assert ns.out == "/tmp/fi.json"
    assert ns.instance == "xyz"
    assert ns.target == "active"


def test_doctor_rejects_target_flag(parser):
    # Doctor is not a target-aware command; -t should fail to parse.
    with pytest.raises(SystemExit):
        parser.parse_args(["doctor", "-t", "active"])
