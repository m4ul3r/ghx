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
        ["session", "restart"],
        ["session", "restart", "--timeout", "60"],
        ["instance", "prune"],
        ["instance", "prune", "--idle", "300"],
        ["load", "/bin/ls"],
        ["load", "/bin/ls", "--quick"],
        ["close"],
        ["target", "list"],
        ["target", "info"],
        ["decompile", "main"],
        ["decompile", "main", "--addresses"],
        ["decompile", "main", "--lines", "10:20"],
        ["function", "list"],
        ["function", "list", "--sort", "size", "--count"],
        ["function", "list", "--sort", "name", "--limit", "20"],
        ["function", "search", "main"],
        ["function", "search", "parse", "--exact"],
        ["function", "search", "parse_.*", "--regex", "--sort", "size"],
        ["function", "search", "init", "--min-address", "0x400000", "--max-address", "0x410000"],
        ["function", "info", "main"],
        ["function", "info", "main", "-v"],
        ["function", "info", "main", "--verbose"],
        ["il", "main", "--form", "raw"],
        ["il", "main", "--form", "high"],
        ["il", "main", "--form", "high", "--lines", "1:40"],
        ["disasm", "main"],
        ["disasm", "main", "--lines", ":50"],
        ["xrefs", "main"],
        ["xrefs", "main", "--limit", "10", "--offset", "5"],
        ["xrefs", "--field", "Player.hp"],
        ["xrefs", "--field", "Player.0x10", "--in-function", "update"],
        ["xrefs", "--field", "Player.hp", "--limit", "20"],
        ["strings"],
        ["strings", "--section", ".rodata", "--no-crt"],
        ["strings", "--query", "passwd", "--regex"],
        ["strings", "--count"],
        ["strings", "--query", "key|token", "--regex", "--count"],
        ["imports"],
        ["imports", "--summary"],
        ["imports", "--count"],
        ["imports", "--limit", "50", "--offset", "10"],
        ["sections"],
        ["sections", "--count"],
        ["sections", "--query", ".text", "--limit", "5"],
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
        ["callsites", "memcpy", "--caller-static"],
        ["bundle", "function", "main"],
        ["batch", "apply", "/tmp/manifest.json"],
        ["py", "exec", "--code", "print(1)"],
        ["py", "exec", "--code", "x=1", "--mutate"],
        ["py", "exec", "--stdin"],
        ["function", "structured-il", "main"],
        ["function", "structured-il", "main", "--form", "raw"],
        ["function", "structured-il", "main", "--form", "high"],
        ["function", "create", "0x401000"],
        ["function", "create", "0x401000", "--name", "parse_pkt"],
        ["function", "create", "0x401000", "--preview"],
        ["read", "0x401000"],
        ["read", "0x401000", "-n", "64"],
        ["read", "0x401000", "--length", "256"],
        ["rename", "main", "ghx_main"],
        ["rename", "0x401000", "parse_pkt", "--kind", "function", "--preview"],
        ["instance", "use", "abcd1234"],
        ["instance", "clear"],
        ["target", "use", "active"],
        ["target", "clear"],
        ["evidence", "xrefs", "main"],
        ["evidence", "xrefs", "0x401000"],
        ["evidence", "function", "main"],
        ["evidence", "init"],
        ["evidence", "table", "0x401000"],
        ["evidence", "table", "vtable", "-n", "32", "--no-stop"],
        ["evidence", "message"],
        ["evidence", "message", "--query", "google::protobuf"],
        ["evidence", "message", "--query", "^_ZTV", "--regex", "--limit", "5"],
        ["dataflow", "defuse", "main", "argc"],
        ["dataflow", "defuse", "0x401000", "local_10"],
        ["dataflow", "values", "main", "0x401010"],
        ["dataflow", "values", "main", "0x401010", "--register", "RAX"],
        ["dataflow", "values", "main", "0x401010", "--no-frame"],
        ["dataflow", "callgraph", "main"],
        ["dataflow", "callgraph", "main", "--direction", "callees", "--depth", "2"],
        ["dataflow", "callgraph", "0x401000", "--direction", "callers"],
        ["taint", "forward"],
        ["taint", "forward", "--function", "main"],
        ["taint", "forward", "--sources", "recv,read", "--sinks", "strcpy,system"],
        ["taint", "backward", "main", "--at", "0x401050", "--arg", "0"],
        ["taint", "backward", "main", "--variable", "buf"],
        ["trace", "main", "--at", "0x401050"],
        ["trace", "main", "--at", "0x401050", "--arg", "1"],
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
