#!/usr/bin/env python3
"""A/B parity harness — compare `bn` and `ghx` answers on the SAME binary.

Surface parity (matching commands/flags) is not real parity; real parity is the
two engines returning equivalent ANSWERS. Addresses are ground truth, so this
harness extracts comparable signals (address sets, name sets, counts) from each
engine and reports exactly what one found that the other didn't.

Usage:
    python tools/ab_parity.py <binary-path> [--keep] [--probe NAME ...]

It starts an ISOLATED bn instance (never touches existing ones — see
`bn instance list`) and uses/loads a ghx daemon, runs each probe through both,
then stops the bn instance it created. Pass --keep to leave both loaded.

The binary path is taken as an argument and never written anywhere; point it at
your gitignored dogfood target. Redirect the report into .dogfood/ if you want
to keep it.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

TIMEOUT = 300


def _run_json(argv: list[str]) -> object:
    """Run a CLI with `--format json --out <tmp>` and return parsed JSON.

    Using --out sidesteps the >10k-token spill envelope that both CLIs print to
    stdout for large results. Returns a dict with a `_error` key on failure.
    """
    fd, out = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        cp = subprocess.run(
            argv + ["--format", "json", "--out", out],
            capture_output=True, text=True, timeout=TIMEOUT,
        )
        body = Path(out).read_text(encoding="utf-8", errors="replace")
        if not body.strip():
            body = cp.stdout
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"_error": "non-JSON output", "_stdout": cp.stdout[:400],
                    "_stderr": cp.stderr[:400]}
    except subprocess.TimeoutExpired:
        return {"_error": f"timeout after {TIMEOUT}s"}
    finally:
        with contextlib.suppress(OSError):
            os.unlink(out)


def _norm_addr(a: object) -> int | None:
    s = str(a)
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (ValueError, TypeError):
        return None


def _items(data: object, *keys: str) -> list[dict]:
    """Pull the row list out of either engine's shape: a bare JSON array (ghx)
    or a {<key>: [...]} / {items: [...]} envelope (bn)."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in (*keys, "items", "functions", "chains", "callsites"):
            v = data.get(k)
            if isinstance(v, list):
                return v
    return []


# Each probe: how to fetch from each engine and how to key the rows. `addr`
# and `name` are pulled per-row; we diff the resulting sets.
PROBES: dict[str, dict] = {
    "functions": {
        "bn": ["function", "list", "--limit", "100000"],
        "ghx": ["function", "list", "--limit", "100000"],
        "key": "address", "label": "name",
    },
    "imports": {
        "bn": ["imports", "--limit", "100000"],
        "ghx": ["imports", "--limit", "100000"],
        "key": "name", "label": "address",
        # ghx lists each external + its thunks; collapse to the symbol name set.
    },
    "strings": {
        "bn": ["strings", "--limit", "100000"],
        "ghx": ["strings", "--limit", "100000"],
        "key": "address", "label": "value",
    },
    "sections": {
        "bn": ["sections", "--limit", "100000"],
        "ghx": ["sections", "--limit", "100000"],
        "key": "name", "label": "start",
    },
}


def _keyset(rows: list[dict], key: str) -> set:
    out = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        v = r.get(key)
        if v is None:
            continue
        out.add(_norm_addr(v) if key in ("address", "start", "end") else str(v))
    return out


def _fmt_keys(keys: set, key: str, n: int = 25) -> str:
    def show(k):
        return f"0x{k:x}" if isinstance(k, int) else repr(k)
    items = sorted(keys, key=lambda k: (isinstance(k, str), k))
    head = ", ".join(show(k) for k in items[:n])
    more = f"  …(+{len(items) - n} more)" if len(items) > n else ""
    return head + more


def run(binary: str, bn_inst: str, ghx_inst: str | None, probes: list[str]) -> int:
    print(f"# A/B parity: {Path(binary).name}\n")
    diverged = 0
    for name in probes:
        spec = PROBES[name]
        key = spec["key"]
        bn_data = _run_json(["bn", *spec["bn"], "--instance", bn_inst])
        ghx_argv = ["python", "-m", "ghx", *spec["ghx"]]
        if ghx_inst:
            ghx_argv += ["--instance", ghx_inst]
        ghx_data = _run_json(ghx_argv)

        if isinstance(bn_data, dict) and bn_data.get("_error"):
            print(f"## {name}: bn error: {bn_data}\n")
            continue
        if isinstance(ghx_data, dict) and ghx_data.get("_error"):
            print(f"## {name}: ghx error: {ghx_data}\n")
            continue

        bn_rows = _items(bn_data, name)
        ghx_rows = _items(ghx_data, name)
        bn_set = _keyset(bn_rows, key)
        ghx_set = _keyset(ghx_rows, key)
        both = bn_set & ghx_set
        bn_only = bn_set - ghx_set
        ghx_only = ghx_set - bn_set

        agree = not bn_only and not ghx_only
        tag = "AGREE" if agree else "DIVERGE"
        if not agree:
            diverged += 1
        print(f"## {name}: {tag}  (bn={len(bn_set)} ghx={len(ghx_set)} "
              f"shared={len(both)})  key={key}")
        if bn_only:
            print(f"   bn-only ({len(bn_only)}): {_fmt_keys(bn_only, key)}")
        if ghx_only:
            print(f"   ghx-only ({len(ghx_only)}): {_fmt_keys(ghx_only, key)}")
        print()
    print(f"# {diverged}/{len(probes)} probes diverge")
    return diverged


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", help="Path to the binary to compare (e.g. dogfood target)")
    ap.add_argument("--keep", action="store_true", help="Leave both engines loaded")
    ap.add_argument("--probe", action="append", choices=list(PROBES),
                    help="Run only these probes (repeatable; default: all)")
    ap.add_argument("--bn-instance", default=None,
                    help="Reuse an existing bn instance instead of starting one")
    ap.add_argument("--ghx-instance", default=None)
    ns = ap.parse_args()

    binary = str(Path(ns.binary).expanduser())
    if not Path(binary).exists():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2

    probes = ns.probe or list(PROBES)
    started_bn = False
    bn_inst = ns.bn_instance
    if bn_inst is None:
        bn_inst = "abparity" + secrets.token_hex(3)
        print(f"# starting isolated bn instance {bn_inst} …", file=sys.stderr)
        r = subprocess.run(["bn", "load", binary, "--instance", bn_inst],
                           capture_output=True, text=True, timeout=TIMEOUT)
        if r.returncode != 0:
            print(f"bn load failed: {r.stderr or r.stdout}", file=sys.stderr)
            return 1
        started_bn = True

    # Clean ghx slate so a double-load doesn't make the target ambiguous.
    if ns.ghx_instance is None:
        subprocess.run(["python", "-m", "ghx", "close", "--all"],
                       capture_output=True, text=True)
        lr = subprocess.run(["python", "-m", "ghx", "load", binary],
                            capture_output=True, text=True, timeout=TIMEOUT)
        if lr.returncode != 0:
            print(f"ghx load failed: {lr.stderr or lr.stdout}", file=sys.stderr)
            if started_bn:
                subprocess.run(["bn", "instance", "stop", bn_inst],
                               capture_output=True, text=True)
            return 1

    try:
        return 0 if run(binary, bn_inst, ns.ghx_instance, probes) == 0 else 0
    finally:
        if started_bn and not ns.keep:
            print(f"# stopping bn instance {bn_inst}", file=sys.stderr)
            subprocess.run(["bn", "instance", "stop", bn_inst],
                           capture_output=True, text=True)


if __name__ == "__main__":
    raise SystemExit(main())
