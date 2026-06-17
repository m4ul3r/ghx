"""End-to-end smoke test: boot the daemon, load a binary, decompile."""
from __future__ import annotations

import json
import os
import subprocess

import pytest

from ghx.transport import BridgeError, send_request


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


def test_structured_il_read_create(running_agent):
    """P0 parity ops: structured_il, read_bytes, create_function."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    assert load["ok"] is True
    program_id = load["result"]["program_id"]

    # --- structured_il (high): the data-flow substrate ---
    sil = send_request(
        "structured_il",
        params={"identifier": "entry", "form": "high"},
        target=program_id,
        instance_id=running_agent,
        timeout=60.0,
    )
    assert sil["ok"] is True
    assert sil["result"]["form"] == "high"
    assert sil["result"]["op_count"] > 0
    op0 = sil["result"]["ops"][0]
    assert isinstance(op0["op"], str)
    assert isinstance(op0["inputs"], list)
    assert "address" in op0

    # raw form also works (per-instruction p-code)
    sil_raw = send_request(
        "structured_il",
        params={"identifier": "entry", "form": "raw"},
        target=program_id,
        instance_id=running_agent,
    )
    assert sil_raw["ok"] is True
    assert sil_raw["result"]["op_count"] > 0

    # --- read_bytes: cross-check against disasm's first instruction bytes ---
    dis = send_request(
        "disasm",
        params={"identifier": "entry"},
        target=program_id,
        instance_id=running_agent,
    )
    assert dis["ok"] is True
    first = dis["result"]["instructions"][0]
    first_bytes = first["bytes_hex"]
    rd = send_request(
        "read_bytes",
        params={"address": first["address"], "length": len(first_bytes) // 2},
        target=program_id,
        instance_id=running_agent,
    )
    assert rd["ok"] is True
    assert rd["result"]["length_read"] == len(first_bytes) // 2
    assert rd["result"]["bytes_hex"] == first_bytes

    # read_bytes also accepts a symbol name (resolves like xrefs).
    rd_sym = send_request(
        "read_bytes",
        params={"address": "entry", "length": len(first_bytes) // 2},
        target=program_id,
        instance_id=running_agent,
    )
    assert rd_sym["ok"] is True
    assert rd_sym["result"]["bytes_hex"] == first_bytes

    # --- create_function: guard rejects an address that's already a function ---
    info = send_request(
        "function_info",
        params={"identifier": "entry"},
        target=program_id,
        instance_id=running_agent,
    )
    entry_addr = info["result"]["function"]["address"]
    with pytest.raises(BridgeError) as exc:
        send_request(
            "create_function",
            params={"address": entry_addr},
            target=program_id,
            instance_id=running_agent,
        )
    assert "already_exists" in str(exc.value)


def test_evidence_ops(running_agent):
    """Tier B composition ops: evidence_function, evidence_xrefs."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    # evidence_function on entry: summary fields present and self-consistent.
    ev = send_request(
        "evidence_function",
        params={"identifier": "entry"},
        target=program_id,
        instance_id=running_agent,
        timeout=60.0,
    )
    assert ev["ok"] is True
    r = ev["result"]
    assert r["function"]["name"] in ("entry", "_start")
    assert r["instruction_count"] > 0
    assert r["call_count"] == len(r["calls"])
    assert isinstance(r["arg_hints"], list)
    assert "section" in r  # memory block resolved (or explicitly None)

    # evidence_xrefs on entry: incoming refs carry a section field.
    info = send_request(
        "function_info", params={"identifier": "entry"},
        target=program_id, instance_id=running_agent,
    )
    entry_addr = info["result"]["function"]["address"]
    ex = send_request(
        "evidence_xrefs",
        params={"identifier": entry_addr},
        target=program_id,
        instance_id=running_agent,
    )
    assert ex["ok"] is True
    assert "incoming" in ex["result"]
    assert "target_section" in ex["result"]
    for ref in ex["result"]["incoming"]:
        assert "section" in ref  # enrichment applied to every incoming ref


def test_evidence_init_and_table(running_agent):
    """Tier B pointer-walking ops: evidence_init, evidence_table."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    # .init_array is present in virtually every PIE/ELF.
    ev = send_request(
        "evidence_init",
        target=program_id,
        instance_id=running_agent,
    )
    assert ev["ok"] is True
    names = {s["name"] for s in ev["result"]["sections"]}
    assert ".init_array" in names
    init = next(s for s in ev["result"]["sections"] if s["name"] == ".init_array")
    assert init["count"] >= 1
    # Each entry carries a slot, a value, and a classification.
    e0 = init["entries"][0]
    assert e0["slot"].startswith("0x")
    assert "kind" in e0

    # Reading the same .init_array as a generic pointer table resolves the
    # same first entry.
    tbl = send_request(
        "evidence_table",
        params={"address": init["start"], "count": init["count"], "stop_on_unmapped": False},
        target=program_id,
        instance_id=running_agent,
    )
    assert tbl["ok"] is True
    assert tbl["result"]["count"] >= 1
    assert tbl["result"]["entries"][0]["value"] == init["entries"][0]["value"]


def test_evidence_message(running_agent):
    """Tier B: evidence_message surfaces matching strings with xrefs/section."""
    import re

    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    # Pull a real string token to use as a deterministic query.
    strings = send_request(
        "strings",
        params={"min_length": 4, "limit": 300},
        target=program_id,
        instance_id=running_agent,
    )["result"]
    query = None
    for row in strings:
        match = re.search(r"[A-Za-z]{4,}", row["value"])
        if match:
            query = match.group(0)
            break
    assert query is not None, "no usable string token found in /bin/true"

    res = send_request(
        "evidence_message",
        params={"query": query},
        target=program_id,
        instance_id=running_agent,
    )
    assert res["ok"] is True
    assert res["result"]["match_count"] >= 1
    assert any(query in m["value"] for m in res["result"]["matches"])
    m0 = res["result"]["matches"][0]
    assert "section" in m0 and "xrefs" in m0 and "xref_count" in m0


def test_dataflow_defuse(running_agent):
    """Tier A: SSA def/use for a real variable discovered from the binary."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]
    funcs = send_request(
        "list_functions", params={"limit": 50},
        target=program_id, instance_id=running_agent,
    )["result"]

    found = None
    for f in funcs:
        if f.get("is_thunk") or f.get("is_external"):
            continue
        # The not_found error enumerates the function's variable names.
        try:
            send_request(
                "dataflow_defuse",
                params={"identifier": f["address"], "variable": "__ghx_nope__"},
                target=program_id, instance_id=running_agent, timeout=60.0,
            )
            continue
        except BridgeError as exc:
            msg = str(exc)
            if "available:" not in msg:
                continue
            names = [n.strip() for n in msg.split("available:", 1)[1].split(",") if n.strip()]
        for var in names[:8]:
            try:
                r = send_request(
                    "dataflow_defuse",
                    params={"identifier": f["address"], "variable": var},
                    target=program_id, instance_id=running_agent, timeout=60.0,
                )
            except BridgeError:
                continue
            if r["ok"]:
                found = (var, r["result"])
                break
        if found:
            break

    if found is None:
        import pytest as _pytest
        _pytest.skip("no named SSA variable found in /bin/true sample")

    var, res = found
    assert res["variable"] == var
    assert res["instance_count"] == len(res["instances"])
    # Each instance has a varnode descriptor and a use list.
    for inst in res["instances"]:
        assert "varnode" in inst
        assert inst["use_count"] == len(inst["uses"])


def test_taint_backward(running_agent):
    """Tier A: backward slice of a real call argument to its origins."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]
    funcs = send_request(
        "list_functions", params={"limit": 50},
        target=program_id, instance_id=running_agent,
    )["result"]

    chosen = None
    for f in funcs:
        if f.get("is_thunk") or f.get("is_external"):
            continue
        sil = send_request(
            "structured_il", params={"identifier": f["address"], "form": "high"},
            target=program_id, instance_id=running_agent, timeout=60.0,
        )["result"]
        for op in sil["ops"]:
            # A CALL with at least one argument (inputs = target + >=1 arg).
            if op["op"] in ("CALL", "CALLIND") and len(op.get("inputs", [])) >= 2:
                chosen = (f["address"], op["address"])
                break
        if chosen:
            break

    if chosen is None:
        import pytest as _pytest
        _pytest.skip("no call-with-arg found in /bin/true sample")

    fn_addr, call_addr = chosen
    res = send_request(
        "taint_backward",
        params={"identifier": fn_addr, "address": call_addr, "arg": 0},
        target=program_id, instance_id=running_agent, timeout=60.0,
    )
    assert res["ok"] is True
    r = res["result"]
    assert r["start"]["kind"] == "call_arg"
    assert r["start"]["address"] == call_addr
    assert r["origin_count"] == len(r["origins"])
    # A slice to origins must bottom out in at least one classified leaf.
    assert r["origin_count"] >= 1
    assert all("kind" in o for o in r["origins"])


def test_dataflow_callgraph(running_agent):
    """Tier A: resolved direct callees/callers around entry."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    cg = send_request(
        "dataflow_callgraph",
        params={"identifier": "entry", "direction": "both", "depth": 2},
        target=program_id, instance_id=running_agent, timeout=60.0,
    )
    assert cg["ok"] is True
    r = cg["result"]
    assert r["depth"] == 2
    assert "callees" in r and "callers" in r
    # entry calls __libc_start_main — a resolvable direct callee.
    callee_names = {n["name"] for n in r["callees"]}
    assert any("libc_start_main" in n for n in callee_names)
    # Every callee node carries a level and address.
    for n in r["callees"]:
        assert 1 <= n["level"] <= 2
        assert n["address"].startswith("0x")
    assert isinstance(r.get("indirect_callsites"), int)


def test_quick_load_then_refresh(running_agent):
    """Tier C: --quick load skips analysis; refresh deepens it."""
    quick = send_request(
        "load_binary",
        params={"path": "/bin/true", "quick": True},
        instance_id=running_agent,
        timeout=120.0,
    )
    assert quick["ok"] is True
    assert quick["result"]["analyzed"] is False
    program_id = quick["result"]["program_id"]

    before = send_request(
        "list_functions", params={"limit": 5000},
        target=program_id, instance_id=running_agent,
    )["result"]

    # refresh runs full auto-analysis, which should not error and typically
    # discovers more functions than a bare import.
    ref = send_request("refresh", target=program_id, instance_id=running_agent, timeout=120.0)
    assert ref["ok"] is True

    after = send_request(
        "list_functions", params={"limit": 5000},
        target=program_id, instance_id=running_agent,
    )["result"]
    assert len(after) >= len(before)


def test_save_export_gzf(running_agent, tmp_path):
    """Tier C: `save <path>` exports a non-empty .gzf archive."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    out = tmp_path / "true_export"
    res = send_request(
        "save_database",
        params={"path": str(out)},
        target=program_id, instance_id=running_agent, timeout=60.0,
    )
    assert res["ok"] is True
    assert res["result"]["exported"] is True
    assert res["result"]["format"] == "gzf"
    written = res["result"]["path"]
    assert written.endswith(".gzf")
    import os
    assert os.path.exists(written) and os.path.getsize(written) > 0


def test_stable_local_ids(running_agent):
    """Tier C: locals carry a storage-stable id; rename-by-id works and the id
    is unchanged after the rename."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]
    funcs = send_request(
        "list_functions", params={"limit": 50},
        target=program_id, instance_id=running_agent,
    )["result"]

    picked = None
    for f in funcs:
        if f.get("is_thunk") or f.get("is_external"):
            continue
        locals_ = send_request(
            "list_locals", params={"identifier": f["address"]},
            target=program_id, instance_id=running_agent,
        )["result"]["locals"]
        for lv in locals_:
            if lv.get("id"):
                picked = (f["address"], lv)
                break
        if picked:
            break

    if picked is None:
        import pytest as _pytest
        _pytest.skip("no stored local with a stable id found")

    fn_addr, lv = picked
    var_id = lv["id"]

    # Rename by stable id (not by name).
    res = send_request(
        "local_rename",
        params={"identifier": fn_addr, "name": var_id, "new_name": "ghx_renamed"},
        target=program_id, instance_id=running_agent,
    )
    assert res["ok"] is True
    assert res["result"]["committed"] is True

    # The id is stable: same storage handle after the rename, new name present.
    after = send_request(
        "list_locals", params={"identifier": fn_addr},
        target=program_id, instance_id=running_agent,
    )["result"]["locals"]
    match = [x for x in after if x.get("id") == var_id]
    assert match, f"stable id {var_id} disappeared after rename"
    assert match[0]["name"] == "ghx_renamed"


def test_dataflow_values(running_agent):
    """Tier A: SymbolicPropogator constant resolution runs and returns shape."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    dis = send_request(
        "disasm", params={"identifier": "entry"},
        target=program_id, instance_id=running_agent,
    )["result"]
    # Pick an address a few instructions in (still inside the function body).
    insns = dis["instructions"]
    query_addr = insns[min(3, len(insns) - 1)]["address"]

    res = send_request(
        "dataflow_values",
        params={"identifier": "entry", "address": query_addr},
        target=program_id, instance_id=running_agent, timeout=60.0,
    )
    assert res["ok"] is True
    r = res["result"]
    assert r["address"] == query_addr
    assert isinstance(r["values"], list)
    assert r["value_count"] == len(r["values"])
    assert "note" in r  # honest scoping note present
    for v in r["values"]:
        assert "register" in v and v["value"].startswith("0x")


def test_taint_forward(running_agent):
    """Tier A: forward-taint scan pipeline runs end-to-end and returns shape."""
    load = send_request(
        "load_binary",
        params={"path": "/bin/true"},
        instance_id=running_agent,
        timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    # Default run: must return the documented shape (chains may be empty).
    base = send_request(
        "taint_forward", params={},
        target=program_id, instance_id=running_agent, timeout=120.0,
    )
    assert base["ok"] is True
    r = base["result"]
    assert isinstance(r["chains"], list)
    assert r["chain_count"] == len(r["chains"])
    assert r["sources_used"] and r["sinks_used"]
    assert "note" in r

    # Drive the decompile+slice path: treat real imports as sinks so the scan
    # actually finds call sites and decompiles their callers.
    imports = send_request(
        "imports", target=program_id, instance_id=running_agent,
    )["result"]
    names = [i["name"] for i in imports if i.get("name")][:15]
    if names:
        res = send_request(
            "taint_forward", params={"sinks": ",".join(names)},
            target=program_id, instance_id=running_agent, timeout=120.0,
        )
        assert res["ok"] is True
        assert res["result"]["scanned_functions"] >= 1
        assert isinstance(res["result"]["chains"], list)


def test_callsites_libc_name_not_ambiguous(running_agent):
    """A libc name resolves to a .plt thunk AND the EXTERNAL symbol; callsites
    must union them (real callers) instead of raising ambiguous_function."""
    load = send_request(
        "load_binary", params={"path": "/bin/true"},
        instance_id=running_agent, timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    imports = send_request(
        "imports", target=program_id, instance_id=running_agent,
    )["result"]
    names = [i["name"] for i in imports if i.get("name")]
    assert names, "no imports found in /bin/true"

    # At least one imported libc name must resolve through callsites without an
    # ambiguity error and return the documented shape.
    ok_any = False
    for name in names[:20]:
        resp = send_request(
            "callsites", params={"identifier": name},
            target=program_id, instance_id=running_agent,
        )
        assert resp["ok"] is True, f"callsites {name} errored: {resp}"
        assert "callsites" in resp["result"]
        # No site may be the thunk's own internal trampoline (caller == callee).
        for site in resp["result"]["callsites"]:
            assert site.get("caller") != site.get("callee")
        ok_any = ok_any or bool(resp["result"]["callsites"])
    assert ok_any, "no callsites resolved for any imported name"


_TAINT_FIXTURE_C = r"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
void f_stack_array(FILE *fp){char buf[128],dst[128];fgets(buf,sizeof buf,fp);strcpy(dst,buf);puts(dst);}
void f_heap_ptr(int fd){char *buf=malloc(256),dst[256];read(fd,buf,256);memcpy(dst,buf,100);puts(dst);}
void f_getline(FILE *fp){char *line=NULL,dst[256];size_t n=0;getline(&line,&n,fp);strcpy(dst,line);puts(dst);free(line);}
void f_no_chain(FILE *fp){char a[128],b[128],dst[128];fgets(a,sizeof a,fp);memset(b,0,sizeof b);strcpy(dst,b);puts(dst);}
/* interprocedural: getline in ip_reader -> ip_process -> ip_copy(memcpy) */
void ip_copy(char *dst,char *src,size_t n){memcpy(dst,src,n);}
void ip_process(char *buf){char dst[256];ip_copy(dst,buf,128);puts(dst);}
void ip_reader(FILE *fp){char *line=NULL;size_t n=0;getline(&line,&n,fp);ip_process(line);free(line);}
int main(int c,char**v){(void)c;(void)v;f_stack_array(stdin);f_heap_ptr(0);f_getline(stdin);f_no_chain(stdin);ip_reader(stdin);return 0;}
"""


def test_taint_forward_out_buffer_source(running_agent, tmp_path):
    """A source that writes through an out-parameter (fgets/read/getline) is a
    taint origin: the sink reading that buffer must chain via 'out_buffer'.
    Covers a stack array, a heap pointer, and getline's char** double pointer;
    f_no_chain (source taints `a`, sink reads `b`) must NOT produce a chain."""
    import shutil
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc not available to build the taint fixture")
    src = tmp_path / "tt.c"
    src.write_text(_TAINT_FIXTURE_C)
    binp = tmp_path / "tt"
    cp = subprocess.run(
        [gcc, "-O0", "-fno-stack-protector", "-fno-inline", "-o", str(binp), str(src)],
        capture_output=True, text=True,
    )
    if cp.returncode != 0:
        pytest.skip(f"fixture build failed: {cp.stderr[:200]}")

    load = send_request(
        "load_binary", params={"path": str(binp)},
        instance_id=running_agent, timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    res = send_request(
        "taint_forward", target=program_id, instance_id=running_agent, timeout=120.0,
    )["result"]
    chains = res["chains"]

    # Every positive function must yield an out_buffer chain.
    by_fn = {}
    for c in chains:
        by_fn.setdefault(c["function"]["name"], []).append(c)
    for fn in ("f_stack_array", "f_heap_ptr", "f_getline"):
        outs = [c for c in by_fn.get(fn, []) if c.get("via") == "out_buffer"]
        assert outs, f"{fn}: expected an out_buffer chain, got {by_fn.get(fn)}"

    # The negative control must NOT chain (source buffer != sink buffer).
    assert not by_fn.get("f_no_chain"), (
        f"false positive in f_no_chain: {by_fn.get('f_no_chain')}"
    )

    # Intraprocedural alone must NOT cross ip_reader -> ip_process -> ip_copy.
    ip = [c for c in chains if c["function"]["name"] == "ip_copy"]
    assert not ip, f"intraprocedural should not catch the cross-function chain: {ip}"

    # With --interprocedural the getline->memcpy chain (3 frames) appears, and
    # the negative control still does not.
    ipres = send_request(
        "taint_forward", params={"interprocedural": True, "ip_depth": 4},
        target=program_id, instance_id=running_agent, timeout=120.0,
    )["result"]
    ipchains = [c for c in ipres["chains"] if c.get("interprocedural")]
    ipcopy = [c for c in ipchains
              if c["function"]["name"] == "ip_copy" and c["source"] == "getline"]
    assert ipcopy, f"expected interprocedural getline->memcpy chain, got {ipchains}"
    assert ipcopy[0].get("path"), "interprocedural chain should carry a frame path"
    assert not any(c["function"]["name"] == "f_no_chain" for c in ipres["chains"]), (
        "interprocedural must not introduce a false chain in f_no_chain"
    )


def test_xrefs_by_name_unions_thunks(running_agent):
    """A libc name resolves to BOTH a .plt thunk and the EXTERNAL stub; xrefs by
    name must union their references (like callsites, and like `bn xrefs`)
    instead of raising ambiguous_function."""
    load = send_request(
        "load_binary", params={"path": "/bin/true"},
        instance_id=running_agent, timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    imports = send_request(
        "imports", target=program_id, instance_id=running_agent,
    )["result"]
    # A name that appears as both an external symbol and a thunk is the
    # ambiguous case that used to error.
    by_name: dict[str, set] = {}
    for r in imports:
        by_name.setdefault(r["name"], set()).add(bool(r.get("is_thunk")))
    ambiguous = [n for n, kinds in by_name.items() if kinds == {True, False}]

    checked = 0
    for name in (ambiguous or [r["name"] for r in imports])[:10]:
        resp = send_request(
            "xrefs", params={"identifier": name},
            target=program_id, instance_id=running_agent,
        )
        assert resp["ok"] is True, f"xrefs {name} errored: {resp}"
        assert "incoming" in resp["result"]
        checked += 1
    assert checked, "no import names to exercise xrefs-by-name"


def test_function_list_hides_external_block_by_default(running_agent):
    """bn omits Ghidra's synthetic EXTERNAL-block import thunks from the function
    list; ghx must match by default and expose them only via --include-externals."""
    load = send_request(
        "load_binary", params={"path": "/bin/true"},
        instance_id=running_agent, timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    default = send_request(
        "list_functions", params={"limit": 100000},
        target=program_id, instance_id=running_agent,
    )["result"]
    with_ext = send_request(
        "list_functions", params={"limit": 100000, "include_externals": True},
        target=program_id, instance_id=running_agent,
    )["result"]

    default_addrs = {r["address"] for r in default}
    ext_addrs = {r["address"] for r in with_ext}
    # Default is always a subset of the full Ghidra view.
    assert default_addrs <= ext_addrs
    # The EXTERNAL block lives at the top of the address space; every function
    # the flag adds back must sit in a block named EXTERNAL, and none may leak
    # into the default list.
    added = ext_addrs - default_addrs
    blocks = send_request(
        "py_exec",
        params={"code": (
            "mem = currentProgram.getMemory()\n"
            "af = currentProgram.getAddressFactory()\n"
            "result = {a: (lambda b: b.getName() if b else None)("
            "mem.getBlock(af.getAddress(a))) for a in " + repr(sorted(added)) + "}"
        )},
        target=program_id, instance_id=running_agent,
    )["result"]["result"]
    if added:
        assert all(name == "EXTERNAL" for name in blocks.values()), blocks
    # Inversely, no default function may be an EXTERNAL-block entry.
    default_blocks = send_request(
        "py_exec",
        params={"code": (
            "mem = currentProgram.getMemory()\n"
            "af = currentProgram.getAddressFactory()\n"
            "result = [a for a in " + repr(sorted(default_addrs)) + " "
            "if (lambda b: b and b.getName() == 'EXTERNAL')("
            "mem.getBlock(af.getAddress(a)))]"
        )},
        target=program_id, instance_id=running_agent,
    )["result"]["result"]
    assert default_blocks == [], default_blocks


def test_strings_excludes_metadata_blocks_by_default(running_agent):
    """ELF metadata blocks (.shstrtab/.gnu_debuglink/section headers) live in
    non-loaded overlay spaces; bn never reports strings there, so ghx hides them
    unless --include-metadata (or an explicit --section) is given."""
    load = send_request(
        "load_binary", params={"path": "/bin/true"},
        instance_id=running_agent, timeout=120.0,
    )
    program_id = load["result"]["program_id"]

    default = send_request(
        "strings", params={"limit": 100000},
        target=program_id, instance_id=running_agent,
    )["result"]
    with_meta = send_request(
        "strings", params={"limit": 100000, "include_metadata": True},
        target=program_id, instance_id=running_agent,
    )["result"]

    def key(rows):
        return {(r.get("section"), r["address"], r["value"]) for r in rows}

    assert key(default) <= key(with_meta)
    # Every string the default view drops must come from a non-loaded block.
    dropped_sections = {sec for (sec, _a, _v) in key(with_meta) - key(default)}
    if dropped_sections:
        loaded = send_request(
            "py_exec",
            params={"code": (
                "mem = currentProgram.getMemory()\n"
                "result = {b.getName(): bool(b.isLoaded()) for b in mem.getBlocks()}"
            )},
            target=program_id, instance_id=running_agent,
        )["result"]["result"]
        for sec in dropped_sections:
            assert loaded.get(sec) is False, (sec, loaded)


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
