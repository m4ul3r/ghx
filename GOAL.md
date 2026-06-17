# GOAL.md — ghx ⇄ bn feature parity

> Hand this file back to Claude any session to keep working. It is the single
> source of truth for *what "done" means* and *what to do next*. Update the
> **Progress ledger** at the bottom every cycle.

## Mission

`ghx` is the Ghidra-backed twin of `bn` (the Binary Ninja agent CLI). The north
star is **full feature + ergonomic parity with `bn`**: an agent that knows how to
drive `bn` should be able to drive `ghx` with the same mental model and get
semantically equivalent answers. We are *not* chasing byte-identical output — the
two engines differ — we are chasing **the same command surface, the same agent
workflows, and the same or better signal per call.**

When this is achieved, an RE/VR agent should never care which engine is behind
the CLI.

## Operating rules — READ FIRST

1. **Secrecy (non-negotiable).** The dogfood target is sensitive. **Never** put
   real binary names, function names, paths, strings, or addresses-tied-to-names
   into anything tracked: commits, PR titles/bodies, code comments, this file,
   skills, or test fixtures. Use **aliases only**:
   - Filesystem root → `fw-A` (real path lives in `.dogfood/target.md`, gitignored).
   - Individual binaries → `fw-A/bin-1`, `fw-A/svc-1`, …
   - If you need to record a real address/name for a cycle, it goes in
     `.dogfood/<date>/…` (gitignored), never in tracked files.
2. **Dogfood, don't theorize.** Every parity claim is proven by running the
   command against `fw-A` and comparing to `bn`. "It should work" is not done.
3. **No stubs / no hacks.** Per repo CLAUDE.md: fix root causes, solve generally,
   verify before claiming done. A parity item is done only with evidence.
4. **Keep the CLI Ghidra-free.** `src/ghx/` imports no Ghidra. All engine work
   lives in `plugin/ghx_agent_bridge/bridge.py`. (See repo `CLAUDE.md`.)

## The loop (do this every session)

```
1. Pick the highest-priority unchecked item from the Backlog.
2. Reproduce the gap: run the bn version and the ghx version against fw-A,
   capture both outputs to .dogfood/<date>/ (gitignored).
3. Implement on the bridge + CLI (see "Adding an op" in CLAUDE.md).
4. Add/extend a parser-acceptance test (tests/test_cli_parser.py) and an
   integration check if it touches Ghidra state.
5. uv run pytest   (and  uv run pytest -m integration  when relevant).
6. Re-run the A/B dogfood; confirm ghx now matches bn's shape/signal.
7. Tick the box, append a one-line Progress-ledger entry, commit (sanitized).
8. Repeat.
```

Work top-down by priority. Prefer a few fully-verified items over many
half-done ones.

## Parity philosophy — how to map two engines

| bn concept | ghx / Ghidra equivalent | Parity = |
|---|---|---|
| HLIL / MLIL / LLIL | high p-code / raw p-code (PcodeOp) | same `il` surface, `--view`/`--form` cover both ladders, `--ssa` where meaningful |
| SSA use-def (`trace`, `dataflow defuse`) | Ghidra HighFunction Varnode SSA | same query shape + origin-kind taxonomy |
| value-set | SymbolicPropogator constants | same `dataflow values` contract (honest about single-constant limits) |
| caller_static | call-site return-address mapping | `callsites --caller-static` text mode |
| Binary Ninja types | Ghidra DataTypeManager | same `types`/`struct`/`local`/`proto` editing surface |

When an exact equivalent doesn't exist, parity means **same agent task is
achievable with the same number of calls and comparable signal** — document the
mapping, don't fake the feature.

## Parity is measured by AGREEMENT, not flag-matching (read this)

Matching command names + flags is the easy 80% and was mostly already built.
**Real parity = bn and ghx return semantically equivalent ANSWERS on the same
binary.** A command can have identical `--help` and still disagree. Proven by an
A/B run on `fw-A/bin-1` (2026-06-17, see ledger).

Baseline (first run) — every probe diverged:

| metric | bn | ghx (before) | root cause |
|---|---|---|---|
| functions | 51 | 79 | ghx listed 28 synthetic EXTERNAL-block import thunks |
| imports (by name) | 28 | 28 | (already agreed — the 59/84 raw gap was thunk-row inflation) |
| strings | 104 | 125 | ghx scanned ELF metadata blocks (.shstrtab/debuglink/sec-hdrs) |
| sections | 25 | 28 | memory-block vs section modeling |

After this cycle — three probes reconciled:

| metric | bn | ghx (after) | status |
|---|---|---|---|
| functions | 51 | 51 | **AGREE on count**; sets differ by 1 each way — both are single-instruction CRT/padding stubs (a lone `ret` / `nop`); bidirectional engine heuristic, documented |
| imports (by name) | 28 | 28 | **AGREE** |
| strings | 104 | 100 | metadata noise removed (ghx-only 27→2); residual ghx-only 2 = ELF-header/`.note` bytes, residual bn-only 6 = strings Ghidra never defined (analysis gap) |
| sections | 25 | 28 | DIVERGES — synthetic-block naming (`EXTERNAL`/`.shstrtab` vs `.extern`/`.synthetic_builtins`); **documented engine difference** |
| xrefs (callers, 28 import seeds) | 95 | 95 | **AGREE** on code-ref callers (26/28 seeds exact); the 2 residuals are CRT-startup glue; ghx additionally surfaces 29 GOT/PLT data-slot relocations (bn buckets these as `data_ref_count`) |
| decompile | 216 lines | 139 lines | engine difference (naming/types/line count) — DOCUMENT, verify logic not bytes |

Every "[x]" below means the **surface** matches. A "[x]" in P0(real) additionally
means the *answer* agrees with bn (or the divergence is a documented engine
difference). Re-grade against this A/B bar.

## Status snapshot (2026-06-17)

- **Surface parity (commands/flags/output-shape): ~done.** Every `bn` verb exists
  in `ghx` except `plugin` (GUI extension — out of scope). Option-level gaps,
  friction-log signal issues, and P2 surface are closed (see ledger).
- **Out-of-box auto-spawn: FIXED** (`/tmp/ghx-projects/<id>`).
- **Semantic parity: ESTABLISHED for the basic queries (cycle 1).** A/B-verified
  agreement now holds for `imports`, `functions` (count, after hiding EXTERNAL-block
  thunks), `strings` (after dropping metadata-block noise), and `xrefs` callers
  (26/28 import seeds exact). Remaining divergences are documented engine
  differences (`sections` block naming, `decompile` naming/types/line-count, a
  handful of bidirectional single-instruction-stub / CRT-glue / string-analysis
  gaps). The real remaining work is **dataflow depth** (taint out-buffer source,
  interprocedural trace/taint) and **running the harness on a corpus**, not just
  one 13KB binary.

## P0(real) — semantic reconciliation (the actual parity work)

Build the A/B harness and drive each command's answer to agree with bn, or
document why it can't (genuine engine difference). Until this is done, parity is
unproven regardless of how many flags match.
- [x] **A/B harness** — `tools/ab_parity.py <binary>`. Starts an isolated bn
  instance (never touches the ~20 sensitive ones), loads the same binary in both,
  and diffs address/name sets per command (addresses are ground truth). First run
  on `fw-A/bin-1` root-caused every divergence below. Now covers 5 probes:
  list-style (functions/imports/strings/sections) plus a **seeded** `xrefs` probe
  that, per shared import name, diffs the caller-address set (splitting code refs
  from GOT/PLT data slots). `--probe NAME` runs a subset.

Root-caused divergences (from the 2026-06-17 A/B run — each is now a concrete fix
or a documented engine difference):
- [x] **functions (bn 51 / ghx 79 → 51).** ghx over-counted 28 synthetic thunks in
  Ghidra's `EXTERNAL` block (`is_thunk=true`, size 1). FIXED: `function
  list/search` now hide EXTERNAL-block entries by default (matching bn's notion);
  `--include-externals` restores the full Ghidra view. Filter is by memory-block
  name so the 29 *real* `.plt` thunks bn also lists are kept. Residual set diff is
  1 each way — bn made a function at a lone `ret` Ghidra left as an undefined byte;
  ghx wrapped a lone `nop` in a `FUN_` bn ignored. Both are single-instruction
  CRT/padding stubs — a bidirectional engine heuristic, DOCUMENTED, not a bug.
- [x] **imports (bn 28 / ghx 28 by name).** AGREE in a clean A/B. The earlier
  `bn=30` (with `stderr`/`__stack_chk_guard`) did NOT reproduce in a freshly-loaded
  isolated bn instance — it was an analysis-timing/state artifact of the prior bn
  process, not a ghx gap. Lesson: A/B both engines from a clean load. (The raw
  84-vs-59 count gap was always just thunk-row inflation; compare by unique name.)
- [x] **strings (bn 104 / ghx 125 → 100).** ghx scanned ELF METADATA blocks
  (`.shstrtab`/`.gnu_debuglink`/`_elfSectionHeaders` — overlay spaces where
  `isLoaded()==False`). FIXED: `strings` defaults to the loaded image only;
  `--include-metadata` (or an explicit `--section`) restores them. ghx-only noise
  27→2. Residual: 2 ghx-only (ELF-header/`.note.ABI-tag` bytes in loaded segments,
  borderline) + 6 bn-only (real strings Ghidra's analyzer never defined — an
  analysis-depth gap; would need extra string detection to close). DOCUMENTED.
- [~] **sections (bn 25 / ghx 28).** Synthetic-block naming differs (ghx exposes
  `EXTERNAL`, `_elfSectionHeaders`, `.shstrtab`, `.note.ABI-tag`, `segment_2.1`; bn
  exposes `.extern`, `.synthetic_builtins`, `.dynamic_rela`). This is how each
  engine *names* the same underlying layout — a DOCUMENTED engine difference. An
  agent gets equivalent structural info either way. NOT filtering: `sections` is a
  structural view where completeness beats noise-reduction (unlike `strings`).
- [x] **xrefs (callers).** Harness extended to seed per shared import and diff
  caller-address sets. Result: 26/28 seeds AGREE exactly on code-ref callers
  (bn=95 / ghx=95 shared). The harness ALSO surfaced + we fixed a real bug:
  `xrefs <name>` raised `ambiguous_function` when a libc name matched both the
  `.plt` thunk and the `EXTERNAL` stub — it now unions refs across both (mirroring
  `callsites`, matching `bn xrefs <name>`), reporting `matched_targets`. ghx still
  surfaces GOT/PLT *data*-slot relocations bn omits from its caller list (bn keeps
  a separate `data_ref_count`); the harness buckets those as a note, not a
  disagreement. The 2 residual code-ref diffs are CRT-startup glue (a `bl abort`
  from `entry`; a `__gmon_start__` GOT pointer-load) — DOCUMENTED.
  NB: bn `callsites` REQUIRES a scope (`--within`/`--within-file`); its
  whole-program "callers of X" is `bn xrefs <name>`. ghx `callsites <name>` is
  whole-program by default — both reach the same answer, mapped via xrefs here.
- [ ] **decompiler/types.** Naming (`sub_` vs `FUN_`), inferred return types
  (`uint64_t` vs `void`), line counts (216 vs 139) differ — engine difference.
  Verify the same *logic* is recovered, document rather than force byte-equality.
- [ ] **Run on a corpus, not one 13KB binary.** Multiple arches/sizes. The harness
  is generic (`tools/ab_parity.py <binary>`); only the dogfood target has been run.

## Backlog (prioritized, grounded in the dogfood friction log + option diff)

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · each item names the
concrete bn behavior to match.

### P0 — out-of-box reliability
- [x] Auto-spawn ephemeral project path bug (dotted `.cache` element rejected by
  Ghidra ProjectLocator). Fixed in `2d979bf`; verified `ghx doctor` cold start.
- [x] `doctor`/auto-spawn surfaces a clear cause when the daemon dies on spawn.
  `transport._spawn_failure_detail` now bubbles the fatal log tail (error-marker
  lines + recent stack frames) inline into the `BridgeError`, instead of "check
  the log". Covered by `tests/test_transport.py`.
- [x] `doctor` reports stale bridge build: the text renderer already emits a
  `WARN` with the daemon-vs-current build IDs and a "Run `ghx session stop` and
  retry" remediation (`cli.py:_render_doctor`).

### P1 — VR-core depth (the reason this tool exists; friction log rows 5-8,12)
- [x] **Forward-taint out-buffer source.** DONE (intraprocedural). `taint forward`
  now models out-parameter writes as taint origins: `read/pread/recv/recvfrom/
  readlink`=arg1, `fgets/gets/fread`=arg0, `getline/getdelim`=arg0 (`char **`).
  A sink arg referring to such a buffer chains with `via:"out_buffer"` (existing
  return-value chains now carry `via:"return_value"`). Matching is by buffer
  identity (`_buffer_keys`): the variable's storage id, plus a `&stackvar`
  `PTRSUB((register,_,_),OFF)` resolved through the function's stack-symbol map —
  empirically the PTRSUB offset equals the `Stack[OFF]` storage offset on both
  x86-64 (frame reg 0x20) and AArch64 (0x8), so getline's `&line`→`line` resolves
  arch-robustly. A shallow expansion (`_buffer_keys_expanded`, COPY/CAST + ptr
  +const) covers `buf+off`, deliberately NOT crossing PTRSUB bases / phi / non-
  const adds (those would over-connect). Ordering heuristic: source_addr < sink.
  **Verified** on a built x86-64 fixture (`.dogfood/taint-fixture/`, gitignored):
  3 patterns chain (stack array `fgets→strcpy`, heap pointer `read→memcpy`,
  getline double-pointer `getline→strcpy`); the negative control (source taints
  `a`, sink reads `b`) yields NO chain; and `fw-A/bin-1` still honestly reports 0
  (its only chain is interprocedural — see below). Integration test compiles its
  own fixture (skips without gcc); the honest `note` is retained.
- [x] **`taint forward` interprocedural.** DONE + verified on a fixture, with a
  documented decompiler-limited miss on bin-1. `taint forward --interprocedural
  [--ip-depth N]` (default 3): when a sink arg derives from a PARAMETER, it walks
  UP the call graph — at each caller mapping the parameter to the actual arg and
  re-checking for a source (return_value or out_buffer) — and emits a chain with
  the frame `path`. Conservative by construction: it uses the decompiler's own
  arg/param model, so missed signatures UNDER-report rather than fabricate. Also
  fixed a thunk-trampoline duplicate (sink-site discovery now skips thunk bodies).
  **Verified** on a built 3-frame fixture (`getline` in `ip_reader` → `ip_process`
  → `ip_copy`'s `memcpy`): caught with the full path, negative control still
  clean. **bin-1 honestly reports 0** even interprocedurally — ROOT CAUSE: the
  decompiler recovered the `FUN_004015e0 → FUN_004012b0 @0x401634` call site as
  taking **0 arguments** (`nargs=0`) though the callee is `FUN_004012b0(char *)`
  and its `memcpy` copies that very `param_1`. With no parameter seam at that
  frame there is nothing to follow — a Ghidra calling-convention/signature
  recovery limitation, NOT a taint bug. Closing it needs deeper param-ID analysis
  (see `decompile --force-analysis`) or register-level taint, both out of scope.
- [x] **`taint forward` output shape.** JSON is key-sorted (so `chain_count`/
  `chains` already lead); the real problem was the *size* of the sources/sinks
  echo. Now rendered as compact single-line strings + explicit
  `source_count`/`sink_count`, shrinking the whole default object to ~11 lines so
  `| tail` shows the full signal. Text mode already prints a one-line summary.
- [x] **`taint forward --function` semantics.** Already handled: when the scoped
  function has no sink calls the `note` says "contains no calls to any configured
  sink (N checked) — nothing to scan", distinguishing it from "scanned, 0 chains".
  Verified on `fw-A/bin-1`.
- [x] **`callsites <libc-name>` thunk ambiguity.** Already resolved:
  `_op_callsites` uses `_resolve_functions` (plural) and unions call sites across
  all matched thunks/symbols, dropping thunk→EXTERNAL trampolines and returning
  `matched_targets`. Verified `callsites memcpy/strlen/snprintf/mount` on
  `fw-A/bin-1` — no ambiguity error.
- [x] **`callsites --caller-static`** — added. Text mode leads with each call's
  static return address; JSON now carries a bn-compatible `caller_static` field
  (= instruction-after-call). Verified on `fw-A/bin-1`.
- [x] **`dataflow values` frame-register noise.** Added `--no-frame` to drop
  stack/frame/link/pc registers (sp, fp, lr, pc, x29, x30, rbp/rsp/rip, …). On
  `fw-A/bin-1` it cut `sp/x29/x30` from the output, leaving the meaningful
  `x0/x1/x19/x23/x27`.
- [~] **`trace` depth flags.** Added `--max-depth` (bounds the SSA slice;
  verified truncation on `fw-A/bin-1`). Still TODO: `--interprocedural`/
  `--ip-depth` (follow return values across call boundaries) — a larger item.
  `--view {mlil,hlil}` has no clean Ghidra analogue (the slice runs on high
  p-code only); documented as N/A rather than faked.
- [x] **`taint backward` arg model** — added `--max-depth` (shared
  `_send_taint_backward`, maps to the op's `max_steps`). ghx's
  `--at/--arg/--variable` is the working analogue of bn's
  `--function/--sink`; verified on `fw-A/bin-1`.

### P1 — listing / paging / filtering ergonomics (mechanical, recurring)
bn gives every list command `--count`, `--limit`, `--offset`, and a query/regex.
ghx is missing these in several places:
- [x] `strings`: added `--regex` (case-insensitive) and `--count`. Matching now
  runs against the *decoded* string content (`_decoded_string_value`), so
  anchored regexes like `^/lib` / `\.so` work instead of hitting Ghidra's
  C-literal quoting. `--count` returns `{"count": N}`; `--count` + `--no-crt`
  counts the client-side-filtered set. Verified on `fw-A/bin-1`.
- [x] `xrefs`: added `--limit` / `--offset` paging on inbound refs, with an
  `incoming_total` (and `code_refs_total` for `--field`) so paging is visible
  ("N of M" in text). Refs are address-sorted for stable pages. Verified on
  `fw-A/bin-1`.
- [x] `imports`: added `--count`, `--limit`, `--offset`, `--summary`. `--summary`
  aggregates `by_kind` (external/thunk) + `by_library`, which directly answers
  the friction-log "3 rows per symbol" verbosity (28 external / 56 thunks on
  `fw-A/bin-1`). Verified.
- [x] `sections`: added `--count`, `--limit`, `--offset` (address-sorted pages).
  Verified on `fw-A/bin-1`.
- [x] `function list`: added `--count` and `--sort {address,name,size}` (size is
  descending — biggest first). Verified on `fw-A/bin-1` (79 functions; top-5
  by size).
- [x] `function search`: added `--exact` (case-sensitive, mutex with `--regex`),
  `--min-address`/`--max-address`, and `--sort`. Render now shows size. Verified
  on `fw-A/bin-1`.
- [x] `evidence xrefs`: added `--limit`/`--offset` (threads through `_op_xrefs`
  paging; keeps `incoming_total`). `evidence init`: added `--limit` (caps entries
  per section, keeps full `count`, flags `truncated`). Verified on `fw-A/bin-1`.
- [ ] `types`: bn exposes group-level `--count/--limit/--offset/--query`; ghx
  exposes these on the `types list` subcommand instead. Confirm the agent
  workflow is equivalent or align the surface.

### P1 — IL / decompile / disasm slicing
- [x] `il`: added `--lines START:END` slicing (keeps large IL inline instead of
  spilling). `--form high` is documented as the Ghidra analogue of bn's
  `--ssa hlil/mlil` (Ghidra high p-code is already SSA). A literal `--view`/
  `--ssa` alias remains a small naming follow-up.
- [x] `disasm`: added `--lines START:END`. Verified on `fw-A/bin-1` (sliced
  output stays inline; full disasm JSON otherwise spills at ~30KB).
- [x] `function structured-il`: `--form {raw,high}` is the functional equivalent
  of bn's `--view`/`--no-ssa`/`--ssa` (raw = non-SSA per-instruction p-code,
  high = SSA decompiler p-code); help text now documents the mapping.
- [ ] `decompile`: bn has `--force-analysis` (override Ghidra's skip on huge
  funcs and reanalyze). ghx has `--timeout`; add `--force-analysis` equivalent.

### P2 — session / instance management
bn unifies lifecycle under `instance {start,stop,restart,list,use,clear,prune}`
and mirrors `session`. ghx splits: `session {list,start,stop,restart}` +
`instance {use,clear,prune}`.
- [ ] `session prune` — add (with `--dry-run`, `--idle`, `--include-gui`,
  `--include-sticky` to match bn).
- [ ] `instance` — add `list/start/stop/restart` (or alias to `session`) so the
  two command names are interchangeable like bn's.
- [ ] `instance prune` — add `--dry-run`, `--include-gui`, `--include-sticky`.

### P2 — misc option parity
- [x] `close --all` (closes every loaded program; returns `{closed:[...],count}`).
  Verified on `fw-A/bin-1` (caught + fixed a duplicate-`close_all` shadowing bug
  via dogfooding).
- [x] `read --encoding {hex,bytes}` and `--address` alias. `--encoding bytes`
  writes raw bytes to `--out` or stdout. Verified on `fw-A/bin-1`.
- [x] `save --path` alias for the positional output path.
- [ ] `comment` — reconcile ghx `--kind`/`--kinds` naming with bn (`comment list
  --query`).
- [ ] `target info --verbose`.
- [ ] `evidence {function,table,message}` — reconcile remaining flag diffs
  (`--context`, `--entries`/`--stride`, `--table-entries`). Audit each against bn.
- [x] `strings` value field now matches bn: `value` is the raw decoded string
  (`libc.so.6`), with Ghidra's C-literal kept as `repr` (`u8"libc.so.6"`) and the
  prefix split into `encoding`. Verified on `fw-A/bin-1` (`value='libc.so.6'
  repr='u8"libc.so.6"' encoding='u8'`).

### Out of scope (do NOT implement without a new decision)
- `plugin` — Binary Ninja's GUI companion-plugin installer. ghx's phase-2 GUI
  extension (a Java Ghidra plugin hosting the same socket server in a live GUI)
  is deliberately deferred. See repo `CLAUDE.md` → "Not yet implemented".
- True in-project `saveAs` to a new DomainFile path (only `.gzf` export is wired).

## Definition of Done (per backlog item)

An item is `[x]` only when ALL hold:
1. The ghx command/flag exists and its `--help` reads like bn's.
2. Running it against `fw-A` produces output **semantically equivalent** to bn's
   on the same binary (shape, field names where sensible, ordering, signal).
3. A parser-acceptance case exists in `tests/test_cli_parser.py`.
4. If it touches Ghidra state: an integration test covers it, and
   `uv run pytest -m integration` passes.
5. `uv run pytest` is green.
6. The A/B comparison is recorded in the Progress ledger (sanitized).

## Verification protocol (dogfood A/B)

```sh
# Bind alias → real path is in .dogfood/target.md (gitignored). Resolve there.
B=fw-A/bin-1            # real path resolved locally, never echoed into tracked files
D=.dogfood/$(date +%F)  # gitignored scratch for this cycle

# Compare a command across engines (example: imports):
bn  imports -t "$B" --format json --out "$D/bn-imports.json"
ghx imports -t "$B" --format json --out "$D/ghx-imports.json"
# Diff the SHAPE (keys/counts/ordering), not engine-specific values.
```

Both daemons can stay warm across a session; a `ghx` daemon with `fw-A/bin-1`
already loaded speeds the loop. Keep all captured artifacts under `.dogfood/`.

## Reference — where things live (see repo `CLAUDE.md` for depth)

- `src/ghx/cli.py` — `@command()` registry; per-command text renderers. Common
  options (`--format/--out/--instance/-t/--target`, paging, address filters) are
  plumbed by the framework.
- `plugin/ghx_agent_bridge/bridge.py` — daemon: JVM, socket server,
  `TargetManager`, `_run_mutation`, all `_op_*` handlers. Read/Write lock sets:
  `READ_LOCKED_OPS` / `WRITE_LOCKED_OPS`.
- `src/ghx/transport.py` — socket client, discovery, auto-spawn.
- `src/ghx/output.py` — token spill (10k) + artifact envelope.
- `tests/test_cli_parser.py` — parser acceptance. Integration tests auto-skip
  without a Ghidra install.
- **Adding an op:** follow the 6-step checklist in `CLAUDE.md` → "Adding a new op".

## Progress ledger (append one line per cycle — newest first)

- 2026-06-17 — **VR-core: interprocedural forward taint.** `taint forward
  --interprocedural [--ip-depth N]` follows a sink arg that derives from a
  parameter UP the call graph (mapping param→actual-arg at each caller) to a
  source in an ancestor frame, emitting the frame `path`. Conservative (uses the
  decompiler's arg/param model → misses, never false chains). Fixed a
  thunk-trampoline duplicate (skip thunk bodies in sink-site discovery). Verified
  on a built 3-frame fixture (getline→…→memcpy caught with path; negative control
  clean). bin-1 honestly reports 0: the decompiler recovered the key call site
  `FUN_004015e0→FUN_004012b0` as `nargs=0`, so there's no parameter seam to
  follow — a Ghidra signature-recovery limit, not a bug. +2 parser cases,
  integration test extended; 181 unit green.
- 2026-06-17 — **VR-core: forward-taint out-buffer source (intraprocedural).**
  `taint forward` now treats a source's written out-buffer as a taint origin
  (out-arg map: read/recv=arg1, fgets/fread=arg0, getline/getdelim=arg0 char**),
  emitting `via:"out_buffer"` chains (return-value chains now `via:"return_value"`).
  Buffer matching (`_buffer_keys`/`_buffer_keys_expanded`) keys by storage id and
  `&stackvar` PTRSUB offset resolved through the stack-symbol map (verified the
  PTRSUB↔Stack offset convention on x86-64 AND AArch64). Verified on a built
  fixture (3 positive patterns + a negative control that must NOT chain); bin-1
  still honestly reports 0. KEY FINDING: bin-1's getline→memcpy chain is
  INTERprocedural (no function calls both a source and a sink), so the
  intraprocedural model can't catch it — that now gates on interprocedural taint
  (next item). +1 integration test (compiles its own fixture, skips w/o gcc);
  179 unit green.
- 2026-06-17 — **Semantic reconciliation, cycle 1 (fix against the A/B bar).**
  Drove 3 of 4 structural probes to AGREEMENT and extended the harness:
  (1) `function list/search` hide EXTERNAL-block synthetic thunks by default
  (`--include-externals` opts in) — functions 79→51, matches bn's 51; residual
  1-each-way is single-instruction CRT/padding stubs (documented).
  (2) `strings` defaults to the loaded image (`--include-metadata` opts in) —
  ghx-only noise 27→2; residual 6 bn-only is a Ghidra string-analysis gap.
  (3) imports confirmed AGREE in a clean A/B (earlier bn=30 was an analysis-timing
  artifact, not a ghx bug).
  (4) Extended `ab_parity.py` with a seeded `xrefs` probe (per shared import, diff
  caller-address sets, code-refs vs GOT/PLT data slots) → 26/28 seeds AGREE on
  callers. The probe surfaced a real bug: `xrefs <name>` raised
  `ambiguous_function` for libc names matching a `.plt` thunk + `EXTERNAL` stub;
  FIXED to union refs (mirrors `callsites`, matches `bn xrefs`), emits
  `matched_targets`. sections + decompile remain documented engine differences.
  179 unit green; +5 new parser cases; +3 new integration tests (function/strings
  default-filter, xrefs union) all green; full integration suite (17) green.
- 2026-06-17 — Built `tools/ab_parity.py` and root-caused all 4 structural
  divergences via address-set diffs: functions = ghx over-counts EXTERNAL thunks
  + misses 0x401d40 that bn found; imports = ghx misses data symbols (stderr,
  __stack_chk_guard); strings = ghx includes .shstrtab/.gnu_debuglink metadata
  noise; sections = synthetic-block modeling diff. Each now a concrete fix in
  P0(real). This is what "understand the differences" produced.
- 2026-06-17 — **Reality check (skeptic prompt).** Ran the first true A/B: same
  binary in an isolated bn instance vs ghx. Counts DIVERGE (funcs 51/79, imports
  59/84, strings 104/125, sections 25/28; decompile 216/139 lines, differing
  return types). Conclusion: surface parity ≠ semantic parity; the latter is
  unproven. Reframed GOAL.md — added the "agreement, not flag-matching" bar and a
  P0(real) semantic-reconciliation workstream. The 9 prior commits are real
  surface/ergonomics work, not parity.

- 2026-06-17 — Documented `structured-il --form` ↔ bn `--view/--ssa/--no-ssa`
  mapping; recorded the full out-buffer-taint design (out-arg map, HighVariable
  matching, getline double-pointer, ordering heuristic) for a focused pass.
- 2026-06-17 — `trace`/`taint backward --max-depth` (bounds the SSA slice; maps to
  the op's max_steps). Verified truncation on `fw-A/bin-1`. trace
  `--interprocedural` still pending. 174 green.
- 2026-06-17 — P2 surface: `close --all`, `read --address`/`--encoding {hex,bytes}`,
  `save --path` alias. Dogfooding caught a duplicate-`close_all` method shadowing
  bug (returned None) — fixed. 172 green.
- 2026-06-17 — `evidence xrefs --limit/--offset` (through `_op_xrefs` paging) and
  `evidence init --limit` (per-section entry cap with `truncated`). 168 green.
- 2026-06-17 — Friction-log signal fixes: `taint forward` sources/sinks echo now
  compact strings (+counts) so default JSON is ~11 lines and `| tail`-safe;
  `dataflow values --no-frame` drops sp/fp/lr/pc noise; confirmed `taint forward
  --function` no-sink case is clearly explained in `note`. 166 green.
- 2026-06-17 — P1 function ergonomics: `function list --count/--sort` and
  `function search --exact/--min-address/--max-address/--sort` (shared
  `_sort_func_rows`; `--exact` mutex with `--regex`). 165 green. Dogfooded.
- 2026-06-17 — P1 IL slicing: `il --lines` and `disasm --lines` (CLI-side, reuses
  `_slice_lines`). Keeps large IL/disasm inline instead of spilling. 160 green.
- 2026-06-17 — P1 VR-core: `callsites --caller-static` (return-address-first text
  + bn-compatible `caller_static` JSON field). Confirmed the thunk-ambiguity
  friction is already fixed (union across thunks, `matched_targets`). 158 green.
- 2026-06-17 — More P1 listing ergonomics: `imports --count/--limit/--offset/
  --summary` and `sections --count/--limit/--offset`. Full suite 157 green.
  Dogfooded on `fw-A/bin-1` (summary: 28 external / 56 thunks).
- 2026-06-17 — Shipped P1 listing ergonomics: `strings --regex/--count` (match on
  decoded content) and `xrefs --limit/--offset` (with totals). Bridge + CLI +
  parser tests; full unit suite 152 green. Dogfooded both on `fw-A/bin-1`.
- 2026-06-17 — P0 reliability: `transport._spawn_failure_detail` now bubbles the
  fatal daemon-log tail into the spawn `BridgeError` (error-marker lines + recent
  frames); confirmed stale-build WARN already in the doctor renderer. +5 transport
  tests.
- 2026-06-17 — Authored GOAL.md. Audited full command surface: top-level &
  sub-command parity confirmed DONE; auto-spawn fix verified via cold `doctor`.
  Built option-level parity matrix → backlog below. No code change this cycle.
