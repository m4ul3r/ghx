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

## Status snapshot (2026-06-17)

- **Top-level command parity: DONE.** Every `bn` top-level command exists in
  `ghx` except `plugin` (GUI extension — deliberately out of scope, see below).
- **Sub-command parity: DONE.** `dataflow/taint/function/evidence/bundle/symbol/
  comment/proto/local/struct/types/target/batch` all expose the same set of
  second-level verbs.
- **Out-of-box auto-spawn: FIXED** (ephemeral project now under
  `/tmp/ghx-projects/<id>`, no dotted path element; `ghx doctor` cold-spawns
  cleanly).
- **Remaining gap = option-level + output-semantics + dataflow depth.** That is
  the entire backlog below.

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
- [ ] **Forward-taint out-buffer source.** `getline/read/fgets/recv` write into
  `*buf`; that written buffer is the real taint source and is currently
  untracked, so whole-binary `taint forward` reports `chain_count=0` on binaries
  that obviously flow input→parse→`memcpy`. Model out-parameter writes as taint
  origins. *Biggest single dataflow gap.*
- [ ] **`taint forward` interprocedural.** Today it is intraprocedural v1; bn
  follows source→sink across calls. Add interprocedural propagation (mirror
  `trace --interprocedural --ip-depth`).
- [ ] **`taint forward` output shape.** Put `chain_count` + `chains` FIRST;
  demote the large `sources_used`/`sinks_used` echo. Add a one-line text summary
  for default text mode so `| tail` doesn't hide the signal.
- [ ] **`taint forward --function` semantics.** A named function with no
  source+sink pair is silently dropped → `scanned_functions: 0` reads like "not
  found". Distinguish "0 functions matched filter" from "scanned, 0 chains".
- [x] **`callsites <libc-name>` thunk ambiguity.** Already resolved:
  `_op_callsites` uses `_resolve_functions` (plural) and unions call sites across
  all matched thunks/symbols, dropping thunk→EXTERNAL trampolines and returning
  `matched_targets`. Verified `callsites memcpy/strlen/snprintf/mount` on
  `fw-A/bin-1` — no ambiguity error.
- [x] **`callsites --caller-static`** — added. Text mode leads with each call's
  static return address; JSON now carries a bn-compatible `caller_static` field
  (= instruction-after-call). Verified on `fw-A/bin-1`.
- [ ] **`dataflow values` frame-register noise.** Default dumps `sp/x29/x30`;
  add `--args-only` / filter to non-frame regs to raise signal.
- [ ] **`trace` depth flags.** ghx `trace` has `--arg/--at`; bn adds
  `--max-depth`, `--view {mlil,hlil}`, `--interprocedural`, `--ip-depth`. Bring
  these over (the SSA backward slice is the standout op — make it bn-complete).
- [ ] **`taint backward` arg model** — verify ghx's `--at/--arg/--variable`
  reaches semantic parity with bn's `--function/--sink/--max-depth`; add
  `--max-depth`.

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
- [ ] `evidence xrefs`: add `--limit`, `--offset`. `evidence init`: add `--limit`.
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
- [ ] `function structured-il`: align `--form` with bn's `--view` + `--no-ssa`.
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
- [ ] `close --all` (close every loaded program in one call).
- [ ] `read --encoding {hex,bytes}` and `--address` alias.
- [ ] `save --path` alias for the positional output path.
- [ ] `comment` — reconcile ghx `--kind`/`--kinds` naming with bn (`comment list
  --query`).
- [ ] `target info --verbose`.
- [ ] `evidence {function,table,message}` — reconcile remaining flag diffs
  (`--context`, `--entries`/`--stride`, `--table-entries`). Audit each against bn.
- [ ] `strings` value field is Ghidra's C-literal repr (`u8"libc.so.6"`,
  trailing quote). bn returns the raw decoded string. Consider exposing the
  decoded `value` and carrying the encoding/prefix separately, so output matches
  bn. (Discovered 2026-06-17; matching already uses the decoded content.)

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
