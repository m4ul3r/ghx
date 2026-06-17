---
name: ghx
description: Use the local ghx CLI for Ghidra reversing work through the ghx PyGhidra daemon. Headless by default (no GUI required). Prefer this skill for decompilation, function search, callsite recovery, raw/high p-code, disassembly, structured IL, xrefs, type inspection, struct field edits, preview/commit mutations, types declare, batch apply, inline Python; source→sink taint tracing (forward + backward slice), SSA def/use and constant (value) dataflow, resolved call graphs, evidence helpers (vtable/pointer-table tables, .init_array/.ctors, RTTI/type-name strings), raw memory reads, stable local-variable ids, sticky instance/target pins, and .gzf export against a live Ghidra Program.
---

# ghx

Use this skill when the user wants reverse-engineering work against a Ghidra
Program and the local `ghx` CLI is available. The daemon is a long-running
PyGhidra process that holds a JVM and a Ghidra Project open across calls.

## Workflow

1. Start with target discovery:

```bash
ghx target list
```

If no daemon is running, `ghx` auto-spawns one. JVM cold start is ~3s on
Linux; first-ever use of the daemon may take longer. Prefer `ghx session
start` to pre-warm if you're about to run several commands.

2. Pick a target:
- If exactly one Program is loaded, target-scoped commands can omit `-t`.
- If multiple Programs are loaded, commands that omit `-t` fail; pass
  `-t <program_id>` or `-t <basename>` from `ghx target list`.
- Use `-t active` only when you explicitly mean the most recently loaded
  program.

3. Pick the right output mode:
- Read commands default to `text`.
- Mutation, preview, and manifest commands default to `json`.
- Other options: `--format json`, `--format ndjson`, `--out <path>`.

Outputs above `10_000` `o200k_base` tokens auto-spill to disk
(`$TMPDIR/ghx-spills/YYYYMMDD/...`). When that happens, stdout is a compact
text envelope (`ok: true`, `path: ...`, `tokens: ...`, `sha256: ...`). Do NOT
chain `ghx ... | rg ...` and expect to search the real output after a spill.
Read the file path from the envelope, or pass `--out <path>` upfront.

Override the threshold per-invocation with `GHX_SPILL_TOKENS=<N>`.

## Headless Mode

`ghx` is headless-only in v1. There is no "GUI bridge" yet. Everything runs
through the PyGhidra daemon. First invocation auto-spawns:

```bash
ghx load /path/to/binary       # auto-spawns daemon, imports + analyzes
ghx target list
```

To pre-warm or pin a persistent project:

```bash
ghx session start --project ~/ghx_projects/work --project-name main
ghx load /path/to/binary
```

Without `--project`, an ephemeral Project is created under
`~/.cache/ghx/projects/<instance_id>/` and discarded when `ghx session stop`
is called. Pre-analysis state is preserved across loads within the same
session, but renames/types/comments are **lost on daemon stop** unless you
started with `--project`. `ghx doctor` shows `project ... [ephemeral]` when
the current project won't survive a restart. If you plan to work across
multiple sessions, always `ghx session start --project <path>` first.

`ghx close [-t SELECTOR]` releases a loaded program; `ghx session stop`
terminates the daemon.

## High-Value Read Commands

```bash
ghx target list
ghx target info

ghx function list
ghx function list --min-address 0x401000 --max-address 0x40ffff
ghx function list --limit 100 --offset 0

ghx function search alloc
ghx function search --regex '^(alloc|free|realloc)$'

ghx function info sample_parse
ghx function info sample_parse -v          # include stack offsets, frame size, thunked target
ghx callsites crt_rand --within bonus_pick_random_type
ghx callsites crt_rand --context 2         # include 2 prev + 2 next instructions per site
ghx callsites crt_rand --within-file /tmp/rng-functions.txt --format ndjson

ghx proto get sample_parse
ghx local list sample_parse

ghx decompile sample_parse                 # Ghidra decompiler's C output
ghx decompile sample_parse --addresses     # prefix each line with its min address
ghx decompile sample_parse --lines 20:60   # slice output to lines 20..60
ghx il sample_parse --form raw             # per-instruction p-code
ghx il sample_parse --form high            # decompiler high p-code (SSA-ish)
ghx function structured-il sample_parse    # per-pcode-op JSON (op/inputs/output) for tooling
ghx disasm sample_parse

ghx read 0x401000 -n 64                    # hexdump raw bytes (accepts a symbol name too)
ghx read sample_parse -n 16
ghx function create 0x401abc               # define a function auto-analysis missed
ghx function create 0x401abc --name parse_hdr --preview

ghx xrefs sample_parse
ghx xrefs 0x401000
ghx xrefs --field Player.hp                         # scan binary for Player.hp accesses
ghx xrefs --field Player.0x10 --in-function update  # fast scoped scan

ghx comment list
ghx comment list --kinds plate,pre
ghx comment get --address 0x401000 --kind plate

ghx types list --query Player
ghx types show Player
ghx struct show Player                     # struct-only view of a type

ghx strings --query usage
ghx strings --min-length 6
ghx strings --section .rodata --no-crt     # restrict to .rodata, drop CRT noise

ghx imports
ghx sections
ghx sections --query text
```

`ghx function search` is case-insensitive substring by default. Add `--regex`
for regular expressions. `ghx function list` and `ghx function search`
accept `--min-address`/`--max-address` and paging (`--offset`, `--limit`).

`ghx imports` includes both the external symbol and its thunk (in Ghidra,
imported functions usually surface as thunks that trampoline to an external
symbol). Entries tagged `(thunk)` are the code you actually call into.

`ghx sections` returns `perms` as a 3-char `rwx` string (dashes where a
permission is absent) and `initialized: true/false`.

## Callsites + Return-Address Recovery

Prefer `ghx callsites` over ad-hoc `py exec` when the task is "find exact
native return-address callers":

```bash
ghx callsites crt_rand --within bonus_pick_random_type
ghx callsites crt_rand                                   # all callers
ghx callsites crt_rand --format ndjson                   # one callsite per line
```

`ghx callsites` reports for each caller:
- `call_addr` — the native `CALL` instruction address
- `return_address` — the exact post-call return address
  (`return_address = call_addr + call_instruction_length`)
- `caller` — the containing function name, or `null` if unknown
- `ref_type` — Ghidra's RefType (e.g. `UNCONDITIONAL_CALL`, `COMPUTED_CALL`)
- `disasm` — the call instruction's textual form

`--within A,B,C` restricts to a comma-separated list of caller names.
`--within-file PATH` reads one caller per line (blank lines and lines
starting with `#` are ignored). `--context N` includes `N` previous and `N`
next instructions around each site.

## Field Xrefs

`ghx xrefs --field` walks each function's high p-code and matches PTRSUB /
PTRADD ops whose constant offset is the target field and whose base pointer
is typed as the target struct (or pointer to it). (The op is `field_xrefs`;
there is **no** top-level `field-xrefs` command — it's a flag on `xrefs`.)

```bash
# Fast path: limit to one function.
ghx xrefs --field Player.hp --in-function player_update

# By offset instead of field name.
ghx xrefs --field Player.0x10 --in-function player_update

# Whole-binary: slow; ~3s per 100 functions depending on timeout.
ghx xrefs --field Player.hp --timeout 15
```

Requires that the relevant locals/parameters are *typed* as `Player *` in
Ghidra. If the decompiler is using `undefined8` for the pointer, field scans
will miss those sites. Use `ghx local retype` to fix typing first.

## Evidence Helpers

One-shot triage summaries that aggregate several primitives. All default to
JSON; large ones spill — use `--out` or `--format text`.

```bash
ghx evidence function parse_hdr        # prototype, section, thunk info,
                                       # outgoing calls (resolved), insn count,
                                       # incoming-xref count, arg hints
ghx evidence xrefs parse_hdr           # xrefs enriched with section + symbol +
                                       # disasm context per ref
ghx evidence init                      # walk .init_array/.fini_array/.ctors/.dtors
                                       # as pointer arrays -> resolved functions
ghx evidence table 0x4a1000 -n 32      # interpret memory as a pointer table /
                                       # vtable; classifies each slot
                                       # (function/symbol/data/unmapped),
                                       # flags looks_like_vtable
ghx evidence table 0x4a1000 --no-stop  # don't stop at the first unmapped slot
ghx evidence message --query 'google::protobuf'   # type-name/RTTI/message
ghx evidence message --query '^_ZTV' --regex      # strings + their xrefs + section
ghx evidence message                   # no query -> type-name heuristic ("::" / dotted)
```

`evidence table` and `evidence init` are the fast path for C++ vtable / RTTI
recovery and constructor discovery; `evidence message` finds the type-name
strings those tables point near.

## Dataflow & Taint

The VR workhorses. All run on the decompiler's HighFunction (SSA) except
`dataflow values`, which uses Ghidra's SymbolicPropogator.

```bash
# Where does a value come from / go?
ghx dataflow defuse parse_hdr len            # SSA def site + all use sites of a variable
                                             # (var = name OR stable id from `local list`)

# Resolved call graph (direct edges; indirect targets are counted, not resolved)
ghx dataflow callgraph parse_hdr                       # immediate callees + callers
ghx dataflow callgraph parse_hdr --direction callees --depth 3
ghx dataflow callgraph parse_hdr --direction callers   # who reaches this function

# Proven constant register values at an address (NOT a full value-set — constants only)
ghx dataflow values parse_hdr 0x401abc                 # all base registers
ghx dataflow values parse_hdr 0x401abc --register X0

# Backward taint: slice a sink argument (or variable) to its origins
ghx taint backward parse_hdr --at 0x401abc --arg 0     # 0-based arg of the call at --at
ghx taint backward parse_hdr --variable len            # slice a named variable
ghx trace parse_hdr --at 0x401abc --arg 1              # alias: backward slice of a call arg

# Forward taint: source -> sink chains (intraprocedural v1)
ghx taint forward                                      # libc defaults, whole binary
ghx taint forward --function handle_request            # scope to one function (fast)
ghx taint forward --sources recv,read --sinks strcpy,system,memcpy
```

What each origin/leaf means in `taint backward` / `trace`:
- `parameter` / `global` — the slice bottomed out at a function input
- `const` — a literal value
- `load` — a memory read (the pointer expression is sliced further)
- `call_result` — the value is a callee's return (the slice stops here; this is
  what `taint forward` keys on to declare a source→sink chain)

**Honest scope (read before trusting):**
- `taint forward` is **intraprocedural** in v1 — it finds a chain when a sink
  argument backward-slices to a *source call's return* within the same function.
  It does **not** follow taint across function boundaries (callee params/returns)
  or through a source's out-buffer (`recv(fd, buf, ...)` does not yet taint
  `*buf`). A reported chain is real; a missing one is possible — so 0 chains is
  **not** an all-clear.
- `dataflow values` reports **proven single constants**, not value-sets/ranges
  (Ghidra has no native VSA). That is also why `dataflow callgraph` cannot
  resolve indirect (computed) call targets and instead reports
  `indirect_callsites` as a count.

## Bundles

Use bundles to capture a reusable artifact instead of pasting long output
into context:

```bash
ghx bundle function sample_parse --out /tmp/sample.json
```

A bundle includes: decompiled C, disassembly, prototype, calling convention,
parameters, locals, incoming refs. Always use `--out <path>` for bundles —
they are verbose.

## Python Escape Hatch

Use inline Python for Ghidra work that's awkward to express as a built-in
command. `ghx py exec` runs in the daemon's CPython interpreter (PyGhidra +
JPype) so you get the full Ghidra Java API, not just a curated subset.

```bash
ghx py exec --code 'print(hex(currentProgram.getImageBase().getOffset())); result = len(list(currentProgram.getFunctionManager().getFunctions(True)))'
```

For multi-line scripts use `--stdin` with a quoted heredoc so the shell
doesn't expand `$vars`/backticks before Python sees them:

```bash
ghx py exec --script - <<'PY'
out = []
for f in currentProgram.getFunctionManager().getFunctions(True):
    entry = f.getEntryPoint().getOffset()
    if 0x416000 <= entry < 0x41c000:
        out.append((int(entry), str(f.getName())))
out.sort()
print("\n".join(f"0x{a:x} {n}" for a, n in out))
PY
```

Wait — `--script` takes a path, not `-`. Use `--code` with a `$(cat <<'PY' ... PY)`
substitution, or drop the snippet into a file. Full pattern:

```bash
cat > /tmp/hunt.py <<'PY'
from ghidra.program.model.data import Structure
dtm = currentProgram.getDataTypeManager()
for dt in dtm.getAllDataTypes():
    if isinstance(dt, Structure) and dt.getLength() > 0x200:
        print(dt.getPathName(), dt.getLength())
PY
ghx py exec --script /tmp/hunt.py
```

The `py exec` scope includes:
- `currentProgram`, `program`, `project`
- `flat`, `fpapi` — `ghidra.program.flatapi.FlatProgramAPI(currentProgram)`,
  the canonical GhidraScript-style surface
- `listing`, `functionManager`, `symbolTable`, `referenceManager`,
  `dataTypeManager`, `memory`
- `monitor` — `TaskMonitor.DUMMY`
- `decompile(fn)` — returns the decompiler's C for `fn` (accepts name or
  Function object)
- `get_function(ident)` — resolves name or hex address to a `Function`
- `addr(s)` — resolves a hex string to an `Address`
- `hexa(addr)` — formats an `Address` as `"0x<offset>"`
- `define_data(addr, dt, *, clear=True)` — define typed data at `addr`;
  clears any conflicting auto-analyzed code unit first. `dt` may be a
  `DataType` or a name/expression resolvable via the DTM (e.g. `"Item *"`,
  `"uint64_t[4]"`, `"MyStruct"`).
- `clear_data(addr, length=1)` — clear existing code units over `length`
  bytes starting at `addr`.
- `ghidra`, `jpype` — escape hatches for obscure APIs
- `result` — assign here; it's returned as the op's `result` field

**Read-only by default.** Mutating calls (anything that writes to the
program database) must pass `--mutate`:

```bash
ghx py exec --mutate --code 'listing.setComment(addr("0x401000"), 3, "reviewed")'
```

`--mutate` wraps your code in a Program transaction. Without it, writes will
fail with a Ghidra "not in transaction" error.

## Mutation Workflow

All mutation commands take **positional arguments** for the primary targets
(identifier, new name, etc.) and reserve `--flags` for options.

Prefer `--preview` first:

```bash
ghx symbol rename sub_401000 player_update --preview
ghx proto set player_update "void player_update(Player *self)" --preview
ghx local rename player_update self_ptr self --preview
ghx local retype player_update self "Player *" --preview
ghx types declare --source 'typedef struct Foo { int x; } Foo;' --preview
ghx struct field set Player 0x10 ptr "uint *" --preview
ghx struct field rename Player offset flags --preview
ghx struct field delete Player pad_04 --preview
ghx comment set --address 0x401000 "reviewed" --preview
```

Preview mode opens a transaction, applies, runs verification, then rolls the
transaction back. The response includes `before`, `after`, and
`observed_after` so you can see what *would* have landed.

Commit (drop `--preview`):

```bash
ghx symbol rename sub_401000 player_update
ghx proto set player_update "void player_update(Player *self)"
ghx struct field set Player 0x10 ptr "uint *"
```

### Command cheatsheet (mutations)

| Command | Positionals |
|---|---|
| `symbol rename` | `identifier new_name [--kind auto\|function\|data] [--preview]` |
| `proto set` | `identifier prototype [--preview]` |
| `local rename` | `function variable new_name [--preview]` |
| `local retype` | `function variable new_type [--preview]` |
| `struct field set` | `struct_name offset field_name field_type [--no-overwrite] [--length N] [--comment TEXT] [--preview]` |
| `struct field rename` | `struct_name old_name new_name [--preview]` or `struct_name --offset O new_name [--preview]` |
| `struct field delete` | `struct_name field_name [--preview]` or `struct_name --offset O [--preview]` |
| `comment set` | `comment [--address A \| --function F] [--kind K] [--preview]` |
| `comment get` | `[--address A \| --function F] [--kind K]` |
| `comment delete` | `[--address A \| --function F] [--kind K] [--preview]` |
| `types declare` | `[--source S \| --file P \| --stdin] [--preview]` |

Result statuses:
- `verified` — applied and re-read the expected state
- `verification_failed` — applied but observed state didn't match (the
  transaction is rolled back if this happens in a non-preview run)

After any live mutation, verify by re-reading:

```bash
ghx function info player_update
ghx proto get player_update
ghx types show Player
ghx decompile player_update
```

## Batch Apply

For bulk mutations, use `ghx batch apply` with a JSON manifest. All ops run
in a single Program transaction; any failure aborts the whole batch.

Manifest shape:

```json
{
  "operations": [
    {"op": "rename_symbol",  "params": {"identifier": "sub_401000", "new_name": "player_update"}},
    {"op": "rename_symbol",  "params": {"identifier": "sub_402000", "new_name": "player_init"}},
    {"op": "set_prototype",  "params": {"identifier": "player_update",
                                        "prototype": "void player_update(Player *self)"}},
    {"op": "set_comment",    "params": {"address": "0x401000", "text": "entry",
                                        "kind": "plate"}}
  ]
}
```

(A bare list is also accepted — `ghx` treats `[{"op": ...}, ...]` and
`{"operations": [...]}` identically.)

```bash
ghx batch apply /tmp/manifest.json --preview   # preview, roll back
ghx batch apply /tmp/manifest.json             # commit
```

Allowed ops in `batch_apply`:
`rename_symbol`, `set_comment`, `delete_comment`, `set_prototype`,
`local_rename`, `local_retype`, `struct_field_set`, `struct_field_rename`,
`struct_field_delete`, `types_declare`.

### Batch ordering trap

Each op in a batch observes the program state *after* all prior ops. If you
rename `FUN_00101350` → `item_new` at op 0 and then try to `set_prototype`
for `FUN_00101350` at op 1, op 1's lookup fails (`not_found`) because the
symbol no longer exists under that name — and the whole batch rolls back
including the rename.

Two reliable patterns:

1. **Split into two batches**: one for all renames, one for all
   prototype/type ops keyed on the *new* names.
2. **Refer by address** in the second ops, not by name — addresses don't
   shift across renames:
   ```json
   {"op": "rename_symbol",  "params": {"identifier": "FUN_00101350", "new_name": "item_new"}},
   {"op": "set_prototype",  "params": {"identifier": "0x101350", "prototype": "Item * item_new(void)"}}
   ```

## types declare

```bash
ghx types declare --source 'typedef struct Player { int hp; int mp; char name[32]; } Player;'
ghx types declare --file /path/to/game.h
ghx types declare --file /path/to/game.h --preview
```

Uses Ghidra's `CParser`. Composites and enums discovered during parsing are
added to the `DataTypeManager` with `REPLACE_HANDLER` conflict handling.

If a declaration only introduces typedefs/extern variables and no named
composites or enums, the op reports an empty `applied: []` — that's
expected, not a failure.

## Ghidra semantics worth knowing

1. **IL forms.** `ghx il --form raw` is per-instruction p-code (SLEIGH
   output). `ghx il --form high` is the decompiler's high p-code (SSA-ish).
   The decompiler's C text lives under `ghx decompile` — it's the
   highest-level view Ghidra produces.
2. **SourceType.** Every mutation is applied with
   `SourceType.USER_DEFINED`. Without that, Ghidra's auto-analysis may
   silently overwrite the change on the next `reAnalyzeAll`. `ghx` handles
   this for you — just know that if you write state via `py exec` without
   `USER_DEFINED`, it may disappear.
3. **Thunks.** Imported functions usually surface as thunks in Ghidra.
   `ghx imports` lists both the external symbol and its thunk. Prototype
   and signature ops on a thunk apply to the thunk wrapper; follow
   `fn.getThunkedFunction(True)` if you need the external proper.
4. **Projects.** One daemon = one Ghidra Project. Multiple Programs can be
   loaded into the same Project — switch between them with `-t`.
5. **Calling convention prefix.** `Function.getPrototypeString(true, true)`
   includes the calling convention name (e.g. `processEntry` for ELF
   entry). `ghx proto set` verifies by comparing parameter/return types,
   not the rendered string, so the rendered form may look different from
   what you passed in even on a successful apply.

## Saving and Loading

`ghx load <path>` imports a binary into the daemon's Project (if not already
present) and runs auto-analysis. It is idempotent — loading the same
`basename` a second time returns the existing handle.

```bash
ghx load /path/to/binary           # import + full auto-analysis
ghx load /path/to/binary --quick   # import only, SKIP auto-analysis (fast cold load)
ghx refresh                        # run/redo full auto-analysis (use after --quick,
                                   # or after a big type change)
```

Use `--quick` to get a binary open in ~seconds for a first look (sections,
strings, imports), then `ghx refresh` to deepen when you need functions/xrefs.
The load result reports `analyzed: false` after a `--quick` load.

Each mutation is saved to the project's `DomainFile` as it happens (Ghidra's
DB model is transactional, not document-based). Commit-time persistence is
automatic — you don't need to "save" to keep renames/types/comments. If the
daemon is killed, saved mutations survive in a persistent `--project`; an
ephemeral project (`~/.cache/ghx/projects/<instance>/`) is deleted on
`session stop`.

To export the analyzed program to a portable archive, use `ghx save <path>` —
it writes a Ghidra Zip File (`.gzf`, extension appended if absent):

```bash
ghx save /tmp/target.gzf           # export the current program as .gzf
ghx save                           # no path: just flush to the project DomainFile
```

## Session Management

`ghx` may run multiple daemons. If more than one is registered, commands
that omit `--instance` fail with an ambiguity error. Pick one, or **pin** a
default so you stop passing `--instance`/`-t` on every call:

```bash
ghx session list               # list running daemons
ghx --instance <id> doctor     # scope one command to one daemon
GHX_INSTANCE=<id> ghx doctor   # env-var scope
ghx session stop               # stop the (only) running daemon

# Sticky pins (survive across invocations; explicit --instance/-t still win):
ghx instance use <id>          # default daemon for subsequent calls
ghx instance clear
ghx target use <selector>      # default program (program_id/basename/'active')
ghx target clear

# Lifecycle:
ghx session restart            # stop + respawn same id, reloading its targets
ghx instance prune --idle 900  # stop daemons idle longer than 900s
```

A pin only takes effect when it points at a *live* instance; a stale pin is
ignored. When juggling several binaries, `ghx target use <basename>` once is
much less error-prone than threading `-t` through every command.

## Troubleshooting

```bash
ghx doctor                     # version + install dir + loaded targets
```

Run it only when something feels wrong — don't run it in normal workflow.
It also cross-checks the daemon's build id against the current bridge
source and prints a `WARN` line if they diverge — when that happens, run
`ghx session stop` and retry to pick up the new code.

Common failure modes:
- **"no function matches identifier"**: Ghidra may have renamed the function
  (e.g. `entry` → `main` after analysis). Try `ghx function search` first.
- **"ambiguous_function"**: multiple matches; use the hex address from the
  error message.
- **"ambiguous_target"**: multiple Programs loaded with the same basename.
  Pass `-t <program_id>` from `ghx target list`.
- **"no_target"**: no Program is loaded. Run `ghx load <path>` first.
- **"apply_failed: TypeError: No matching overloads..."**: a Ghidra Java
  method was called with wrong types via `py exec`. Check the stub types at
  `/opt/ghidra_12.1.2_PUBLIC/docs/ghidra_stubs/typestubs/ghidra-stubs/`.

## Known quirks

- **Decompile of a thunk is empty.** `ghx decompile some_import` often
  returns no body because the thunk has no instructions. Decompile the
  *caller* and look at the call site, or use `ghx bundle function` on the
  caller for full context.
- **`types declare` with `--preview`.** Preview rolls back the transaction,
  so the newly-added type disappears. If you want to inspect the type's
  fields, commit first and then `ghx types show`.
- **Local rename on decompiler-introduced locals.** Ghidra has two tiers:
  stored variables (persist to the database) and decompiler-introduced
  locals (exist only in the HighFunction). `ghx local rename` handles both
  via `HighFunctionDBUtil.updateDBVariable`, but the HighFunction reference
  must be fresh — don't cache it across mutations.
- **Stable local ids.** `ghx local list` emits an `id` per variable derived
  from its storage (e.g. `X0`, `Stack[-0x10]`) that is stable across both
  rename and retype. `ghx local rename`/`local retype` accept the variable
  argument as **either a name or that id** — prefer the id in scripts so a
  rename earlier in a batch doesn't break a later retype that referenced the
  old name. (Names also still work.)
- **`ghx rename` is an alias** for `ghx symbol rename` (rename a function or
  data symbol by name or address). `ghx trace` is an alias for the call-arg
  case of `ghx taint backward`.
- **`field-xrefs` misses untyped accesses.** If a pointer is still
  `undefined8` instead of `Player *`, field scans won't find accesses
  through it. Retype first, rescan second. This includes global
  variables: if `g_inv_head` is still `undefined8`, retype it to
  `Item *` via `py exec --mutate` (use `define_data`) before scanning.
- **`proto set` with pointer returns.** The underlying
  `FunctionSignatureParser` binds `*` to the name when there's no space,
  so `"Item *item_new(void)"` fails with `Can't parse name: *item_new`.
  `ghx proto set` now normalizes `*name` → `* name` automatically, but
  know this if you're invoking the parser through `py exec`.

