# ghx

Agent-friendly Ghidra CLI. Drives Ghidra 12+ through a long-running PyGhidra
daemon that holds a JVM and a Ghidra Project open across calls.

Built for LLM-driven workflows: stable JSON output, token-aware spillover,
preview-then-commit mutations, and an inline Python escape hatch.

## Install

```
uv tool install -e /path/to/ghid
```

Requires:
- Python 3.11–3.13 (capped by JPype)
- Ghidra 12+ at `/opt/ghidra_12.0.4_PUBLIC` (or set `GHIDRA_INSTALL_DIR`)

## Quickstart

```
ghx session start                     # boot the PyGhidra daemon (JVM cold start ~3s)
ghx doctor                            # healthcheck: ghidra version, project, loaded targets
ghx load /bin/ls                      # import + auto-analyze
ghx function search main
ghx decompile main
ghx symbol rename --identifier main --new-name real_main --preview
ghx symbol rename --identifier main --new-name real_main
ghx session stop
```

## Command reference

Every command supports:

- `--format {text,json,ndjson}` (env: `GHX_FORMAT`; default `text`)
- `--out PATH` — render to file; print an envelope summary with byte/token counts
- `--instance ID` — pick a specific daemon (env: `GHX_INSTANCE`)
- `-t / --target SELECTOR` — pick a loaded program (`program_id`, `basename`,
  full path, or `active`)

Output automatically spills to `$TMPDIR/ghx-spills/YYYYMMDD/…` when it exceeds
10k tokens (override with `GHX_SPILL_TOKENS`).

### Lifecycle

| Command | Purpose |
|---|---|
| `ghx doctor` | Daemon + Ghidra version, install dir, project, targets |
| `ghx session start\|stop\|list` | Daemon process management |
| `ghx load PATH` | Import + auto-analyze into the daemon's project |
| `ghx close [SELECTOR]` | Release a loaded program |
| `ghx target list\|info` | Inspect loaded programs |

### Reads

| Command | Notes |
|---|---|
| `ghx function list [--query] [--min/max-address] [--offset/limit]` | |
| `ghx function search QUERY [--regex]` | |
| `ghx function info IDENT` | prototype + conv + xref count + params + locals |
| `ghx decompile IDENT` | decompiler C output |
| `ghx il IDENT --form raw\|high` | raw p-code per instruction or high p-code from decompiler |
| `ghx disasm IDENT` | |
| `ghx xrefs IDENT` | incoming + outgoing refs |
| `ghx callsites IDENT [--within A,B,C]` | every CALL into the function |
| `ghx field-xrefs --type-name T --field F \| --offset O [--in-function FN] [--timeout S]` | scan high p-code for `PTRSUB`/`PTRADD` hits on a struct field (slow full-binary; use `--in-function` for targeted audits) |
| `ghx strings [--query] [--min-length]` | `DefinedStringIterator.forProgram` |
| `ghx imports` | external symbols + thunks |
| `ghx sections [--query]` | memory blocks |
| `ghx types list [--query]` / `ghx types show NAME` | `DataTypeManager` |
| `ghx bundle function IDENT` | decompile + disasm + proto + locals + refs in one blob |

### Mutations

Every mutation supports `--preview`: apply + diff + roll the transaction back.

| Command | Ghidra operation |
|---|---|
| `ghx symbol rename --identifier ID --new-name NAME` | `Symbol.setName` (functions use `Function.setName` to keep thunks in sync) |
| `ghx comment set --address A --text T [--kind plate\|pre\|post\|eol\|repeatable]` | `Listing.setComment` |
| `ghx comment get\|delete\|list` | |
| `ghx proto get IDENT` | `Function.getPrototypeString` |
| `ghx proto set --identifier I --prototype "C SIG"` | `FunctionSignatureParser` + `ApplyFunctionSignatureCmd` |
| `ghx local list IDENT` | |
| `ghx local rename --identifier I --name OLD --new-name NEW` | `HighFunctionDBUtil.updateDBVariable` |
| `ghx local retype --identifier I --name N --type T` | same, with `DataTypeParser` |
| `ghx types declare --source "C CODE"` / `--file PATH` | `CParser` |
| `ghx struct field-set --type-name T --offset O --field-type DT [--field-name N] [--no-overwrite]` | `Structure.replaceAtOffset` / `insertAtOffset` |
| `ghx struct field-rename --type-name T --name OLD --new-name NEW` | `DataTypeComponent.setFieldName` |
| `ghx struct field-delete --type-name T --name N` / `--offset O` | `Structure.delete` |
| `ghx batch apply MANIFEST.json [--preview]` | all ops in one Program transaction; any failure rolls back the whole batch |

### Inline Python

```
ghx py exec --code 'result = flat.getFunction("main").getName()'
ghx py exec --script path/to/script.py
ghx py exec --mutate --code 'listing.setComment(addr("0x400000"), 3, "via py_exec")'
```

The daemon is already CPython-with-JPype; `py exec` just calls `exec()` with a
prebuilt scope: `currentProgram`, `program`, `project`, `flat` (FlatProgramAPI),
`listing`, `functionManager`, `symbolTable`, `referenceManager`,
`dataTypeManager`, `memory`, `monitor` (TaskMonitor.DUMMY), `decompile(fn)`,
`get_function(ident)`, `addr(s)`, `hexa(addr)`, plus `ghidra` and `jpype`.

Default is **read-only**. Pass `--mutate` to wrap execution in a Program
transaction.

## Batch manifests

```json
{
  "operations": [
    {"op": "rename_symbol",  "params": {"identifier": "entry", "new_name": "ghx_entry"}},
    {"op": "set_prototype",  "params": {"identifier": "ghx_entry",
                                        "prototype": "void ghx_entry(int argc, char **argv)"}},
    {"op": "set_comment",    "params": {"address": "0x1054f0", "text": "bundled change"}}
  ]
}
```

`ghx batch apply manifest.json [--preview]`. Opens one transaction; any op
failure aborts the whole batch.

## Ghidra semantics worth knowing

1. **IL forms.** `ghx il --form raw` gives per-instruction p-code (SLEIGH
   output); `ghx il --form high` gives the decompiler's high p-code
   (SSA-ish). The Ghidra decompiler's C output is the highest-level view
   and lives under `ghx decompile`, not `ghx il`.
2. **SourceType.** Ghidra distinguishes `DEFAULT`, `ANALYSIS`, `IMPORTED`,
   `USER_DEFINED`. Every mutation must pass `USER_DEFINED` or the next
   `reAnalyzeAll` may silently overwrite it. All `ghx` mutations do this.
3. **Thunks.** Imported functions usually surface as thunks. `ghx imports`
   lists both the external symbol and its thunk. Prototype/signature ops on
   a thunk apply to the thunk wrapper — follow `fn.getThunkedFunction(True)`
   if you want the external.
4. **Projects.** One daemon = one Ghidra Project (ephemeral under
   `~/.cache/ghx/projects/<instance>/` by default; pass `--project` at
   `ghx session start` to pin a persistent one).
5. **Calling convention prefix.** `Function.getPrototypeString(true, true)`
   includes the calling convention name (e.g. `processEntry`). `ghx proto
   set` verifies by comparing return + parameter types, not the rendered string.

## Development

```
uv sync                     # install
uv run pytest               # unit tests (no JVM)
uv run pytest -m integration  # full round-trip (needs GHIDRA_INSTALL_DIR)
```

See `CLAUDE.md` for the architecture and for tips on adding new ops.
