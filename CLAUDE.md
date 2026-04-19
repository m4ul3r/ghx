# CLAUDE.md

Notes for Claude (and humans) working in this repo.

## What ghx is

`ghx` is a CLI + PyGhidra daemon pair for agent-driven Ghidra work. The CLI
is pure Python with no Ghidra imports; it talks to a long-running daemon
that holds a JVM and a Ghidra Project open across calls.

## Architecture

Two processes over a Unix domain socket:

```
  ghx (CLI)                            ghx-agent (daemon)
  ─────────                            ──────────────────
  Python 3.11-3.13, argparse           PyGhidra + JPype + Ghidra 12.0.4
  no Ghidra imports at all             one JVM, one Project, N Programs
  src/ghx/{cli,transport,output}.py    plugin/ghx_agent_bridge/bridge.py
                                       └─ BridgeHandler (socketserver)
                                       └─ TargetManager (ProgramHandle map)
                                       └─ _run_mutation (transaction+verify)
                                       └─ op handlers (_op_*)
```

- **Protocol.** JSON envelope: `{id, op, params, target}` → `{ok, result|error}`.
- **Socket path.** `~/.cache/ghx/instances/<instance_id>.sock`
- **Registry.** `~/.cache/ghx/instances/<instance_id>.json` (discovery).
- **Auto-spawn.** If no daemon is running, `choose_instance()` spawns a fresh
  `ghx-agent` and polls the registry file (45s timeout for JVM cold start).

## Daemon lifecycle

`ghx_agent_bridge.bridge.start_headless()`:

1. `pyghidra.start(install_dir=…)` — one-time JVM boot (~3s on Linux).
2. `pyghidra.open_project(path, name, create=True)` — one Project per daemon.
3. Bind Unix socket, `serve_forever` on a background thread.
4. Dispatch uses `_ReadWriteLock`: concurrent reads, exclusive writes
   (`READ_LOCKED_OPS` / `WRITE_LOCKED_OPS` sets).
5. On SIGTERM / `shutdown` op: release all Programs, close the Project,
   unlink socket + registry.

`ghx session start --project PATH --project-name NAME` pins a persistent
project; otherwise we create an ephemeral one under
`~/.cache/ghx/projects/<instance_id>/`.

## Mutation flow

`_run_mutation(program, description, apply, verify, preview, before, after)`:

1. `tx = program.startTransaction(description)`
2. call `apply()`; on exception, abort.
3. call `verify()` → `(ok, observed)`.
4. `program.endTransaction(tx, committed)` where
   `committed = (not preview) and verify_ok`.
5. Return a `{status, committed, preview, before, after, observed_after}` shape.

Preview = apply + verify + rollback. Commit = apply + verify + commit iff ok.

`batch_apply` opens a single Program transaction around multiple sub-ops;
any failure or preview aborts the entire batch. Inner op flags are
post-processed so `committed` / `preview` on the nested results reflect the
batch-level disposition rather than the nested transaction state.

## Adding a new op

1. Add a handler method on `GhxBridge`: `_op_my_thing(self, params, target)`.
2. Add the op name to `READ_LOCKED_OPS` or `WRITE_LOCKED_OPS`.
3. Wire the `if op == "my_thing": return self._op_my_thing(...)` branch in
   `_run_op`.
4. Add a CLI command in `src/ghx/cli.py` via the `@command(*path, ...)`
   decorator — the framework plumbs common options (`--format`, `--out`,
   `--instance`, `-t/--target`, paging, address filters).
5. Add a parser-acceptance case to `tests/test_cli_parser.py`.
6. Add an integration check if the op touches Ghidra state meaningfully.

For mutations, wrap the core apply logic in a closure and pass to
`_run_mutation`. Keep `verify()` cheap — it runs twice (preview + commit).

## Ghidra API conventions (that tripped us up)

- `ProgramLoader.Builder` has no `.build()`; call `.load()` directly on the
  builder. `LoadResults` is `AutoCloseable` and needs `.close()`; the Program
  obtained via `.getPrimaryDomainObject(consumer)` needs a separate
  `.release(consumer)`.
- Call `Loaded.save(monitor)` **before** running analysis, or the Program
  has no DomainFile to persist into.
- `pyghidra.ApplicationInfo.from_file(install_dir/"Ghidra"/"application.properties")`
  — it's not a zero-arg constructor.
- `DefinedStringIterator` is at `ghidra.program.util`, not
  `ghidra.program.util.string`.
- `HighFunctionDBUtil` is at `ghidra.program.model.pcode`, not
  `ghidra.app.decompiler.util`.
- `CParser.getComposites()` / `getEnums()` return `Map<String, DataType>` —
  iterate `.values()`, not the map directly.
- `DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL)` is
  the four-arg form that Just Works for type expressions like `unsigned
  long`, `char *`, `int[4]`.
- `FunctionSignatureParser` trips on `T *name(...)` (binds `*` to the
  name). `_op_set_prototype` normalizes `*name` → `* name` before parsing.
- Every mutation takes `SourceType.USER_DEFINED` or it gets wiped by the
  next `reAnalyzeAll`.
- Built-in types (`bool`, `int`, `char`, etc.) live in
  `BuiltInDataTypeManager.getDataTypeManager()`, not the program's DTM.
  `_find_data_type` falls back to the built-in DTM when the program DTM
  misses.

## Build & test

```
uv sync                       # install editable + deps
uv run pytest                 # unit tests (~85, no JVM needed)
uv run pytest -m integration  # integration tests (boots a real ghx-agent)
```

Integration tests auto-skip if `GHIDRA_INSTALL_DIR` is unset and
`/opt/ghidra_12.0.4_PUBLIC` is absent. They use a per-test `GHX_CACHE_DIR`
under `tmp_path` so they don't collide with a running developer daemon.

## Key files

- `src/ghx/cli.py` — argparse tree driven by the `@command()` declarative
  registry (`arg()`, `mutex()`, `_build_from_commands()`). Per-command
  text renderers; `_emit` wraps `write_output_result` for spillover.
- `src/ghx/transport.py` — Unix socket client, instance discovery,
  auto-spawn, `BridgeError`.
- `src/ghx/output.py` — tokenizer (`o200k_base` via tiktoken), spill
  threshold (10k), artifact envelope rendering.
- `src/ghx/paths.py` — cache dir resolution, registry/socket paths,
  Ghidra install resolution.
- `plugin/ghx_agent_bridge/bridge.py` — the daemon: JVM boot, socket
  server, `TargetManager`, `_run_mutation`, all op handlers.

## Not yet implemented (deliberately out of scope for v1)

- **GUI extension plugin** (phase 2: a Java Ghidra extension that runs the
  same socket server inside a live Ghidra GUI, so a human can drive the
  GUI while the CLI issues ops against the same analysis state).
- **`ghx save <alternate-path>`** — `ghx save` persists the Program to its
  existing DomainFile; writing to an alternate path would require
  `project.saveAs(...)` and isn't wired up.
- **Retrieving `program.save(msg, monitor)` return values** — Ghidra
  persists atomically per-transaction anyway.
