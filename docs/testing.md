# Testing BEA

Written by WP0 (scaffold) and maintained by WP17-DOCS. DESIGN §8 is the authoritative test plan.

## Lanes

| Lane       | Command                                                                                      | Needs                           | Build?                          |
| ---------- | -------------------------------------------------------------------------------------------- | ------------------------------- | ------------------------------- |
| check      | `npm run check`                                                                              | Node                            | no                              |
| fast       | `npm test` (projects `unit`, `mcp-boundary`, `cli-boundary`, `http-boundary`)                | Node                            | no (vitest runs the TypeScript) |
| process    | `npm run test:process` (`process-boundary`, serial)                                          | Windows, gcc                    | yes                             |
| emulation  | `npm run test:emu` (`emu-boundary`, serial)                                                  | Python with unicorn 2.1.x       | yes                             |
| acceptance | `npm run test:acceptance` (`acceptance`, serial, `tests/globalSetup.ts` builds the fixtures) | Windows x64, Frida 17.23.2, gcc | yes                             |
| smoke      | `npm run smoke` (`scripts/smoke-stdio.mjs`)                                                  | a build                         | yes                             |
| receipts   | `npm run verify:frida:windows`, `npm run verify:emulation` (JSON receipts on stdout)         | as acceptance (+ Python)        | yes                             |

The release lanes of WP18 are part of the `acceptance` project: `tests/acceptance/lifecycle/` (S6 §10.9 must-haves),
`tests/acceptance/investigations/` (the seven S6 §1 investigations as `bea run` scenarios through the built CLI, with
their analysis-call counts; `support/scenario.ts` runs a scenario and records the owned processes) and
`tests/acceptance/integration/` (the cross-wave rows of DESIGN §8.4 and the trace_execution threads-mode regression).
`verify:frida:windows` runs CLI one-shots and the same tools over MCP and compares their pointer-free projections;
`verify:emulation` is WP14's live-vs-emulator receipt.

Every test file belongs to exactly one vitest project (`scripts/verify-test-discovery.mjs`; the table is
`scripts/lib/testProjects.mjs` and must match `vitest.config.ts`). No tests under `src/agent/` (they would be staged into
the frida.Compiler build); tests of agent pure helpers live in `tests/unit/agent/`. `retry: 0`, no sleeps for
synchronization (READY/RAMP/DONE markers, `vi.waitFor` at 25 ms), pointer-free assertions (module+RVA, never raw VAs).

## Working in a shared tree (several agents at once)

Many agents build and test in this one checkout concurrently. Three rules keep them from breaking each other.

### 1. Builds serialize on the build lock

Every build-like script holds the cross-process lock `build` (`scripts/lib/lock.mjs`): `npm run build`, `build:ts`,
`build:agent`, `build:native`, `build:bridge`, `build:skill`, `build:fixtures`, `generate` (also `--check`),
`catalog:golden`, `scripts/clean.mjs` and `scripts/snapshot-dist.mjs`.

- The lock is the directory `build/.locks/build/` with `owner.json` (pid, process start, token, command). Waiting
  processes print who holds it every 30 s and give up after 20 min (`BEA_LOCK_TIMEOUT_MS`).
- A lock whose owner process is gone (or whose pid now belongs to another process) is taken over automatically. Never
  delete a lock directory by hand while its owner is alive.
- Nested steps re-enter: `npm run build` holds the lock and exports `BEA_LOCK_TOKEN_BUILD` to its children, so
  `npm run build:agent` inside it does not wait for itself. Code that runs inside a build and starts an unrelated
  locking process must not pass that variable on.
- `build:agent`, `build:native` and `build:fixtures` compile into unique staging directories under `build/tmp/` and
  publish their outputs by rename (bundle/exe first, manifest last), so a reader never sees a half-written file. A
  running `bea-jobhost.exe` in `dist/` is renamed aside, never overwritten; `clean.mjs` removes such leftovers later.
- Generated files (`npm run generate`) are written atomically and formatted with the repository's oxfmt config.

Run repository-wide rewriters (`npm run format`, `oxfmt .`) only when nobody else is editing; format only your own
files otherwise (`npx oxfmt <files>`).

### 2. Tests of built binaries run from a snapshot

`dist/` changes whenever anyone rebuilds. A test that launches the BUILT server, agent bundle, jobhost or bridge first
takes a private snapshot and points the harness at it:

```sh
npm run build
node scripts/snapshot-dist.mjs <your-id>         # prints e.g. C:\...\bea\build\dist-snapshots\<your-id>\dist
BEA_DIST_DIR=<printed path> npx vitest run --project acceptance tests/acceptance/<area>/x.test.ts
BEA_DIST_DIR=<printed path> npm run smoke
```

(PowerShell: `$env:BEA_DIST_DIR = (node scripts/snapshot-dist.mjs <your-id>)`.)

- The snapshot is `build/dist-snapshots/<name>/` and mirrors the package layout: `dist/**`, `scripts/bea.mjs`,
  `package.json` and `bridge/emu/**` (when present). Bare imports resolve to the repository's `node_modules`.
- It is taken under the build lock (a consistent build) and replaces the previous snapshot of the same name
  atomically. Use your own name; a snapshot that still has running processes cannot be replaced.
- The harnesses resolve everything from `BEA_DIST_DIR` when set, else from the repository's `dist/`:
  `tests/support/mcp/stdioSubprocess.ts` (`connectStdioBea`), `tests/support/acceptance/harness.ts` (`connectBea`),
  `tests/support/acceptance/fixtures.ts` (`jobhostSkip`) and `scripts/smoke-stdio.mjs`.

### 3. The runtime locates its build outputs relative to its own dist

`src/application/distLayout.ts` is the single place that knows where build outputs are. A built server resolves
`<dist>/agent/bea-agent.js`, `<dist>/native/win32-x64/bea-jobhost.exe`, `<dist>/bridge-manifest.json`, `<dist>/skills/`
and the package root `<dist>/..` (`bridge/emu/bea_emu_bridge.py`, `scripts/bea.mjs`) from its own location
(`resolveDistLayout()`), never from the working directory, so a snapshot (or an installed package) is self-contained.
Code running from the TypeScript sources (vitest) has no dist of its own and uses `BEA_DIST_DIR`, else `dist/`.
Providers (agent bundle: WP4-SESS, jobhost: WP2-PROC, bridge: WP14-EMU, skill: WP15-CLI) must use this module.

## Isolation

- Every test uses a temp BEA_HOME: `createTempHome()` (`tests/support/workspace/tempHome.ts`) gives a fresh directory
  with HOME/USERPROFILE/APPDATA/LOCALAPPDATA/TEMP/TMP/XDG_* and BEA_HOME inside it. Never the real `%LOCALAPPDATA%\bea`.
- Servers and helpers listen on random ports (`--port 0`, parse the printed port).
- Only spawn, attach to, inject into or kill processes the test started. The owned-PID ledger
  (`tests/support/process/ownedPidLedger.ts`) records every owned process (spawn identities, behavior.exe `CHILD pid=`
  lines) and every attach target the test spawned; after each file it asserts owned processes are gone, attach targets
  are alive (BEA never kills attached processes), reaps proven leaks and fails.

## Harnesses (`tests/support/`)

| Module                      | Use                                                                                                                                                                                                                                                                            |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mcp/inMemory.ts`           | `connectInMemoryBea({services, env})`: the production MCP server over an in-memory transport with `fakeServices()` overrides and a temp BEA_HOME; `createTestMcp()` / `mcpTest` (REA mcpFixture).                                                                              |
| `mcp/stdioSubprocess.ts`    | `connectStdioBea()`: the built server over real stdio, minimal env, Ajv 2020-12 meta-validation, output validated against the advertised schema on every call; `close()` reports exit code and close time.                                                                     |
| `mcp/inProcessStdio.ts`     | `startInProcessStdio()`: `runStdio` in-process over PassThrough with the real transport and shutdown wiring; exit codes, hard-exit timers and signals are observable.                                                                                                          |
| `mcp/parseToolError.ts`     | `parseToolError(result)`: strict `{error: projection}` parse; `expectToolSuccess(result)`.                                                                                                                                                                                     |
| `fakes/fakeServices.ts`     | every service slot `capability_unavailable(not-implemented)`; override the slots a test exercises.                                                                                                                                                                             |
| `frida/gate.ts`             | `createGate()`: `{entered, wait, release, fail}` barriers for in-flight interleavings.                                                                                                                                                                                         |
| `workspace/tempHome.ts`     | temp homes (above).                                                                                                                                                                                                                                                            |
| `process/ownedPidLedger.ts` | leak oracle (above); `pidStatus()` uses `pidcheck.exe` from the fixture manifest.                                                                                                                                                                                              |
| `acceptance/harness.ts`     | `connectBea({home, gates, ledger})`: the stdio harness plus gate env vars, the bea_status anti-cheat notes (machine-wide services are reported, fixtures must still spawn and attach), ledger recording, ≤ 3 spawned targets per server; `sharedBea()` for read-only matrices. |
| `acceptance/fixtures.ts`    | `loadFixtures()` (the manifest from globalSetup, else built directly) and the named skips `gccSkip()`, `fridaSkip()`, `jobhostSkip()`, `emuSkip()` (DESIGN's GCC_SKIP, FRIDA_SKIP, JOBHOST_SKIP, EMU_SKIP).                                                                    |
| `http/inProcessHttp.ts`     | `serveHttp` over a real `node:http` listener in-process, with a manual clock (idle eviction, capacity, 413).                                                                                                                                                                   |
| `http/httpServerProcess.ts` | `bea mcp --http` as a subprocess: source mode through `scripts/lib/tsHooks.mjs` (no build), or dist mode with `BEA_DIST_DIR` (a snapshot).                                                                                                                                     |
| `http/pythonRecipe.ts`      | runs the docs/http.md Python recipe with the ABSOLUTE `sys.executable` resolved once under the real environment.                                                                                                                                                               |

Named skips are only for a missing toolchain, never for a failing behavior; put the reason in the test title
(`skipNote(reason)`).

The `http-boundary` lane runs in `npm test`: it starts subprocesses from the sources, sends two 65 MiB bodies, and
needs a system Python 3 for the recipe test (named skip otherwise). With `BEA_DIST_DIR` set it also runs four tests
against the BUILT server, two of them with real BEA sessions (game_sim spawned through MCP over HTTP, audited by the
owned-PID ledger); those need the gcc fixtures, Frida and the jobhost, and give named skips otherwise. Never run the bare `python` alias under a temp
`LOCALAPPDATA`: on Windows the Python install manager then bootstraps a fresh Python into the temp home (WP16
incident); resolve the interpreter's absolute path first, as `http/pythonRecipe.ts` does.

## Fixtures

`npm run build:fixtures` (and the acceptance globalSetup) builds `fixtures/native/*.c` and `fixtures/emu/*` into
`.cache/fixtures/<key>/` (all artifacts in one directory) with `manifest.json`: per artifact the sha256s, compiler
command and args, PE facts (`imageBase`, `exportRvas`, `.pdata` extents, sections, imports) and `expectations`
parsed from `objdump -d -M intel` (speed/rpm writers, crash sites, VEX functions …). Tests read RVAs from the manifest,
never from documents. The builder fails on a broken fixture invariant (see `fixtures/native/README.md`).

## Generated files and goldens

`npm run generate` writes `src/generated/packageMetadata.ts`, the per-area slices `tests/golden/catalog/<area>.json`
and `docs/tools/<area>.md` (owned by the area's work package), the indexes `tests/golden/catalog.json` and
`docs/tools.md`, and `docs/errors.md` + `docs/error-contract.schema.json`. `npm run check` fails on drift. Never edit or
hand-merge generated files: rerun the generator. In the shared tree, regenerate only your own area's slices with
`npm run generate -- --area <area>` (the shared index files are rewritten too; other areas' drifted slices are listed
and left to their owners). The generator runs on the TypeScript sources through Node's type transform
(`scripts/lib/tsHooks.mjs`), so contract files must be valid TypeScript that Node can execute (no decorators).
`npm run catalog:golden` (WP18) records the measured catalog budget in `tests/contracts/catalog-budget.json`; until then
`measured` is null and the drift check is inactive.

## The agent skill and documentation

The skill (`skills/bea-dynamic-analysis/`) is product surface and has its own checks:

- **Shape.** `SKILL.md` starts with the ownership marker `---
  name: bea-dynamic-analysis
  `, has at most 420 lines
  (target 350–420), and its authored frontmatter carries `metadata.version` equal to `package.json` `bea.skillVersion`
  but **no** `tool_count` or `bea_version`: `npm run build:skill` injects those and refuses a source that already has
  them. The nine `references/*.md` files are 60–200 lines each, and every relative link resolves.
- **Tool names.** Every tool the skill or its references name, and every `name {…}` call they show, exists in the
  catalog (`TOOL_CONTRACTS`, i.e. `tools/list`). Other systems' tools (REA's, Ghidra's) are named in prose, never as
  BEA calls.
- **Install round trip.** With a temp home (`CLAUDE_CONFIG_DIR` and `BEA_HOME` inside it), `bea setup --skill --yes`
  installs `dist/skills/bea-dynamic-analysis/`, and `bea doctor --skill` then reports the `skill` check healthy (name,
  `metadata.version` and `tool_count` equal to the bundled copy).
- **Recipes are scenarios.** Each recipe R1–R7 corresponds to one investigation scenario in
  `tests/acceptance/investigations/` (WP18), run against the gcc fixtures; a recipe change that the scenario does not
  follow is a bug in one of them.

Documents that quote numbers (limits, quotas, timeouts, tool counts) take them from the contracts and
`src/domain` (`HARD_LIMITS`, `GATE_SPECS`, `configFileSchema`, the limitation catalogs); when those change, update
`README.md`, `SECURITY.md`, `docs/security.md`, `docs/limitations.md` and the skill in the same change.
