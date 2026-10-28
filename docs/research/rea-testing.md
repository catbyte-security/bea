# REA testing & verification study, and a testing strategy for BEA

Key: `rea-testing`. Sources: REA clone at `<rea-checkout>` (read-only).
Lab: `<scratch>/bea-lab/rea-testing/`.

Labels: **VERIFIED** means I read the code or ran it on this host (Windows 11 x64, Node 24.18.0).
**BELIEVED** means it comes from docs or memory and I did not check it here.

---

## 0. TL;DR (decision-relevant)

1. REA's test philosophy is in `docs/testing.md:240-295`. Prefer real public CLI/MCP workflows first, then
   production-boundary integration, then goldens captured from real producers. Use module tests only
   for failures that the stronger layers cannot reproduce. Report a missing engine or authority as a
   **named skip**, never as a pass. BEA should adopt this as written.
2. REA uses **three MCP client harnesses**, and BEA needs all three:
   - **in-memory** `InMemoryTransport.createLinkedPair()` against the production `createServer()`
     (`tests/support/mcp/mcpFixture.ts:23-72`). Fast, deterministic, and used with injected fake providers.
   - **real stdio subprocess** `StdioClientTransport` → `node scripts/rea.mjs mcp`
     (`tests/fixtures/localToolsMcp.ts:37-106`). It validates every advertised input and output schema with Ajv2020.
   - **in-process production stdio** `serveStdio(factory, { transport: new StdioServerTransport(stdin, stdout) })`
     over `PassThrough` streams (`tests/boundary/mcp/serverLifecycleMcp.test.ts:224-314`). Use it to test
     stdin-EOF shutdown without spawning a subprocess.
3. REA has **no real-Frida test in Vitest**. All Frida MCP tests inject a hand-written fake `DeviceManager`
   through `new FridaInstrumentationManager({ deviceManager })` (`src/frida/FridaInstrumentationManager.ts:144-148`).
   They use promise "gates" to pin interleavings (`tests/boundary/mcp/fridaLifecycleMcp.test.ts:46-63,65-212`).
   Real Frida is checked by one script lane, `npm run verify:frida` (`scripts/verify-frida.mjs`). That lane is
   **Linux-only** per the docs, and it spawns a short-lived `node -e` target. BEA should go further: real-Frida
   lanes against compiled C fixtures on Windows are BEA's core evidence.
4. **Lab results** (VERIFIED, `bea-lab/rea-testing`, 7 tests, about 7 s, stable across 3 reruns, no leaked processes).
   I used a BEA-shaped stdio MCP server (`server.mjs`), a gcc-built PE fixture, and Vitest 5.0.3 with
   `StdioClientTransport`, and confirmed the following:
   - static PE export RVA + Frida `Process.mainModule.base` == runtime export address for all 6 exports.
     The image was ASLR-rebased away from `0x140000000`.
   - in-process `NativeFunction` calls work as oracles: `bea_add`, and an FNV-1a checksum compared against a JS reference.
   - **Unicorn emulation of `bea_step` (float/SSE) matched the in-process call bit-for-bit** on 3 inputs.
   - MCP cancellation (`AbortController` → `ctx.mcpReq.signal`) reaches the handler, and the server stays usable afterwards.
   - when the target exits, the session's `detached` signal fires, so a pending wait does not hang.
   - client close (stdin EOF) leads to server cleanup, and owned targets are killed.
5. **Two Windows hazards I found and reproduced** (VERIFIED). They shape BEA's lifecycle design and tests:
   - **SDK escalation budget.** `StdioClientTransport.close()` ends stdin, waits **2 s**, sends `SIGTERM`, waits 2 s,
     then sends `SIGKILL` (`node_modules/@modelcontextprotocol/client/dist/stdio.mjs:181-205`). On Windows,
     `SIGTERM` is `TerminateProcess`, so **no JS cleanup runs**. With 6 attached targets and an
     "unload → detach → kill" cleanup order, the server was terminated at 2019 ms. It never logged
     "cleanup", and **all 6 targets leaked**. When I changed the order to **kill first**, close took 20 ms
     with 0 leaks.
   - **Hard-killed server orphans targets.** A Frida-spawned target that does not depend on stdin **survives**
     when the server is killed with `taskkill /F` (`hardKillTargetSurvived: true`). The target's
     `ParentProcessId` is the server's node PID, so Frida local spawn makes a direct child. BEA needs a
     kill-on-close **Job Object** (or an external reaper) as a backstop. Tests must keep a ledger of owned
     target PIDs and reap orphans.
6. **Frida perf anomaly** (VERIFIED, reproducible). With `device.spawn(..., { stdio: "pipe" })`, from the
   **4th** concurrently attached target in one process, spawn takes 1.8–2.7 s and **every** RPC rises to
   340–680 ms. With `stdio: "inherit"`, 6 targets stay at about 16 ms per spawn and 1 ms per RPC. Keep at most
   3 concurrent piped targets per server in tests, or capture output another way. On Windows, inherited
   target stdout did **not** corrupt the MCP stdio channel (no client `onerror`). On POSIX it would
   (fd 1 is the protocol pipe). This POSIX risk is BELIEVED, not tested.
7. **Fixture builds.** MinGW gcc 16.1 output is **byte-reproducible** with `-Wl,--no-insert-timestamp`
   (VERIFIED: two builds to the same path give the same SHA-256). **MSVC is not usable on this host**
   (VERIFIED): VS 18 has `cl.exe` 14.51, but `vcvars64.bat` calls a missing `vcvarsall.bat`, and no Windows
   SDK (`Windows Kits/10/Include`) is installed. So gcc is the primary fixture compiler here, and MSVC
   becomes an optional, named-skip lane.
8. **Tooling.** TypeScript **7.0.2** is the native compiler (platform packages `@typescript/typescript-win32-x64`).
   On Windows, REA uses the official `tsc`; on Linux and macOS it uses `tsrs` (Rust), selected in
   `scripts/run-typescript.mjs:10-22`. REA's strict tsconfig typechecked my BEA harness sketch in about 2 s
   (VERIFIED). oxlint 1.87 and oxfmt 0.72 ran with REA's configs in about 1 s and 10 ms (VERIFIED).
   BEA should copy tsconfig, oxlint, oxfmt and the knip strict rules, plus husky and lint-staged.
   It should **not** copy Turbo, tsrs, Stryker, jscpd, the CI sequencer or sharding until the project is big.

---

## 1. Where REA's testing knowledge lives

| File | What it is |
|---|---|
| `docs/testing.md` (1882 lines) | Canonical guide. Commands :8-27, choosing verification :229-238, **test design & pruning :240-295**, **lifecycle regressions :296-435**, **behavioral depths :436-493**, e2e/golden :495-508, coverage/timing/CI :510-724, real-toolchain lanes :726+, **Frida lane :1842-1852** |
| `CONTRIBUTING.md` | Dev setup :201-241 (Windows checkouts need the native addon), feedback & PR verification :281-317, generated files :318-343, temp files :345-357 |
| `vitest.config.ts` (186 lines) | Project policies, coverage thresholds, custom runner |
| `vitest.reverse-tools.config.ts`, `vitest.reverse-tools-semantics.config.ts` | Focused suites for mutation testing (Stryker) |
| `scripts/lib/test-projects.mjs:4-107` | **Canonical test ownership**: glob → project. Shared by Vitest, CI and dev runners. `projectForTest()` requires exactly one owner |
| `tests/processOwnershipRunner.ts:6-18` | Custom Vitest `TestRunner` that closes a native process-ownership host at worker teardown |
| `tests/support/**` | Reusable test-scoped fixtures (mcp, cli, process, workspace) |
| `tests/fixtures/**` | Immutable artifacts plus some harness modules (`localToolsMcp.ts`, `mcpToolError.ts`, `temporaryDirectory.ts`, `processFinalization.mjs`) |
| `scripts/verify-*.mjs`, `scripts/verify/**` | Real-provider lanes outside Vitest (`npm run verify:*`) |

Counts (VERIFIED): `tests/**/*.ts` = 1359 files; colocated `src/**/*.test.ts` = 753; `tests/boundary/mcp` = 188 files.

---

## 2. Test layering ("behavioral depths")

`docs/testing.md:436-446` (VERIFIED):

| Depth | Location | Proves |
|---|---|---|
| Module | `src/**/*.test.ts` | One domain, service or adapter through its narrow public surface |
| Composition | `tests/composition/**` | Provider-neutral session and registry wiring; no FS/process/network crossing |
| Boundary | `tests/boundary/**` | Exactly **one** production boundary (FS, process, network, browser, CLI or provider) |
| MCP boundary | `tests/boundary/mcp/**` | MCP transport and tool contracts, with isolated sessions and explicit cleanup |
| Acceptance | `tests/acceptance/**` | A compiled CLI or MCP journey (injected providers still count as integration) |
| Conformance | `tests/conformance/**` | Shared provider contracts, parameterized by declared capabilities |
| Evaluation | `tests/evaluation/**` | Deterministic evaluator logic |

Lint enforces the rules (`.oxlintrc.json:53-94`, VERIFIED):

- `src/application/**/*.test.ts` may not import `**/server/**`, `**/cli.*` or `**/main.*`. Service tests use ports.
- `tests/composition/**` may not import server, cli, main, `node:child_process`, `node:net`, `node:http(s)`, `ws` or `playwright`.

Project mapping (`scripts/lib/test-projects.mjs`, VERIFIED):

- **Source group (no build):** `domain`, `services`, `adapters`, `composition`, `conformance`, `evaluation`.
- **Built group (compiled dist):** `boundary`, `cli-boundary`, `process-boundary`, `mcp-boundary`, `acceptance`, `process-global`.

`process-global` is reserved for tests that mutate env or exit status, or use module mocks. These run in isolated forks.

Per-project runner policy (`vitest.config.ts:39-103`, VERIFIED):

```ts
const MAX_TEST_WORKERS = Math.min(2, availableParallelism());      // :36
domain/services/composition/conformance/evaluation: pool "threads", isolate:false
adapters/boundary/acceptance/process-global:        pool "forks"   (per-file isolation)
"cli-boundary":   forks, isolate:false, execArgv --max-old-space-size=384|512 (coverage)
"process-boundary": forks, fileParallelism:false, sequence.groupOrder:1   // serial, runs last
"mcp-boundary":   threads, isolate:false  // "Each file creates and closes an explicit in-memory MCP session"
```

Global settings (`vitest.config.ts:140-186`):

- `retry: 0` (no flake masking).
- `testTimeout: 30_000` (60 s with coverage).
- `runner: "./tests/processOwnershipRunner.ts"`.
- `env: { TMPDIR: realpathSync(tmpdir()) }`, which canonicalizes the temp path.
- v8 coverage thresholds: 65/60/60/68 overall; `src/domain/**` 80/75/75/80; `src/contracts/**` 85/80/80/85.
- With `--shard`, thresholds drop to zero because CI merges blob reports.

Why only two workers: measured. Going from 2 to 4 workers on a 4-core host cut a 6-file acceptance sample
from 96–101 s to 71 s, but did not remove the single-file floor (`docs/testing.md:688-692`).

---

## 3. Test design rules worth copying verbatim

From `docs/testing.md:240-295` and `:296-435` (VERIFIED, paraphrased tightly):

- Prefer public CLI/MCP workflows, then production-boundary integration, then goldens from real producers.
  "Paths, compiled imports, and suite names do not establish test depth."
- Prune tests that mirror implementation details or duplicate a stronger claim. **Keep** regressions for
  malformed formats, cancellation, cleanup, permissions, capacity, target identity, and combinations
  with distinct interactions.
- Use representative scenarios, not Cartesian matrices.
- For `Result` values, throw the typed error before asserting the value.
- **Protocol fixtures must reject unmodeled commands and preserve the real producer reply shapes.**
  Example: the fake gdb in `tests/boundary/mcp/gdbCancellationMcp.test.ts:35-60`.
- Stateless analysis matrices may share one file-owned stdio MCP connection. **Session-lifecycle scenarios need
  their own sessions and cleanup assertions.**
- When a matrix holds a tool definition from a live `tools/list`, pass it via the SDK `toolDefinition` call
  option. "A fresh SDK client has no held tool listing, so a bare `callTool` can skip output-schema validation."
- **Report unavailable authority as a named skip. Await owned cleanup before reporting success.**
- Lifecycle (`:319-326`): "Synchronize cancellation with the finalization boundary being tested; a fixed delay
  after dispatch does not establish that phase. Use markers, barriers, or owned cleanup seams…
  Check server settlement and retained resources even if the MCP SDK rejects the client promise before the
  handler finishes." Also: "Use explicit abort reasons and assert their identity."
- Supervisor tests must observe **process exit, output-pipe closure and IPC disconnection separately**.
  "Process exit alone does not establish pipe or process-tree release" (`:416-420`).
- Windows command supervision: "keep a descendant writing after its leader exits … verify a competing writer
  remains excluded until the exact Job Object closes. Portable doubles cover retry logic; the native Windows
  lane must establish actual process-tree behavior" (`:409-414`).
- Lifecycle scenario table (`:303-311`). It covers:
  - admitted target, startup still pending;
  - late, absent or invalid handshake;
  - launch error with a valid handle;
  - cancellation after workload exit, during result reads, or during temp-root removal;
  - mixed child health;
  - cleanup failure after success or failure;
  - target exits without an ack, or transport disappears while the target stays alive.

  BEA should adopt this table nearly 1:1 for its attach/spawn/hook/trace sessions.
- Real-toolchain lanes (`:739-744`): "Each real-toolchain command must require only the host tools needed to
  prove its stated claim … Check prerequisites before starting expensive work and name the missing command,
  target, and lane in any failure message. A lane must not imply that a host or target is covered when it
  was skipped."

Named-skip helper (`tests/boundary/process/processCaptureCapability.ts:5-22`, VERIFIED):

```ts
/** … A bare `if (!available) return;` inside the test body made an
 * entire lane report green without executing anything. */
export const CAPTURE_CAPABILITY = await probeProcessCaptureCapability();
export const CAPTURE_SKIP_REASON = CAPTURE_CAPABILITY.available
  ? false
  : `requires native process-capture authority: ${CAPTURE_CAPABILITY.reason}`;
export const itWithCaptureCapability = CAPTURE_CAPABILITY.available ? it : it.skipIf(CAPTURE_SKIP_REASON);
```

---

## 4. REA's MCP client test harnesses (key snippets)

### 4.1 In-memory client ↔ production server (fast lane)

`tests/support/mcp/mcpFixture.ts:23-72` (VERIFIED):

```ts
export const createTestMcp = (): TestMcp => {
  const connections: { readonly client: Client; readonly server: McpServer }[] = [];
  return {
    connect: async (server, identity = DEFAULT_CLIENT_IDENTITY) => {
      const client = new Client(identity);
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      try {
        await server.connect(serverTransport);
        await client.connect(clientTransport);
      } catch (cause) {
        await Promise.allSettled([client.close(), server.close()]);
        throw cause;
      }
      connections.push({ client, server });
      return client;
    },
    close: async () => {
      const results = await Promise.allSettled(
        [...connections].reverse().map(async ({ client, server }) => {
          try { await client.close(); } finally { await server.close(); }
        }),
      );
      const failure = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
      if (failure !== undefined) throw failure.reason;
    },
  };
};
export const mcpTest = base.extend<{ mcp: TestMcp }>({
  mcp: async ({}, use) => { const mcp = createTestMcp(); try { await use(mcp); } finally { await mcp.close(); } },
});
```

Usage with the production composition: `tests/support/mcp/productionSession.ts:11-33`. It does
`createServer({ kind: "session", session })`, registers `onTestFinished(session.close)`, then calls `open_binary`
and asserts `isError !== true`.

Imports: `Client, InMemoryTransport` from `@modelcontextprotocol/client`; `McpServer` from `@modelcontextprotocol/server`.

### 4.2 Real stdio subprocess with schema validation (acceptance lane)

`tests/fixtures/localToolsMcp.ts:37-106` (VERIFIED):

```ts
import { Client, type CallToolRequestOptions } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";

export async function connectLocalToolsMcp(
  environment: Readonly<Record<string, string>> = {},
  registerCleanup: (cleanup: () => Promise<void>) => void = onTestFinished,
) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL("../../scripts/rea.mjs", import.meta.url)), "mcp"],
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      REA_LOG_LEVEL: "silent",
      HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",   // force deep providers off
      ...environment,
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "local-tools-e2e", version: "1" });
  registerCleanup(async () => { await client.close(); await transport.close(); });
  await client.connect(transport);
  const tools = (await client.listTools()).tools;
  // validate every advertised input/output schema against the JSON Schema 2020 meta-schema (cached)
  for (const tool of tools) for (const [kind, schema] of [["inputSchema", tool.inputSchema], ["outputSchema", tool.outputSchema]] as const) { … schemaValidator.validateSchema(schemaRecord) … }
  const definitions = new Map(tools.map((tool) => [tool.name, tool]));
  const call = async (name: string, arguments_: Record<string, unknown>,
                      options?: Pick<CallToolRequestOptions, "signal" | "onprogress">) => {
    const definition = definitions.get(name);
    if (definition !== undefined) compileValidator(definition.inputSchema);
    const response = await client.callTool({ name, arguments: arguments_ },
      { ...options, ...(definition === undefined ? {} : { toolDefinition: definition }) });
    if (response.structuredContent !== undefined && definition?.outputSchema !== undefined) {
      const validate = compileValidator(definition.outputSchema);
      expect(validate(response.structuredContent), JSON.stringify(validate.errors)).toBe(true);
    }
    return response;
  };
  return { client, call };
}
```

Notes:

- The child gets a **minimal env**: PATH plus explicit variables, not `process.env`. On Windows, REA's CLI fixture
  also passes `SystemRoot`, `TEMP` and `TMP` (`tests/support/cli/cliFixture.ts:216-231`). I hit the same need in my lab.
- The typed error envelope is parsed in `tests/fixtures/mcpToolError.ts:8-16`: `isError === true`, then the text
  content is parsed as JSON and checked strictly against `analysisErrorProjectionSchema`.

### 4.3 File-scoped shared stdio server (speed)

`tests/support/cli/cliFixture.ts:83-189` (`createSharedMcpSession`) and `:295-359` (`cliTest` fixture), VERIFIED:

- `cliCompileCache` is **worker-scoped**: a temp `NODE_COMPILE_CACHE` dir shared by fresh CLI children.
- `mcpSession` is **file-scoped**: at most one stdio server per test file, started lazily on the first `sharedMcpCall()`.
- Close waits for any startup still in flight. A failed cleanup stays owned and is retried. No new server
  starts while cleanup is pending. A handshake failure stays the primary error, with the cleanup failure
  kept as an `AggregateError` cause (`:63-75`).
- `cli` is **test-scoped** and spreads `sharedMcpCall`/`sharedCliRun`. Commands with stdin or explicit
  deadlines still get a fresh process.
- `tests/support/cli/cliCommandSession.ts:15-19`: the shared CLI process restarts after 32 commands or at 1 GiB RSS.

The docs rule (`docs/testing.md:180-194`): stateless cases share a server. Pass `mcpCall` when a case needs
its own server, environment or lifecycle.

### 4.4 In-process production stdio over PassThrough (shutdown tests without a child)

`tests/boundary/mcp/serverLifecycleMcp.test.ts:224-314` (VERIFIED):

```ts
const stdin = new PassThrough(); const stdout = new PassThrough();
const started = await startMcpTransport({
    env: {}, serve: (factory, options) =>
      serveStdio(factory, { ...options, transport: new StdioServerTransport(stdin, stdout) }),
    createServer: (source, options) => createServer(source, { ...options, sqliteDatabase }),
    writeStderr: () => undefined, setExitCode: () => undefined, registerShutdown: () => () => undefined },
  session, { … });
stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "…", version: "1.0.0" } } })}\n`);
…
if (shutdown === "stdin") { stdin.end(); await new Promise((r) => setImmediate(r)); }
await expect(started.handle.close()).rejects.toBeInstanceOf(AggregateError);   // cleanup denied → retained
removalAllowed = true; await started.handle.close();                          // retry succeeds
await started.handle.close(); expect(attempts).toBe(completedAttempts);       // idempotent
```

All process-level hooks (`serve`, `writeStderr`, `setExitCode`, `registerShutdown`) are injected through
`RuntimeDependencies`. That makes the shutdown code testable: see `tests/boundary/mcp/shutdown.test.ts:19-72`,
which uses a `StdioServerHandle` whose `close` rejects. **BEA should keep the same injection seam.**

### 4.5 Handler-only harness (unit-level tool handlers)

`tests/support/reverseEngineeringMcpHarness.ts:5-33`: a fake `McpServer` with only `registerTool`, storing
the handlers. `invokeWithLiveSignal(handler, input)` calls `handler(input, { mcpReq: { signal } })`.
This shows that the **v2 SDK handler context carries the abort signal at `ctx.mcpReq.signal`**. I confirmed
that in my lab server.

### 4.6 HTTP listener

`tests/support/mcp/streamableHttpProcess.ts:40-99`: spawns `rea mcp --http --port 0` and parses the pino JSON
stderr for `{"msg":"MCP transport listening","url":…}`, with a 30 s startup deadline. If the child exits
early, the test fails with the stderr attached. BEA only needs this if it ships HTTP.

### 4.7 Script-lane (non-Vitest) stdio verifier

`scripts/lib/artifact-e2e.mjs:13-66,122-175` (VERIFIED):

- `advertisedTool()` binds `tools/list` to the negotiated connection (`client.getServerVersion()` identity)
  and rejects duplicate tool names.
- `artifactMcpCall()` **refuses caller-supplied `toolDefinition`**, always validates against the advertised
  schema, and requires an `outputSchema`.
- `withArtifactMcp(target, verify)` spawns stdio, calls `open_binary`, runs `verify(client)`, then runs
  `closeVerifierResources([client.close, transport.close], failure)`.
- `closeVerifierResources` (`scripts/lib/verifier-cleanup.mjs:1-17`) attempts every cleanup and throws an
  `AggregateError` that keeps the primary failure.

---

## 5. Process and workspace fixtures

`tests/support/process/processFixture.ts` (VERIFIED):

- `createTestProcessRegistry()` (`:74-166`) tracks every spawned child in a Set.
- `run()` has a timeout that escalates SIGTERM → SIGKILL after 1 s, and a timed-out run throws with the
  captured result as `cause`.
- `shutdown()` stops every child in reverse order (`stopChild` :63-71). It **throws if any child is still
  registered** ("N test child process(es) leaked") or one does not exit after SIGKILL.
- `processTest = base.extend({ processes })` (`:169-179`) runs shutdown in `finally`.

`tests/support/workspace/workspaceFixture.ts:28-79`: `createTestWorkspace()` builds a realpath'd temp root with
`home/` and `xdg/{config,cache}`, and its `environment` projection redirects HOME and XDG. `path()` refuses `..`
escapes. Removal uses `rm(..., { maxRetries: 3, retryDelay: 25 })`, which matters on Windows because of file locks.

`tests/fixtures/temporaryDirectory.ts:21-33`: `createTestTempDirectory(prefix)` adds `onTestFinished` removal.
`npm run verify:test-temp-hygiene` runs the suite under a fresh TMPDIR and fails on leftover `rea-*` paths
(CONTRIBUTING.md:345-351).

`tests/support/hostCleanup.ts:71-120` tolerates **only one** named host flake (an unreadable ownership token on
Linux) and checks its exact shape. A general "cleanup may fail" escape hatch is not allowed.

Process-target fixture `tests/fixtures/processFinalization.mjs` (VERIFIED). It has modes `cooperative`, `ignoring`,
`delayed-ignoring`, `exits` and `descendant` (a SIGTERM-ignoring detached child). It writes `pid.txt` and
report files that tests poll. The acceptance test `tests/acceptance/process/processFinalization.test.ts` drives the
same scenario through both CLI (`runCliJson`) and MCP (`connectLocalToolsMcp`). **BEA's C fixtures should
copy this "modes by argv" design** (I did: `serve`/`hold`/`exit`/`crash`).

---

## 6. How REA tests Frida

### 6.1 Fake native layer injected through the manager constructor

`src/frida/FridaInstrumentationManager.ts:118-148` (VERIFIED):

```ts
readonly deviceManager?: DeviceManager;
readonly deviceManagerLoader?: () => Promise<DeviceManager>;
constructor(options: FridaInstrumentationManagerOptions = {}) {
  this.#deviceManager = options.deviceManager;
  this.#deviceManagerLoader = options.deviceManagerLoader ?? (async () => (await import("frida")).getDeviceManager());
}
```

The `frida` binding is an **optionalDependency** loaded lazily with `import("frida")`. Types come from REA's
own **narrowed shim** `src/frida/frida-bindings.d.ts` (81 lines, `declare module "frida" { … }`). That way
typecheck never depends on the binding being installed. A separate check,
`scripts/verify/fridaBindingsCompatibility.ts:1-28` plus `tsconfig.frida-verification.json` (run with
`npm run verify:frida:bindings`), asserts the vendor types still fit the shim:

```ts
import type { Device as VendorDevice, … } from "../../node_modules/frida/build/src/frida_binding.js";
import type { Device, DeviceManager, Script, Session } from "frida";
type Assert<Condition extends true> = Condition;
type VendorDeviceFitsShim = Assert<VendorDevice extends Device ? true : false>;   // fails on API narrowing
```

**BEA should copy this exact pattern**: a shim, a compatibility assertion and a lazy import.

### 6.2 Lifecycle tests with gates

`tests/boundary/mcp/fridaLifecycleMcp.test.ts` (1436 lines, VERIFIED). It does not use real Frida.

- `gate()` (`:46-63`) returns `{ entered, release, wait }`. The fake native call awaits `wait()`, and the test awaits
  `entered`, so it knows **exactly** which phase is held.
- `nativeFixture()` (`:65-212`) builds fake `Session`/`Script`/`Device`/`DeviceManager` objects with control knobs:
  `controls.attach|create|load|resume|detach|discover` hooks, plus counters `unloadFailures`, `detachFailures`,
  `detachCalls`, `resumes`, `remoteRemovals` and `removalFailures`, and `markDetached()`.
- `connectedFixture()` (`:214-257`) creates the production `createServer({kind:"session",session},{fridaInstrumentation: manager})`
  with an in-memory client. Its `onTestFinished` resets the failure knobs, then closes client, server,
  `manager.closeAll()` and the session.
- Cancellation (`:500-559`):

  ```ts
  fixture.controls.resume = async () => { await held.wait(); fixture.controls.resume = async () => {}; throw new Error("native resume rejected"); };
  const controller = new AbortController();
  const pending = fixture.client.callTool({ name: "instrument_with_frida", arguments: {…} }, { signal: controller.signal }).catch((c) => c);
  await held.entered;
  controller.abort(new Error("cancel pending resume"));
  await fixture.client.ping();               // round-trip ⇒ server processed notifications/cancelled
  expect(serverSignal?.aborted).toBe(true);
  held.release(); await pending;
  await vi.waitFor(() => expect(delivery).toHaveBeenCalledOnce());   // server-side settlement, not client promise
  expect(fixture.controls.detachCalls).toBe(1); expect(fixture.unloaded).toEqual(["resume-failure"]);
  ```

- Server shutdown during an in-flight attach (`:1216-1251`): the first `server.close()` rejects with an
  `AggregateError` (detach failed once). The second close retries detach and the third is a no-op. After that,
  `startSession` returns `AnalysisCapabilityUnavailableError`.
- Other titles show the matrix to copy:
  - "preserves observed detachment through resume settlement" (attached, during-resume, after-resume);
  - "retains detached state and resume evidence when remote cleanup needs retry";
  - "retains the identity of a cancelled native create/load for an explicit MCP unload retry";
  - "drains remote discovery before shutdown and retains failed connection cleanup".

`tests/boundary/mcp/fridaMcp.test.ts:17-91` uses a whole fake `FridaInstrumentationPort` (application port level)
for evidence and summary-view contract tests. `tests/boundary/cli/fridaCli.test.ts` covers the CLI mapping.

### 6.3 The only real-Frida check

`scripts/verify-frida.mjs` (VERIFIED code; docs say Linux-only, `docs/testing.md:1842-1852`):

```js
input = { mode: "spawn", deviceId: "local", program: process.execPath,
          argv: ["-e", "setTimeout(() => {}, 1500)"],
          source: { sourceKind: "inline", source: "send({ rea_frida_verification: 'ok', pid: Process.id });" },
          durationMs: 500 };
const result = await service.instrument(input);
… assert a 'send' message with payload.rea_frida_verification === 'ok' && payload.pid === observed.pid
report = { ok: cleanupError === null, provider: "frida", host_platform, target_mode: "local_spawn", target_pid, … };
await closeVerifierResources([() => manager.closeAll()], primaryFailure);
```

It prints a JSON **receipt** to stdout, and a non-zero exit carries every cause. Remote mode is
`--address HOST:PORT --pid PID`; an explicitly selected process is required and auth values are never written out.
**Gap for BEA:** this exercises no native target code, no hooks, no memory and no Windows.

---

## 7. Native fixture production in REA

`scripts/build-conformance-fixtures.mjs` (262 lines, VERIFIED), linux/macOS only:

- Compiler: `process.env.CC ?? "cc"`. Linux flags `-O0 -g -fno-inline -fno-omit-frame-pointer -fno-pie -no-pie` (`:238-256`);
  macOS uses `xcrun clang -arch … -isysroot …`.
- `build()` (`:183-215`) records a **manifest** entry per artifact: `artifactSha256`, `sourceSha256`, per-source
  digests, `compiler.{path,version,arguments}` and `expectations` (symbols, strings, oracles).
  The manifest has `generatedAt: new Date(0)` for determinism.
- Fixture source `tests/conformance/c/fixture.c`: `__attribute__((noinline, used))` functions with known
  semantics (`rea_entry` → `rea_branch` → `rea_leaf`, `main` returns `rea_entry() == 12 ? 0 : 1`) and marker strings.

Windows fixtures are **cross-compiled on Linux CI** with MinGW (`.github/workflows/ci.yml:636-644`):
`x86_64-w64-mingw32-g++ -municode -std=c++17 -O2 -static … tests/fixtures/windows/processBoundary.cc -ladvapi32`.
The result is uploaded as an artifact for the Windows job. The source is `tests/fixtures/windows/processBoundary.cc`
(a `wmain` with modes such as `environment` and `affinity`, printing JSON).

Real-debugger lane `scripts/verify-native-calls.mjs` (macOS LLDB, VERIFIED code). This is the closest analogue to BEA:

- It checks prerequisites first and names the missing tool (`:19-31`).
- It compiles the fixture into a temp dir and runs the **same scenario via CLI and stdio MCP**, then asserts
  `deepEqual(stable(viaMcp), stable(viaCli))`. `stable()` (`:56-68`) projects **pointer-free facts**:
  breakpoint index, symbol, file_address, selector, counter.
- **Static oracle:** `file_address` must equal `nm -n` output (`:70-75,115-117`).
- Bounds: 2 MiB stdout/stderr flood truncation, `max_events` → `outcome: "event-limit"`, and
  `duration-elapsed`; after each, `alive(pid) === false` via `process.kill(pid, 0)` (`:119-126`).
- Negative authority: a hardened-runtime copy must fail with `capability_unavailable` /
  `debugger-attach-denied`, the same on CLI and MCP, with `partial_observation` present.
- The receipt is `{ ok, mocked: false, cli: true, stdio_mcp: true, debugger: version, outcomes: [...] }`.

---

## 8. Lifecycle and shutdown code under test

`src/main/processShutdown.ts:34-51` (VERIFIED):

```ts
export const registerProcessShutdown = (handler, events = { signals: process, stdin: process.stdin }) => {
  events.signals.on("SIGINT", onInterrupt); events.signals.on("SIGTERM", onTerminate);
  events.stdin?.on("end", onInputEnd); events.stdin?.on("close", onInputEnd);
  return () => { /* off(...) all four */ };
};
```

There is also `latchSignalShutdown` (`:72-92`). During startup it records the first signal and exits immediately
on a second one, so startup never dies without its cleanup. `createExitStatus` keeps 130 or 143 after a
signal even when the entry returns 0.

Shutdown tests (`tests/boundary/mcp/shutdown.test.ts`) cover:

- the transport close rejecting → exit code 1, a stable stderr message, and the cause at debug level;
- a typed provider cleanup failure → retained, so a second signal retries it;
- "retries only failed cleanup owners after concurrent shutdown requests";
- a repeated SIGTERM via an injected `EventEmitter` signal source.

---

## 9. Tooling configuration (what it is, and copy or not)

### 9.1 TypeScript 7

- `typescript@7.0.2` (VERIFIED in node_modules). It is the native compiler, with `bin.tsc` plus
  `@typescript/typescript-<platform>-<arch>` optional packages. REA also pins `tsrs@0.18.0-ts7.1.0-dev.…`
  (a Rust checker), `typescript6` (`npm:typescript@6.0.3`, BELIEVED to be for Stryker's compiler-API checker)
  and `typescript-termux` (5.9.3).
- `scripts/run-typescript.mjs:10-22` picks the compiler: `typescript` on win32, otherwise `tsrs` if the platform
  package exists. For tsrs it injects `--checkers min(2,cpus)` and `--maxMemory 3G`. `scripts/run-turbo.mjs`
  exports `REA_TYPESCRIPT_COMPILER` so the Turbo cache keys include the compiler identity.
- Scripts: `typecheck` = `node scripts/run-typescript.mjs --noEmit`. `compile` = clean → `-p tsconfig.build.json`
  → record catalog digests → `bundle-runtime.mjs` (rolldown).
- `tsconfig.json` (VERIFIED, copy as-is):

  ```json
  { "compilerOptions": { "allowUnreachableCode": false, "allowUnusedLabels": false,
    "exactOptionalPropertyTypes": true, "forceConsistentCasingInFileNames": true, "lib": ["ES2023"],
    "module": "NodeNext", "moduleResolution": "NodeNext", "noFallthroughCasesInSwitch": true,
    "noImplicitOverride": true, "noImplicitReturns": true, "noUncheckedIndexedAccess": true,
    "outDir": "dist", "rootDir": ".", "skipLibCheck": true, "strict": true, "target": "ES2023",
    "types": ["node"], "verbatimModuleSyntax": true },
    "include": ["src/**/*.ts", "tests/**/*.ts", "vitest.config.ts", "docs/.vitepress/config.ts"] }
  ```

  `tsconfig.build.json` extends it with `rootDir: src` and excludes `*.test.ts`, `*.fixture.ts` and `tests`.
- Lab (VERIFIED): `typescript@7.0.2` typechecked a BEA harness sketch (`ts/mcpHarness.ts`, which imports the
  SDK v2 client, StdioClientTransport and zod 4) under the strict config in about 2.1 s on Windows, with exit 0.
- **BEA:** copy the tsconfig pair and use plain `tsc` from `typescript@7.x`. Skip `tsrs`, the compiler-identity
  plumbing and Termux. Vitest transpiles TS itself, so typecheck stays a separate script.

### 9.2 oxlint (`.oxlintrc.json`, VERIFIED)

- Plugins: `typescript`, `import`, `unicorn`, `oxc`.
- Warning-level budgets: `complexity` 20, `max-depth` 4, `max-lines` 500, `max-lines-per-function` 100,
  `max-params` 4.
- Errors: `no-var-requires`, `typescript/no-import-type-side-effects`.
- Tests: `max-lines` off, `max-lines-per-function` raised to an **error** at 150.
- `no-restricted-imports` layering for service and composition tests (see §2).
- `npm run lint` wraps oxlint with a report writer and **also runs `verify:module-boundaries`**
  (a custom import-graph checker, `scripts/verify-module-boundaries.mjs`).
- Lab: oxlint 1.87.0 with REA's config ran over my lab in about 1 s, and it flagged a real
  `no-unsafe-finally` in my fixture (fixed).

### 9.3 oxfmt (`.oxfmtrc.json`, VERIFIED)

`{ printWidth: 80, sortImports: false, sortPackageJson: false, ignorePatterns: [dist, build, docs/api, node_modules, CHANGELOG.md, package-lock.json, third_party] }`.
Scripts: `format` = `oxfmt .`, `format:check` = `oxfmt --check .`. Lab: 12 files in 10 ms.

### 9.4 knip (`knip.json`, VERIFIED)

- Explicit `entry` list: `src/main.ts`, `src/cli.ts`, worker entrypoints, verifier `.ts` files and
  `tests/processOwnershipRunner.ts`.
- `project` covers `src`, `tests` and `scripts`.
- Every rule is an `error`: files, dependencies, exports, types, enumMembers, duplicates.
- `ignoreDependencies` lists tools that are only spawned.

**BEA: copy, with BEA's entries.** List the Frida agent bundle entry, and any native helper or Unicorn worker
scripts.

### 9.5 Turbo (`turbo.json`, VERIFIED)

Tasks: `compile`, `typecheck`, `lint`, `lint:built`, `format:check`, `knip`, `jscpd`, `scan:todos`,
`test:run` (`cache:false`), `artifacts:*` generators and `*:check:built`.

- Global dependencies are `.nvmrc` and `.npmrc`.
- `check` = `run-exclusive.mjs artifacts run-turbo.mjs run typecheck lint:built format:check knip metadata:check && verify:architecture-guards`.
- Everything goes through `scripts/run-exclusive.mjs` (an SQLite lock, and a Windows Job Object via the native addon).

**BEA: defer Turbo.** It pays off at about 400K lines with generated catalogs. A single
`npm run check` = `tsc --noEmit && oxlint && oxfmt --check . && knip` is enough at first.

### 9.6 Other REA tooling

| Tool | Notes |
|---|---|
| Husky + lint-staged | pre-commit runs `npx --no-install lint-staged` (`oxfmt` and `oxlint --fix` on staged JS/TS; `oxfmt` on JSON/MD/YAML). pre-push runs `npm run check:fast`. **Copy.** |
| `@fast-check/vitest` | Property tests in 6 files (for example `src/domain/evidence.test.ts:16 it.prop([fc.jsonValue()])`). **Copy for BEA's Evidence/canonical-digest and address-math (rebasing) domain code.** |
| Stryker | Mutation testing over a curated module list (`vitest.reverse-tools.config.ts`, `stryker.config.mjs`). **Defer.** |
| `jscpd` | Duplication checks. **Defer.** |
| `verify:test-discovery` | `scripts/verify-test-discovery.mjs` compares `vitest list --filesOnly --json` with `git ls-files src tests`, so a test file outside every project glob fails CI. **Copy (cheap and catches dead tests).** |
| `tests/ciTestSequencer.ts` | CI timing-history sharding. **Defer.** |
| `.npmrc` / Node pin | `.npmrc` has `engine-strict=true`; `.nvmrc` pins `24.18.0`; `packageManager` is `npm@11.16.0`. The package.json `allowScripts: { "frida@17.23.2": true }` is needed because npm 11 gates install scripts. In my lab, npm warned about frida's install script, but the binding (`frida_binding.node`, 135 MB) was present and worked. That is BELIEVED to come from the npm cache or a prebuilt tarball; add `allowScripts` anyway. |

---

## 10. Lab experiments (all VERIFIED on this host)

Location: `<scratch>/bea-lab/rea-testing/`

| File | Purpose |
|---|---|
| `package.json` | Local-only deps: `@modelcontextprotocol/server|client@2.3.1`, `zod@4.4.3`, `vitest@5.0.3`, `frida@17.23.2`, `typescript@7.0.2`, `oxlint@1.87.0`, `oxfmt@0.72.0`, `@types/node@26.6.4` |
| `fixtures/bea_fixture.c` | Deterministic C fixture. Exports `bea_counter`, `bea_marker`, `bea_add`, `bea_checksum` (FNV-1a), `bea_tick` (the only writer of `bea_counter`) and `bea_step` (float). Modes: `serve` (stdin line protocol, exits on EOF), `hold` (ignores stdin), `exit` (returns 7) and `crash` (null write) |
| `fixtures/build.mjs` | gcc build keyed by sha256(source, compiler version, args), with a manifest of artifact/source hashes, compiler identity and a **PE32+ export parser** used as the static oracle (`imageBase`, `dynamicBase`, `exportRvas`) |
| `server.mjs` | BEA-shaped stdio MCP server (`serveStdio(createServer)`). Tools: `spawn_process`, `list_exports`, `read_memory`, `call_function`, `call_function_f32`, `checksum_oracle`, `wait_for_exit` (cancellable) and `kill_process`. Shutdown on stdin end/close or SIGINT/SIGTERM, with kill-first cleanup |
| `tests/globalSetup.mjs` | Builds fixtures once per run; `provide("fixture", manifest)` |
| `tests/support.mjs` | `connectBea()` (StdioClientTransport) and `beaTest` fixture with an owned-PID ledger and leak assertion |
| `tests/workflow.test.mjs` | spawn → exports rebased from static RVAs → marker memory → oracle calls → write visible via read |
| `tests/lifecycle.test.mjs` | stdin-EOF cleanup, cancellation, target-exit detach, hard-kill orphan probe (`serve` and `hold`) |
| `tests/differential.test.mjs` | Unicorn (`emu_step.py`, run with `python -I`) vs in-process `bea_step`, compared bit-for-bit |
| `emu_step.py` | pefile + unicorn: map image at preferred base, stack, sentinel return page `0x1000`, XMM0/XMM1 args, `emu_start(BASE+rva, SENTINEL, count=10000)` (the same technique as the user's harnesses) |
| `ts/mcpHarness.ts`, `tsconfig.json` | TS7 strict typecheck of a harness sketch |

Results:

```
✓ workflow  > spawn -> exports rebased from static RVAs -> memory -> in-process oracle calls   ~0.9-1.2s
✓ lifecycle > client close (stdin EOF) makes the server kill owned targets                      ~0.9s
✓ lifecycle > MCP cancellation reaches the handler and the server stays usable                  ~0.9s
✓ lifecycle > target exit is observed as a detach, not a hang                                    ~0.9s
✓ lifecycle > hard-killed server … serve target  → {"hardKillTargetSurvived":false}  (EOF on frida-owned stdin pipe)
✓ lifecycle > hard-killed server … hold target   → {"hardKillTargetSurvived":true}   (orphan; test reaps it)
✓ differential > Unicorn emulation of bea_step matches the in-process call bit-for-bit           ~1.0s
Test Files 3 passed, Tests 7 passed, Duration ~7s; 3 reruns stable; tasklist shows 0 bea_fixture* after.
```

Measurements (single fresh server):

- connect: about 140 ms.
- `tools/list`: about 5 ms.
- **first** Frida spawn+attach+load+resume: about 680–720 ms (frida-core warm-up in a fresh process).
- later spawns: about 16 ms.
- RPC `call_function`: about 1 ms.
- `read_memory`: about 1–2 ms.
- close plus reap: about 20 ms (kill-first).

So per-test server startup costs about 0.8 s. A file-scoped shared server (REA §4.3) would remove most of it
for stateless cases.

Other facts:

- PE fixture: `imageBase 0x140000000`, `dynamicBase true`, `highEntropyVa true`.
  Example RVAs: `bea_add 0x1760`, `bea_counter 0xf080`.
- Target `ParentProcessId` = server node PID (via `Get-CimInstance Win32_Process`).
- With 4 or more `stdio:"pipe"` targets per server: spawn takes 1.8–2.7 s and RPC 340–680 ms.
  With `stdio:"inherit"` at 6 targets: 16 ms spawn and 1 ms RPC.
- With `stdio:"inherit"`, the target's printed `READY` line did **not** reach the MCP client and there was no `onerror`.
- 6 targets with unload→detach→kill cleanup: `closeMs 2019`, exit `signal: SIGTERM`, server log `["ready"]`, **6 leaked**.
  With kill-first: `closeMs 20`, `code 0`, log `["ready","cleanup","exit"]`, 0 leaked.
- MSVC: `cl.exe` 14.51.36231 exists, but `vcvars64.bat` fails ("vcvarsall.bat is not recognized"),
  `vswhere -requires …VC.Tools.x86.x64` returns nothing, and there is no `Windows Kits/10`. **MSVC fixture builds are unavailable here.**

Everything the lab spawned was killed. The final `tasklist | grep bea_fixture` count is 0.

---

## 11. BEA testing strategy (concrete)

### 11.1 Layers and directories (REA layout, trimmed)

```
src/**/X.test.ts                  module tests (domain/application); no processes, no Frida
src/**/X.fixture.ts               immutable builders + recording ports for one family
tests/composition/**              session/registry wiring with fake ports (lint-banned from child_process/net)
tests/boundary/mcp/**             in-memory MCP + production createServer + FAKE frida DeviceManager (gates)
tests/boundary/process/**         real child processes (job object, kill, reaper) – serial project
tests/acceptance/**               REAL: stdio MCP subprocess + real frida + compiled fixtures (named skips)
tests/conformance/**              shared contracts (e.g., every tool returns Evidence envelope)
tests/fixtures/native/*.c         C fixture sources (+ expectations.json)
tests/support/{mcp,process,workspace,native}/   harnesses
scripts/build-fixtures.mjs        gcc (+ optional MSVC/clang) builds with manifest
scripts/verify-*.mjs              real-provider lanes with JSON receipts (frida-windows, unicorn-diff, …)
```

Vitest projects (copy `scripts/lib/test-projects.mjs` and `projectForTest`):

- `domain`/`services`: `threads`, `isolate:false`.
- `mcp-boundary`: `threads`, `isolate:false`, since each file owns in-memory sessions.
- `process-boundary` and `acceptance`: `forks`, `fileParallelism:false` for acceptance on a single Windows dev
  box at first. Frida injection, debug ports and the anomaly in §10 favor serial files.
- `maxWorkers: min(2, availableParallelism())`, `retry: 0`.
- `testTimeout` 30 s, with explicit per-call deadlines lower than that.
- Set a `runner` subclass like `processOwnershipRunner.ts` to release native or Frida resources at worker teardown.

### 11.2 Fixtures (real binaries)

- Write C sources with a **mode argv** (`serve`, `hold`, `exit`, `crash`, `spin`, `threads`, `dll-load`, …), the
  REA `processFinalization.mjs` pattern. Use a **stdin line protocol plus `READY pid=` markers** so tests
  synchronize on events, not sleeps.
- **Exports with exact, recomputable semantics:**
  - pure integer and float functions (oracle and emulation differential);
  - a global with exactly one writer (watchpoint "what writes" answer: `bea_tick`'s write instruction);
  - a marker string (memory scan target);
  - a pointer chain struct (pointer-scan or Cheat-Engine-style tests);
  - a `crash` mode (exception capture);
  - a DLL fixture that the exe `LoadLibrary`s on command (module-load events);
  - a `threads` mode (Stalker per-thread, multi-thread hooks).
- Builds:
  - gcc/MinGW `-O0 -g -fno-inline -fno-omit-frame-pointer -Wl,--no-insert-timestamp` (byte-reproducible,
    VERIFIED). Add an `-O2` variant for "optimized code" realism.
  - Optional MSVC lane (`cl /Od /Zi /Ob0 /Brepro … /link /DEBUG /INCREMENTAL:NO /Brepro`). It needs a working
    `vcvars64` and Windows SDK; this host has **neither**, so it is a named skip.
  - Also consider `clang --target=x86_64-pc-windows-gnu` (BELIEVED, untested).
- **Manifest** per artifact, as in `scripts/build-conformance-fixtures.mjs:183-215`: `artifactSha256`,
  `sourceSha256`, compiler path, version and args, and **expectations**: export RVAs, imageBase,
  dynamicBase, the instruction RVA of the single writer, and `.pdata` ranges. Parse expectations from the PE
  itself (my `parsePeExports`) or `objdump -d`/`nm` from the same toolchain. These are the **static oracle**
  for rebasing tests, mirroring REA's `nm` cross-check (`scripts/verify-native-calls.mjs:70-75`).
- Build once per run in `globalSetup` → `provide("fixture", manifest)`, then `inject("fixture")` in tests.
  Cache by input hash in `.cache/fixtures/`. If a compiler is missing, provide `{ unavailable: reason }` and
  have tests use `it.skipIf(reason)`.
- **Never commit binaries** except tiny golden PE or ELF blobs for static-parser module tests. CI rebuilds.

### 11.3 MCP harnesses for BEA (copy and adapt)

1. `mcpTest` (in-memory), copied from `tests/support/mcp/mcpFixture.ts`. Pair it with
   `createServer(session, { frida: new FridaManager({ deviceManager: fake }) })`.
2. `connectBea()` stdio, copied from `localToolsMcp.ts`:
   - a minimal env plus `SystemRoot`, `TEMP` and `TMP` on Windows;
   - `stderr:"pipe"` captured for barriers and diagnostics;
   - Ajv2020 meta-schema validation of every advertised schema;
   - per-call output validation via `toolDefinition`;
   - **plus BEA additions**: an owned-PID ledger and post-close leak assertion (my `tests/support.mjs` `beaTest`).
3. In-process `serveStdio(factory, { transport: new StdioServerTransport(stdin, stdout) })` over `PassThrough`, for
   shutdown ordering without a subprocess. Inject `registerShutdown`, `setExitCode` and `writeStderr` as REA does.
4. File-scoped shared server, `createSharedMcpSession` from `cliFixture.ts:83-189`, for read-only matrices
   against one long-lived fixture process (exports, memory reads, disassembly).
5. A script-lane verifier, the `artifact-e2e.mjs` pattern, that emits a JSON receipt:
   `{ ok, mocked:false, host, frida_version, fixture_sha256, tools_exercised, cleanup:{leaked:0} }`.

Typed tool errors: assert via a `parseMcpToolError` equivalent (`isError === true` plus a strict zod parse of
the error envelope), not by substring.

### 11.4 Lifecycle and cleanup tests (must-have list)

Real lane (acceptance, real Frida, Windows):

1. **Graceful close** (stdin EOF): every owned target dies. The server exits with code 0 **within 2 s** (the SDK
   budget), and the test asserts `closeMs < 2000` plus server `exitCode === 0`. A `signal === "SIGTERM"` or a
   null exit code means the server was terminated, and the test fails.
2. **Many targets**: N ≥ 6 targets, then close. Asserts 0 leaks. This is the regression for the 2019 ms leak in §10.
3. **Hard kill of server** (`taskkill /F`): BEA's backstop must kill targets. Until a Job Object or reaper exists,
   the test records `hardKillTargetSurvived` and reaps the orphans (as in my lab). After the backstop lands,
   assert that it is false.
4. **Target dies on its own** (exit, crash, external kill of an *owned* pid): pending waits settle with
   `detached:<reason>`, status shows `target_exited` with the exit evidence, and nothing hangs.
5. **Cancellation**: `AbortController` on a long-running tool (trace window, scan, watchpoint wait):
   - sync on a server-side admission marker (a stderr log line, or a status tool);
   - `abort(new Error("reason"))`, then `client.ping()` (proves the server processed the cancel);
   - assert settlement on the **server** (stderr marker or status), not just the client rejection;
   - assert the session is still usable and hooks/stalker are unfollowed (status shows zero active
     instrumentation).
6. **Attach to a non-owned process**: forbidden by test policy. Use only fixture processes the test itself spawned
   (with Node `child_process`) when testing `attach`, and verify they **survive** `detach` and server close.
   That is REA's "unrelated/attached targets survive" row.
7. **Detach vs kill semantics**: spawned → killed on close (policy), attached → detached and left running.
   Test both.
8. **Cleanup-failure retention** (fake layer): `detach`/`kill` throws once → `server.close()` rejects with an
   `AggregateError`. The second close retries only the failed owner, and the third is a no-op.
   Copy `fridaLifecycleMcp.test.ts:1216-1251`.
9. **Startup interleavings** (fake layer, with gates): server shutdown while `attach` is in flight; cancel during
   `spawn` before `resume`, which must kill the suspended child; cancel during `script.load`.
10. **PID-reuse guard**: on Windows, `process.kill(pid, 0)` can hit a reused PID. Record the creation time
    (Frida `Process` info, or `Get-CimInstance Win32_Process CreationDate`) together with the PID in the ledger
    before killing an "orphan" in teardown. REA's ownership code tracks "start identity" for exactly this
    reason (`docs/testing.md:343-366`).

Fake-Frida lane (fast, deterministic): reproduce REA's `nativeFixture()` with BEA's extra surface. Each control
gets a `controls.*` hook plus failure counters and a `gate()`:

- `Interceptor`-backed hook manager;
- Stalker follow/unfollow;
- `MemoryAccessMonitor`/hardware breakpoint manager;
- `NativeFunction` caller.

Most BEA agent logic should live behind a port such as `AgentRpc { call(method, args, signal) }`, so that
MCP-boundary tests can use a recording fake instead of a real agent.

### 11.5 Determinism and speed rules

- **No sleeps for synchronization.** Use stdout/stderr markers, Frida `send()` messages, `client.ping()` round-trips,
  `gate()` barriers, and `vi.waitFor`/`waitUntil` polling with a deadline (25 ms poll, as REA does in
  `processFinalization.test.ts:115-123`).
- **Pointer-free projections.** Compare runtime results via RVAs, symbol names, counters and register values that
  do not depend on ASLR, as `stable()` does in `verify-native-calls.mjs:56-68`. Always assert
  `runtime - module.base == static RVA` instead of absolute addresses.
- **Bit-exact float comparison** for emulation differentials: `writeFloatLE` → `readUInt32LE`, not `toBeCloseTo`.
  Run a small fixed input table plus `@fast-check/vitest` property inputs over the pure fixture functions.
- **Bounded concurrency.** At most 3 piped Frida targets per server (see the anomaly), `maxWorkers ≤ 2`, and serial
  acceptance files.
- **Shared server per file** for stateless tool matrices. Per-test servers only for lifecycle cases.
  The first Frida attach per process costs about 0.7 s; later ones about 16 ms.
- **Cache fixture builds** by input hash, and build once per run in `globalSetup`.
- **Coverage instrumentation** never touches the Frida agent (it runs in the target). Unit-test agent logic by
  bundling it as plain TS with a fake `Process`/`Memory` API, and verify the real thing in acceptance.
- **Retry 0**, as in REA. A flaky lifecycle test signals a real race, so fix it with a barrier.
- **Temp hygiene**: one temp root per test under a `bea-` prefix, removed with `maxRetries` (Windows file locks
  on just-killed executables). Copy `verify:test-temp-hygiene`.
- Make **evidence fields deterministic** in tests: inject clock and UUID providers into the Evidence factory
  (REA uses `createEvidence(undefined, provider, {...})` with injectable parts). Golden files must not contain
  timestamps or PIDs.

### 11.6 Lanes and commands for BEA

| Command | Contents | Needs |
|---|---|---|
| `npm run check` | `tsc --noEmit`, `oxlint`, `oxfmt --check .`, `knip`, `verify:test-discovery` | Node only |
| `npm run test:fast` | domain, services, composition, mcp-boundary (fake Frida) | Node only |
| `npm run test:acceptance` | stdio MCP + real Frida + gcc fixtures (named skips if gcc or Frida is missing) | Windows x64, gcc, frida binding |
| `npm run verify:frida:windows` | Script lane receipt: spawn/attach/hook/stalker/watchpoint/call/dump on the fixture through CLI **and** MCP, with `deepEqual(stable(cli), stable(mcp))` | same |
| `npm run verify:emulation` | Unicorn differential (`python -I`, via `uv run --with unicorn==2.1.4 --with pefile` for isolation) vs in-process calls | Python + unicorn |
| `npm run verify:frida:bindings` | Vendor types fit the BEA shim | frida installed |
| `npm run verify:msvc-fixtures` | Optional MSVC builds of the same sources (named skip if no SDK) | VS + Windows SDK |

CI (BELIEVED, not built yet):

- `windows-latest` for acceptance and verify lanes, which have MSVC and the SDK, so MSVC fixtures can run there.
- `ubuntu-latest` for `check`, fast tests, and Linux fixtures (ELF) once BEA supports Linux targets.
- Cross-compile Windows fixtures on Linux with MinGW, as REA does, if Windows runners need prebuilt fixtures.

### 11.7 What to copy from REA, what not to

Copy:

- the tsconfig pair;
- `.oxlintrc.json` (including the test overrides and the layered `no-restricted-imports`);
- `.oxfmtrc.json`;
- knip's strict rules;
- husky and lint-staged;
- `test-projects.mjs` ownership plus `verify:test-discovery`;
- the `mcpFixture`, `localToolsMcp`, `processFixture`, `workspaceFixture`, `temporaryDirectory` and
  `createSharedMcpSession` patterns;
- the `gate()` and fake `DeviceManager` approach;
- the frida `.d.ts` shim plus compatibility assertion;
- `closeVerifierResources`;
- named skips;
- manifest-based fixture builds;
- the lifecycle scenario table;
- `retry: 0`.

Avoid or defer:

- Turbo and the artifact locks;
- the tsrs dual compiler;
- the Termux build;
- Stryker mutation;
- jscpd;
- the CI timing sequencer and sharding;
- the observational test-selection planner;
- compile-cache plumbing;
- the SQLite command locks.

These solve problems of a 400K-line, multi-host, multi-provider repo. They cost a lot of maintenance and give no
benefit at BEA's starting size.

---

## 12. Open questions

- Job Object backstop: should the BEA server put **itself** in a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job at
  startup (children inherit membership), using a tiny native helper (N-API, Rust, or koffi FFI)? Or should it
  run a separate watchdog process? Frida spawns are direct children of the server (VERIFIED), so self-jobbing
  should cover them (BELIEVED). Cross-arch spawns via `frida-helper-32` need checking. Note that REA builds its
  Windows addon with MinGW on **Linux only** (CONTRIBUTING.md:224-241).
- Root cause of the Frida `stdio:"pipe"` ≥4-target slowdown on Windows (frida 17.23.2). Is it a frida-core
  issue to report? Or should BEA capture target output differently, for example through Node-spawned pipes plus
  `attach`, or Frida `inherit` plus a file redirect?
- Do other MCP clients (Claude Code, Codex) apply the same "2 s then terminate" policy as the SDK's
  `StdioClientTransport`? Either way, BEA should treat 2 s as the cleanup budget and document it.
- Does BEA want an HTTP transport (REA tests `--http --port 0`)? If not, skip `streamableHttpProcess`.
- MSVC fixtures need a VS install with the "Desktop development with C++" workload plus a Windows SDK. The user
  must decide whether to install these, since installation is out of scope for this task. Until then, gcc only.
- Should acceptance run on GitHub `windows-latest` with Frida? Frida injection on hosted runners is BELIEVED to
  work, but Defender or AV may interfere.
