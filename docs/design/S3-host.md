# S3-host: Frida host provider, session lifecycle and process containment

Design for BEA v0.1 (`bea-agents`, bin `bea`). Written 2026-10-28 for the BEA design phase. It covers the code that
owns Frida handles, target processes and their lifetimes. It does not cover the tool contracts, the Evidence model, the
agent's instrumentation logic or the emulator. Those are other designs, and §18 and §22 list the interfaces this one needs
from them.

**Inputs.** BRIEF §0 (D1–D20) plus the orchestrator's fixed decisions, and the notes `rea-runtime`, `rea-process`,
`ext-frida`, `rea-testing`, `rea-mcp` and `rea-evidence`. New experiments live in
`<scratch>/bea-lab/design-S3-host/`
(cited as **[S3-lab: file]**).

**Labels.**
- **VERIFIED**: run on this host (Windows 11 26200, Node 24.18.0, frida 17.23.2 from REA's `node_modules`, gcc 16.1
  WinLibs msvcrt), in my lab or in a cited note's lab.
- **BELIEVED**: from docs, typings or memory; not run.
- **ASSUMPTION**: a design choice that another subsystem or the user must confirm.

Citations use the form `[note §section]`.

---

## 0. Decisions

| # | Decision | Basis |
|---|---|---|
| H1 | `FridaHost` creates **its own** `new frida.DeviceManager()` and does not use the `getDeviceManager()` singleton. It awaits `close()` on shutdown | VERIFIED: a distinct instance, local device in 42–44 ms, `dm.close()` in 63–68 ms, Node exits 1 ms after cleanup [S3-lab: frida-lab.mjs]. The singleton is module-global (`frida.js:1118-1157`, read here) and would break per-command CLI hosts and tests |
| H2 | Lazy single-flight binding load with a version pin and a failure memo. A failed `import("frida")` is permanent for the process. A failed device acquisition retries after a 5 s backoff | [rea-runtime §3]; the permanent import failure follows ESM semantics (BELIEVED) |
| H3 | **Path 1 spawn:** `device.spawn(stdio:'pipe')` → `bea-jobhost adopt <pid> <creationTime100ns> --tolerance-100ns 10 --expect-image <program> --expect-parent <node pid>` → attach → createScript (logHandler and message handler in the same tick) → load → `ready` handshake → configure → *(paused)* → resume | Frida's `started` is truncated to µs; it differs from `GetProcessTimes` by 1–8 ×100 ns, and all 8 adopts across two runs passed with tolerance 10. The parent of a Frida-spawned target is the Node pid. Wrong time, image or parent is refused before assignment. All VERIFIED [S3-lab: frida-lab.mjs, jh-smoke.mjs] |
| H4 | `bea-jobhost.exe` **protocol 1** has the modes `adopt`, `spawn`, `watch`, `inspect`, `probe` and `version`. Status is NDJSON on fd3 (stdout if fd3 is absent). Control is `kill`/`resume`/`status` lines on fd0, and EOF kills. The job is `KILL_ON_JOB_CLOSE \| DIE_ON_UNHANDLED_EXCEPTION`, read back. **Stragglers keep running after the root exits** until BEA kills the job. Exit is raw `ReadFile` + `ExitProcess` | Compiled warning-free (801 lines, 66,560 B, imports only KERNEL32/ADVAPI32/msvcrt). Every mode was exercised; full source in Appendix A [S3-lab: bea-jobhost.c, jh-smoke.mjs, jh-fd4.mjs] |
| H5 | **Attach identity** comes from `bea-jobhost inspect <pid>`: creation time (100 ns), image path, parent, session, critical, protection level, WoW64, elevation, integrity, same user. A refusal policy runs before any injection. A per-target `bea-jobhost watch` helper pins the pid and reports the exit code. **It has no PROCESS_TERMINATE right and refuses `kill`** | VERIFIED on processes I started [S3-lab: jh-smoke.mjs]. Protected/critical detection on real protected processes is BELIEVED (not exercised, by lab rule) |
| H6 | `SessionManager`: UUID ids, capacity (4 live, 3 piped, 16 queued ops per session), an admission gate with an operation registry, a per-session FIFO queue for agent-touching ops, deduplicated closes and a memoized, retryable `closeAll` | [rea-runtime §4]; [rea-mcp §6]; BRIEF §1.8 |
| H7 | **`closeAll` kills first.** At t0 it aborts all ops, sends `kill` and EOF to every owned jobhost, and acks pending crashes. Attached targets are torn down concurrently (revert → unload → detach). Then a bounded drain, sink finalization, disconnection of every handler and `await dm.close()`, all inside 2 s | VERIFIED: 3 piped owned targets plus 1 attached target closed in 67–72 ms. The attached target survived. A pending RPC rejected with `Script is destroyed`. Natural exit followed [S3-lab: frida-lab.mjs]; [rea-testing §0.5] |
| H8 | **Crash protocol:** the agent sends `{bea:'crash', id}` and blocks on `recv('ack:<id>')`. The host hands the report to the sink, then posts `{type:'ack:<id>'}` within 5 s, or immediately on close. The crash conclusion is *derived* from the report, the jobhost NTSTATUS and the detach | VERIFIED under `DIE_ON_UNHANDLED_EXCEPTION`: report received, ack sent, agent waited 0 ms, exit `0xC0000005` about 3 ms after the crash, no WER hang. This resolves BRIEF L3 for the report-and-die case [S3-lab: frida-lab.mjs] |
| H9 | Agent RPC: one fresh `frida.Cancellable` per call, armed by a deadline timer and the op signal. Errors map in one table (`Script is destroyed` → `target_exited` when the process ended). Binary results use `[reply, ArrayBuffer]`. Every reply is zod-validated because the agent is untrusted (it shares an address space with the target) | VERIFIED: `[meta, ArrayBuffer]` arrives as `[meta, Buffer]`; a trailing host `Buffer` arrives as the agent's last argument; host-side cancel works even while the agent JS thread is busy (106 ms) [S3-lab: frida-lab.mjs]; [ext-frida §1.7] |
| H10 | Event pump: the host allocates channel ids *before* the instrumenting RPC and binds them to S2 `StreamWriter`s. It counts agent-dropped events, seq gaps, host queue-full and quota drops, and never throws inside a Frida callback | [ext-frida §1.9]; D12 |
| H11 | stdout/stderr come from one `device.output` handler routed by pid into a head (64 KiB) + tail (192 KiB) capture per fd, which always drains. A zero-length chunk means EOF. A stdio stream also goes to S2 | VERIFIED EOF per fd [S3-lab: frida-lab.mjs]; [rea-process §8.2] |
| H12 | Liveness comes from the jobhost (owned), the watch helper (attached) and Frida detach events. **Never** from `enumerateProcesses({pids})` | pipe zombie VERIFIED [ext-frida §1.3] |
| H13 | At most **3 concurrently piped** targets. The 4th piped spawn is refused with `resource_constraint`; `capture_output:false` (Windows only) is the alternative | [rea-testing §0.6] |
| H14 | Linux x64 gets best-effort containment: kill the root plus its process group and descendants found through `/proc`, start-time checked. It is reported as `posix-best-effort, crashSafe:false` with fixed limitation text. macOS spawn and attach are refused | [rea-process §9]; orchestrator scope |

---

## 1. New lab results (this design)

All runs were on this host. Every process was started by the lab script, was inside a jobhost job or was killed
explicitly, and `tasklist` showed no leftovers.

| Experiment | Result | File |
|---|---|---|
| jobhost `probe` | `ok:true`: policy read back exactly; `PROC_THREAD_ATTRIBUTE_JOB_LIST` membership; probe child exited with its own code (assigned before its first instruction); adopt path (`AssignProcessToJobObject` on a suspended process created outside the job); `TerminateJobObject` exit code `0xBEA`. 39–48 ms | jh-smoke.mjs |
| jobhost `inspect` | Full record for node.exe and the fixture, e.g. `protectionLevel 4294967294` (= `PROTECTION_LEVEL_NONE`), `critical:false`, `wow64:false`, `nativeMachine 34404` (0x8664), `integrityRid 8192` (medium), `sameUser:true`, `parentPid` = the spawner. 17–22 ms per call | jh-smoke.mjs |
| `adopt` identity checks | Refused before assignment, with the target still alive, when the creation time was off by 5 ×100 ns, the image path was wrong, or the parent pid was wrong. Accepted with all three right | jh-smoke.mjs |
| `adopt` of a process already in a job | Adopting a `child_process`-spawned fixture already in libuv's job (`wasInJob:true`) **succeeded**. Nested jobs work (was BELIEVED in [rea-process §8.1]) | jh-smoke.mjs |
| `adopt` + EOF | `killed:eof` → `root-exit 3050` → `settled`; helper exited about 15 ms after EOF (65 ms measured including a 50 ms sleep in the script); target dead | jh-smoke.mjs |
| `spawn` normal | `proc-start` for the root and the console host; `root-exit code 0, activeAfterRoot 1` (conhost); `settled` 1 ms later; stdout/stderr pass through; helper exit code = the root's code | jh-smoke.mjs |
| Stragglers | Root exited with `activeAfterRoot:2`. The orphan child was **still alive** 500 ms later (default keep-tree policy). `kill` took it to `settled` in 1 ms, and the child was dead | jh-smoke.mjs |
| `watch` | EOF → `watch-ended` with the target still alive; `kill` refused (`kill-not-permitted-in-watch`); wrong creation time refused; target exit → `root-exit code 1` | jh-smoke.mjs |
| `spawn --stdin-fd4 --kill-on-root-exit --mem-limit 256MiB` | A JSON line written to Node's stdio[4] reached the child's stdin; the child's stdout came back through the helper's stdout; the policy reported `memLimitBytes:268435456` | jh-fd4.mjs |
| `kill` while suspended | Never resumed; `killed:control` → `root-exit 3050` → `settled` in 19 ms; target dead | jh-fd4.mjs |
| Frida `started` precision | ISO string with 6 fractional digits and `Z`; `GetProcessTimes − parse(started)` ∈ {1, 3, 4, 8} ×100 ns over 7 recorded spawns, and all 8 adopts (tolerance 10) passed. So `--tolerance-100ns 10` is exact to Frida's precision | frida-lab.mjs |
| Path 1 timings (warm) | spawn 3–16 ms, metadata 7–9 ms, adopt 16–25 ms, attach 10–12 ms (88–96 ms first in the process), createScript 1–2 ms, load 1 ms, ready <1 ms, resume <1 ms. About 50 ms per target without `inspect` (which production does not run for owned targets) | frida-lab.mjs |
| Crash under the job | `access-violation` report; ack type `ack:1`; agent `waitedMs:0`; a follow-up `send` after the ack **arrived** before death; jobhost `root-exit 0xC0000005` 3 ms after the report; `detached('process-terminated', crash=null)`; script destroyed at the same ms | frida-lab.mjs |
| RPC shapes | `[{kind,n}, ArrayBuffer]` → `[obj, Buffer]`; bare `ArrayBuffer` → `Buffer`; trailing host `Buffer` → agent's last argument (`argCount 2`, `ArrayBuffer`); `Cancellable.withTimeout(200)` → "Operation was cancelled" in 211 ms, script still usable; cancel during a 400 ms busy RPC → host rejection at 106 ms | frida-lab.mjs |
| Binary batch | `send({bea:'batch',…}, Int32Array.buffer)` → `data` Buffer of 4000 B | frida-lab.mjs |
| Kill-first `closeAll` | 3 owned piped targets plus 1 attached: all `settled` 3 ms after `kill`; all `process-terminated` within 3 ms; pending RPC → `Script is destroyed`; attached unload 3 ms, detach 1 ms (`application-requested`), still alive afterwards; `dm.close()` 63–68 ms; **total 67–72 ms** | frida-lab.mjs |
| Natural exit | With every handler disconnected and the owned DM closed, the `exit` event fired **1 ms** after cleanup, with no `process.exit`. (A first run showed 4.4 s; that was my lab's own uncleared `setTimeout` races.) | frida-lab.mjs |
| Cancellable liveness | A plain `Cancellable`, `combine()`, `combine()` then cancel, an unfired `withTimeout(60000)` and a connected `cancelled` handler **all** let Node exit (101–120 ms) | cancellable-leak.mjs |

---

## 2. Files in the future repo (this subsystem)

```
native/jobhost/bea-jobhost.c            Appendix A (protocol 1). Build output only, never committed.
scripts/build-native.mjs                gcc build → dist/native/win32-x64/bea-jobhost.exe + manifest.json
src/ports/DynamicSessionPort.ts         what application services call (= SessionManager surface, §7.1)
src/ports/AgentRpc.ts                   AgentRpc port (§11)
src/ports/OwnedTargetPort.ts            JobHostPort, ProcessWatcherPort, ProcessInspectorPort (fakeable)
src/frida/fridaPorts.ts                 narrow structural Frida types (§4.1)
src/frida/fridaAdapters.ts              vendor → port adapters (string-enum conversions live only here)
src/frida/fridaPorts.compat.ts          compile-time "vendor fits port" assertions [rea-testing §6.1]
src/frida/FridaHost.ts                  binding load, DeviceManager, local device, output fan-out, close (§4)
src/frida/NativeCancel.ts               one Cancellable per native call (§4.3)
src/frida/agentBundle.ts                loads dist/agent/bea-agent.js + manifest, sha256 check (§4.4)
src/frida/hostLimits.ts                 constants + config overrides (§3)
src/frida/sessionStates.ts              SessionState, transition table (pure, unit-tested) (§6.2)
src/frida/SessionRecord.ts              internal record, transitions, disconnectors (§6)
src/frida/SessionManager.ts             admission, registry, queues, capacity, close, closeAll (§7)
src/frida/SerialQueue.ts                per-session FIFO with pending cap (§7.3)
src/frida/spawnSession.ts               Path 1 startup (§8). The only file allowed to call device.kill (lint rule)
src/frida/attachSession.ts              attach startup (§9)
src/frida/startupCleanup.ts             PendingStartup cleanup (§8.3)
src/frida/closeSession.ts               owned/attached close (§7.5)
src/frida/closeAll.ts                   shutdown sequence (§7.6)
src/frida/AgentChannel.ts               message router, ready handshake, logHandler, faults (§10)
src/frida/AgentRpcClient.ts             typed RPC (§11)
src/frida/rpcErrors.ts                  Frida rejection → BeaError mapping (§11.3)
src/frida/EventPump.ts                  batch → StreamWriter (§12)
src/frida/CrashProtocol.ts              report → sink → ack (§13)
src/frida/ConditionHub.ts               wait conditions (§6.6)
src/frida/attachPolicy.ts               refusal rules (pure) (§5.8)
src/frida/peHeader.ts                   PE preflight: machine, ImageBase, TimeDateStamp (pure)
src/process/JobHost.ts                  TS wrapper of bea-jobhost (§5.7)
src/process/jobhostProtocol.ts          zod schemas of the NDJSON events (§5.2)
src/process/HelperLocator.ts            dist path + manifest sha256 check (§5.6)
src/process/ProcessInspector.ts         win32 (jobhost inspect) | linux (/proc) (§5.7, §19)
src/process/posix/BestEffortOwnership.ts  Linux fallback (§19)
src/process/BoundedCapture.ts           head+tail byte capture (§15)
src/process/Deadline.ts                 absolute deadline + signal composition (§16)
src/process/ntstatus.ts                 exit-code naming (§14.3)
```

Layering [rea-runtime §2]: application services depend only on `src/ports/*`. Only `src/frida/**` may import
`frida`, as `import type`, plus the lazy `import("frida")` in `FridaHost.ts`. Only `src/process/**` may import
`node:child_process`. oxlint `no-restricted-imports` enforces both rules.

---

## 3. Constants and limits (`src/frida/hostLimits.ts`)

```ts
export interface HostLimits {
  readonly maxLiveSessions: number;        // default 4; config limits.maxLiveSessions / env BEA_MAX_LIVE_SESSIONS, 1..8
  readonly maxPipedTargets: 3;             // fixed: the stdio:'pipe' anomaly starts at the 4th [rea-testing §0.6]
  readonly maxPendingOpsPerSession: 16;    // fixed [rea-mcp §6.2]
  readonly maxToolCallMs: 120_000;         // orchestrator: any single tool call <= 120 s
  readonly maxWaitMs: 60_000;              // orchestrator: wait <= 60 s
  readonly rpcDefaultTimeoutMs: number;    // default 10_000; config limits.rpcDefaultTimeoutMs, 1_000..115_000
  readonly startup: {
    readonly spawnGuardMs: 10_000; readonly metadataMs: 2_000; readonly adoptMs: 3_000; readonly inspectMs: 3_000;
    readonly watchMs: 3_000; readonly attachMs: 10_000; readonly createScriptMs: 10_000; readonly loadMs: 10_000;
    readonly readyMs: 5_000; readonly configureMs: 5_000; readonly resumeGuardMs: 5_000;
  };
  readonly crashAckTimeoutMs: 5_000;       // orchestrator
  readonly shutdown: {                     // all offsets from t0; whole sequence <= 2 s (SDK budget [rea-testing §0.5])
    readonly killEscalateMs: 900; readonly attachedStepMs: 300; readonly revertMs: 400; readonly drainUntilMs: 1_300;
    readonly sinkUntilMs: 1_500; readonly dmCloseMs: 300; readonly hardExitAtMs: 1_900;
  };
  readonly closeSession: {
    readonly killEscalateMs: 2_000; readonly detachWaitMs: 500; readonly queueDrainMs: 2_000; readonly revertMs: 5_000;
    readonly unloadMs: 2_000; readonly detachMs: 2_000; readonly outputEofWaitMs: 200;
  };
  readonly capture: {
    readonly stdioHeadBytes: 65_536; readonly stdioTailBytes: 196_608;
    readonly logEntries: 256; readonly logBytes: 262_144; readonly logEntryBytes: 4_096;
    readonly agentFaults: 32; readonly crashes: 16; readonly stateHistory: 32;
    readonly orphanOutputBytes: 65_536; readonly orphanOutputTtlMs: 5_000;
  };
}
```

Every fixed limit's refusal message ends with "This release has no runtime override." [rea-mcp §6.2]. Stream and
ledger quotas (512 MiB per run, 256 MiB per stream, 4 GiB of blobs) belong to S2.

---

## 4. Frida host provider

### 4.1 Narrow ports (`src/frida/fridaPorts.ts`)

frida is a regular dependency (D2), but tests inject fakes, so the provider codes against structural subsets of the
vendor classes. REA uses the same shim-and-assert pattern [rea-testing §6.1].

```ts
export interface CancellableLike { cancel(): void; readonly isCancelled: boolean }
export interface SignalLike<H extends (...args: never[]) => void> { connect(handler: H): void; disconnect(handler: H): void }
export type DetachReason =
  | "application-requested" | "process-replaced" | "process-terminated" | "connection-terminated" | "device-lost";
export type FridaMessage =
  | { readonly type: "send"; readonly payload: unknown }
  | { readonly type: "error"; readonly description: string; readonly stack?: string; readonly fileName?: string;
      readonly lineNumber?: number; readonly columnNumber?: number };
export type LogLevel = "info" | "warning" | "error";

export interface FridaScriptLike {
  readonly isDestroyed: boolean;
  logHandler: (level: LogLevel, text: string) => void;
  readonly exports: Readonly<Record<string, (...args: unknown[]) => Promise<unknown>>>;
  readonly message: SignalLike<(message: FridaMessage, data: Buffer | null) => void>;
  readonly destroyed: SignalLike<() => void>;
  load(cancellable?: CancellableLike | null): Promise<void>;
  unload(cancellable?: CancellableLike | null): Promise<void>;
  post(message: unknown, data?: Buffer | null): void;
}
export interface FridaSessionLike {
  readonly pid: number;
  isDetached(): boolean;
  detach(cancellable?: CancellableLike | null): Promise<void>;
  createScript(source: string, options: { name: string; runtime: "qjs" }, cancellable?: CancellableLike | null): Promise<FridaScriptLike>;
  readonly detached: SignalLike<(reason: DetachReason, crash: unknown) => void>;
}
export interface FridaProcessLike { readonly pid: number; readonly name: string; readonly parameters: Readonly<Record<string, unknown>> }
export interface FridaSpawnOptions {
  readonly env?: Record<string, string>; readonly envp?: Record<string, string>;
  readonly cwd?: string; readonly stdio: "pipe" | "inherit";
}
export interface FridaDeviceLike {
  readonly id: string;
  spawn(argv: string[], options: FridaSpawnOptions): Promise<number>;            // NEVER given a cancellable (§16)
  resume(pid: number): Promise<void>;                                            // NEVER given a cancellable
  kill(pid: number): Promise<void>;                                              // owned, pre-adoption cleanup ONLY
  attach(pid: number, options: Record<string, never>, cancellable?: CancellableLike | null): Promise<FridaSessionLike>;
  enumerateProcesses(options: { pids?: number[]; scope: "minimal" | "metadata" | "full" },
                     cancellable?: CancellableLike | null): Promise<FridaProcessLike[]>;
  querySystemParameters(cancellable?: CancellableLike | null): Promise<Readonly<Record<string, unknown>>>;
  readonly output: SignalLike<(pid: number, fd: number, data: Buffer) => void>;
}
export interface FridaDeviceManagerLike {
  getDeviceById(id: string, timeoutMs: number, cancellable?: CancellableLike | null): Promise<FridaDeviceLike>;
  close(cancellable?: CancellableLike | null): Promise<void>;
}
export interface FridaModuleLike {
  readonly DeviceManager: new () => FridaDeviceManagerLike;
  readonly Cancellable: new () => CancellableLike;
}
```

`fridaAdapters.ts` wraps vendor objects where TypeScript string enums block structural assignment: `ScriptRuntime.QJS`,
`Stdio.Pipe`, `Scope.Metadata`. All casts live there. `fridaPorts.compat.ts` asserts that the adapted vendor types fit the
ports (`type Assert<T extends true> = T`), and `tsc --noEmit` runs it in `npm run check`.

`attach` always receives `{}` (the default exceptor). `exceptor:'off'` turns any agent fault into a target kill
[ext-frida §1.5], so BEA never exposes `SessionOptions`.

### 4.2 `FridaHost` (`src/frida/FridaHost.ts`)

```ts
export type FridaBindingState =
  | { readonly state: "not-loaded" }
  | { readonly state: "loading" }
  | { readonly state: "ready"; readonly version: string; readonly loadMs: number }
  | { readonly state: "failed"; readonly stage: "import" | "version" | "device"; readonly reason: string;
      readonly attempts: number; readonly permanent: boolean; readonly retryAfterMs: number | null }
  | { readonly state: "closed" };

export interface FridaAvailability {                       // part of bea_status; computing it never loads anything
  readonly binding: FridaBindingState;
  readonly device: { readonly state: "not-acquired" | "ready" | "failed" | "closed";
                     readonly system?: { readonly os: string; readonly version: string; readonly arch: string; readonly access: string } };
  readonly agentBundle: { readonly state: "not-loaded" | "ready" | "failed"; readonly sha256?: string;
                          readonly protocol?: number; readonly reason?: string };
  readonly platform: { readonly os: NodeJS.Platform; readonly arch: string;
                       readonly support: "full" | "best-effort" | "unsupported";
                       readonly containment: "win32-job" | "posix-best-effort" | "none" };
}

export interface LiveDevice {
  readonly device: FridaDeviceLike;
  readonly system: { readonly os: string; readonly version: string; readonly arch: string; readonly access: string };
}

export interface FridaHostDeps {
  readonly logger: Logger;                                        // pino child, stderr only
  readonly loadModule?: () => Promise<FridaModuleLike>;           // default: lazy import("frida"), m.default ?? m
  readonly readBindingVersion?: () => Promise<string>;            // default: createRequire(...)("frida/package.json").version
  readonly loadAgentBundle?: () => Promise<Result<AgentBundle, BeaError>>;
  readonly expectedFridaVersion?: string;                         // "17.23.2"
  readonly now?: () => number;                                    // performance.now
}

export interface FridaHost {
  availability(): FridaAvailability;
  device(op: OperationContext): Promise<Result<LiveDevice, BeaError>>;
  nativeCancel(spec: { readonly deadline: Deadline; readonly signal?: AbortSignal }): NativeCancel;  // binding must be ready
  agentBundle(): Promise<Result<AgentBundle, BeaError>>;
  routeOutput(pid: number, sink: (fd: number, data: Buffer) => void): () => void;   // returns unregister
  close(deadline: Deadline): Promise<Result<HostCloseReport, BeaError>>;             // idempotent, retryable
}
export interface HostCloseReport { readonly outputDisconnected: boolean; readonly deviceManagerClosed: boolean; readonly closeMs: number }
```

Algorithm of `device(op)`, which is single-flight with a remembered failure:

```ts
// #state: idle | loading{promise} | ready{mod, dm, dev, system} | failed{stage, reason, attempts, at, permanent} | closed
async device(op) {
  if (this.#state.kind === "closed") return err(capabilityUnavailable("frida", "host-closed"));
  if (this.#state.kind === "ready") return ok(this.#state.live);
  if (this.#state.kind === "failed") {
    if (this.#state.permanent) return err(capabilityUnavailable("frida", this.#state.reason, { permanent: true }));
    if (this.#now() - this.#state.at < 5_000) return err(capabilityUnavailable("frida", this.#state.reason, { retry_after_ms }));
  }
  if (this.#state.kind !== "loading") this.#state = { kind: "loading", promise: this.#load() };
  return await raceSignal(this.#state.promise, op.signal);   // a caller abort stops the wait, not the load
}
async #load(): Promise<Result<LiveDevice, BeaError>> {
  let mod: FridaModuleLike;
  try { mod = await this.#loadModule(); }                  // ~55–95 ms native addon load [rea-runtime §7 #1]
  catch (e) { return this.#fail("import", e, /*permanent*/ true); }      // ESM caches a failed import (BELIEVED)
  const v = await this.#readBindingVersion().catch(() => "unknown");
  if (v !== this.#expected) return this.#fail("version", `frida ${v}; BEA requires ${this.#expected}`, true);
  const dm = new mod.DeviceManager();                      // OWNED instance (H1)
  const c = this.#cancel(1_500);
  try {
    const dev = await dm.getDeviceById("local", 1_000, c.token);     // "Device not found" => device-stage failure
    const sp = await dev.querySystemParameters();
    dev.output.connect(this.#onOutput);                    // the ONE output handler; disconnected in close()
    this.#state = { kind: "ready", mod, dm, live: { device: dev, system: pickSystem(sp) } };
    return ok(this.#state.live);
  } catch (e) {
    await dm.close().catch(() => undefined);
    return this.#fail("device", e, false);                 // retry after 5 s backoff
  } finally { c.dispose(); }
}
```

Failure reasons are bounded to 4 KiB and redacted [rea-runtime §3]. `close(deadline)`:

1. Disconnect `device.output`.
2. `await dm.close(cancellable(deadline))`.
3. Set the state to `closed`. On failure keep the state and report it, so a retry is possible.

`close` runs only after every session handle has been released (§7.6).

**Output fan-out.** `#onOutput(pid, fd, data)` looks up `pid` in `Map<number, sink>`. For an unknown pid it buffers into an
orphan buffer (64 KiB total, 5 s TTL, counted in `hostStatus.counters.orphanOutputBytes`). `routeOutput(pid, sink)` drains
that pid's orphan bytes first. Output cannot arrive before `resume`, because the target is suspended, so the orphan buffer
exists only for races during close (BELIEVED harmless).

### 4.3 `NativeCancel` (`src/frida/NativeCancel.ts`)

```ts
export interface NativeCancel {
  readonly token: CancellableLike;                         // pass as the LAST argument of one native call
  outcome(): "none" | "deadline" | "aborted";             // why it fired, if it did
  dispose(): void;                                         // clears timer + listener; idempotent
}
export function createNativeCancel(mod: FridaModuleLike, spec: { deadline: Deadline; signal?: AbortSignal }): NativeCancel {
  const token = new mod.Cancellable();
  let why: "none" | "deadline" | "aborted" = "none";
  const fire = (w: typeof why) => { if (why === "none") { why = w; token.cancel(); } };
  const timer = setTimeout(() => fire("deadline"), Math.max(0, spec.deadline.remaining()));
  timer.unref();
  const onAbort = () => fire("aborted");
  if (spec.signal?.aborted) fire("aborted"); else spec.signal?.addEventListener("abort", onAbort, { once: true });
  return { token, outcome: () => why, dispose() { clearTimeout(timer); spec.signal?.removeEventListener("abort", onAbort); } };
}
```

Use one token per call and never share one. `Cancellable.combine` is safe for liveness (VERIFIED) but never disconnects
its closures, so BEA does not use it.

### 4.4 Agent bundle (`src/frida/agentBundle.ts`)

```ts
export interface AgentBundle {
  readonly source: string;            // dist/agent/bea-agent.js, built by frida.Compiler at BUILD time (D11, orchestrator)
  readonly sha256: string;            // re-hashed at first load; must equal dist/agent/bea-agent.manifest.json
  readonly protocol: number;          // must equal AGENT_PROTOCOL_VERSION (src/shared/agentProtocol.ts)
  readonly fridaVersion: "17.23.2";
  readonly runtime: "qjs";
}
```

The bundle is loaded once and memoized. A mismatch gives `capability_unavailable{capability:"agent-bundle"}`, telling the
user to reinstall or rebuild. Every script is created as
`createScript(bundle.source, {name:"bea-agent", runtime:"qjs"})`; the default ESM multi-file bundle loads
[ext-frida §1.8].

---

## 5. Process containment: `bea-jobhost`

### 5.1 Command line (protocol 1)

```
bea-jobhost adopt   <pid> <creationTime100ns> [--tolerance-100ns N] [--expect-image PATH] [--expect-parent PID]
                    [--mem-limit BYTES] [--kill-on-root-exit]
bea-jobhost spawn   [--suspended] [--stdin-fd4] [--mem-limit BYTES] [--kill-on-root-exit] -- <drive-absolute exe> [args...]
bea-jobhost watch   <pid> <creationTime100ns> [--tolerance-100ns N]
bea-jobhost inspect <pid>
bea-jobhost probe
bea-jobhost version
```

| Mode | Used by | Opens | Can kill? |
|---|---|---|---|
| `adopt` | spawn Path 1 (owned) | `SET_QUOTA \| TERMINATE \| SYNCHRONIZE \| QUERY_LIMITED` | yes: the job, via `kill`, EOF or helper death |
| `spawn` | Path 2 fallback, BEA helpers (emulator bridge with `--stdin-fd4 --kill-on-root-exit --mem-limit`) | creates the process | yes: the job |
| `watch` | attached targets | `SYNCHRONIZE \| QUERY_LIMITED` | **no**: no job, no TERMINATE right, `kill` refused (VERIFIED) |
| `inspect` | attach identity and policy; doctor self-test | `SYNCHRONIZE \| QUERY_LIMITED` (retries `QUERY_LIMITED` only) | no |
| `probe` | `bea doctor` | its own two child processes | its own children only |
| `version` | locator self-check | none | no |

### 5.2 Status protocol (`src/process/jobhostProtocol.ts`)

The helper writes one JSON object per line: to fd3 when the parent supplied a pipe there, otherwise to stdout. `spawn`
**requires** fd3 because fd1/fd2 carry the target's output. A target cannot forge status lines, because
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` lets it inherit only its three std handles. The first line is always `hello`.

Creation times can exceed 2^53, so they are **decimal strings**. A lab bug of exactly this kind would otherwise lose
precision.

```ts
import { z } from "zod";
const u32 = z.number().int().min(0).max(0xffff_ffff);
const dec64 = z.string().regex(/^\d{1,20}$/u);
const jobPolicy = z.strictObject({
  killOnClose: z.literal(true), dieOnUnhandledException: z.literal(true), breakawayAllowed: z.literal(false),
  memLimitBytes: z.number().int().positive().nullable(),
});
const inspectFields = {
  pid: u32, access: z.enum(["limited", "limited+synchronize"]), exited: z.boolean().nullable(), exitCode: u32.nullable(),
  creationTime100ns: dec64.nullable(), imagePath: z.string().nullable(), parentPid: u32.nullable(), sessionId: u32.nullable(),
  critical: z.boolean().nullable(), protectionLevel: u32.nullable(), protected: z.boolean().nullable(),
  wow64: z.boolean().nullable(), processMachine: u32.nullable(), nativeMachine: u32.nullable(), inJob: z.boolean().nullable(),
  elevated: z.boolean().nullable(), integrityRid: u32.nullable(), sameUser: z.boolean().nullable(),
};
export const jobHostErrorStage = z.enum(["usage", "open", "identity", "job-create", "job-policy", "job-port", "assign",
  "membership", "create", "resume", "control", "status"]);
export const jobHostEventSchema = z.discriminatedUnion("event", [
  z.strictObject({ event: z.literal("hello"), protocol: z.literal(1), version: z.string(),
    mode: z.enum(["none", "adopt", "spawn", "watch", "inspect", "probe", "version"]), helperPid: u32,
    helperInJob: z.boolean(), statusFd3: z.boolean() }),
  z.strictObject({ event: z.literal("adopted"), pid: u32, creationTime100ns: dec64, wasInJob: z.boolean(),
    imagePath: z.string().nullable(), active: u32, policy: jobPolicy }),
  z.strictObject({ event: z.literal("started"), pid: u32, tid: u32, creationTime100ns: dec64, suspended: z.boolean(),
    imagePath: z.string().nullable(), policy: jobPolicy }),
  z.strictObject({ event: z.literal("watching"), pid: u32, creationTime100ns: dec64, imagePath: z.string().nullable() }),
  z.strictObject({ event: z.literal("resumed"), previousSuspendCount: u32 }),
  z.strictObject({ event: z.literal("proc-start"), pid: u32 }),
  z.strictObject({ event: z.literal("proc-exit"), pid: u32, abnormal: z.boolean() }),
  z.strictObject({ event: z.literal("proc-events-truncated"), limit: u32 }),
  z.strictObject({ event: z.literal("memory-limit"), pid: u32 }),
  z.strictObject({ event: z.literal("root-exit"), pid: u32, code: u32, codeHex: z.string(), activeAfterRoot: u32.nullable(),
    byKill: z.boolean() }),
  z.strictObject({ event: z.literal("killed"), reason: z.enum(["control", "eof", "root-exit-policy"]), activeBefore: u32,
    ok: z.boolean(), win32: u32 }),
  z.strictObject({ event: z.literal("settled"), active: u32, timedOut: z.boolean(),
    peakJobMemoryBytes: z.number().int().nonnegative(), elapsedMs: u32 }),
  z.strictObject({ event: z.literal("status"), rootAlive: z.boolean(), active: u32, elapsedMs: u32 }),
  z.strictObject({ event: z.literal("watch-ended"), reason: z.literal("eof") }),
  z.strictObject({ event: z.literal("inspect"), ...inspectFields }),
  z.strictObject({ event: z.literal("probe"), ok: z.boolean(), jobPolicyVerified: z.boolean(), jobListAttribute: z.boolean(),
    assignedBeforeFirstInstruction: z.boolean(), adoptAssign: z.boolean(), terminateJob: z.boolean(),
    helperInJob: z.boolean(), statusFd3: z.boolean() }),
  z.strictObject({ event: z.literal("error"), stage: jobHostErrorStage, win32: u32, detail: z.string(),
    expected: dec64.optional(), actual: dec64.optional(), wasInJob: z.boolean().optional() }),
]);
export type JobHostEvent = z.infer<typeof jobHostEventSchema>;
```

Ordering guarantees (VERIFIED in every run):
1. `hello` → (`adopted` | `started` | `watching` | `inspect` | `probe` | `error`).
2. Then `resumed`, then any `proc-*` / `memory-limit` / `status`.
3. Then (`root-exit`, then optionally `killed`) or (`killed`, then `root-exit{byKill:true}`).
4. Then `settled`, then the helper exits.

`proc-*` lines come from the completion-port thread and can interleave with anything after the first event. The parser
caps lines at 8 KiB. A line that fails the schema is a protocol violation: the wrapper terminates the helper (and with
it the job) and reports `execution_failure`.

### 5.3 Control protocol (fd0)

Lines are ASCII, at most 63 bytes, terminated by `\n`; `\r` is ignored.

| Command | adopt / spawn | watch |
|---|---|---|
| `kill` | `TerminateJobObject(job, 0xBEA)` → `killed{reason:"control"}` | `error{stage:"control", detail:"kill-not-permitted-in-watch"}` |
| `resume` | `spawn --suspended` only: `ResumeThread` → `resumed`, else `error{stage:"resume", detail:"not-suspended"}` | error |
| `status` | `status{rootAlive, active, elapsedMs}` | `status` |
| EOF or broken pipe | same as `kill`, with `reason:"eof"` (the owner went away) | `watch-ended` → exit 0; the target is untouched |

The control thread reads with raw `ReadFile`, and every exit goes through `ExitProcess`. CRT `fgets` in a thread plus CRT
`exit()` deadlocks (VERIFIED [rea-process §7]).

### 5.4 Algorithms (normative; the code is Appendix A)

**Job creation (`makeJob`):**
1. `CreateJobObjectW(NULL, NULL)`: unnamed, and the handle is not inheritable.
2. Limit flags `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION`, plus `JOB_MEMORY` (page-rounded) with `--mem-limit`.
3. Read the policy back and require **exact** equality, which proves there is no breakaway flag.
4. Associate the I/O completion port (key 1) **before** any process joins, so no message can be missed
   [rea-process §2.3].

**adopt:**
1. `OpenProcess(SET_QUOTA|TERMINATE|SYNCHRONIZE|QUERY_LIMITED, pid)`.
2. Identity check: `|GetProcessTimes.creation − expected| ≤ tolerance`; not already exited; `QueryFullProcessImageNameW`
   equals `--expect-image` (`CompareStringOrdinal`, ignoring case); `NtQueryInformationProcess(ProcessBasicInformation).
   InheritedFromUniqueProcessId == --expect-parent`. Any mismatch emits `error{stage:"identity"}` and exits `0xBEA3`
   **before** the job exists, leaving the target untouched.
3. `makeJob`, `IsProcessInJob(root, NULL)` → `wasInJob`, `AssignProcessToJobObject`, then
   `IsProcessInJob(root, job) == TRUE`.
4. Emit `adopted`, then run the lifecycle loop.

**spawn:**
1. Require fd3. Build the command line with MSVCRT quoting and bounds checks (algorithm VERIFIED in [rea-process §7 G5]).
2. `makeJob`.
3. stdin is NUL, or the fd4 OS handle with `--stdin-fd4`. stdout and stderr are the helper's own, made inheritable.
4. Use `PROC_THREAD_ATTRIBUTE_JOB_LIST` and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (deduplicated std handles only).
5. `CreateProcessW(exe, cmd, …, TRUE, CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT,
   NULL env, NULL cwd)`. The env and cwd are therefore the helper's own, which Node sets.
6. Membership check: on failure, `TerminateProcess` plus `error{membership}`.
7. Resume now, or keep the thread handle for `resume`. Emit `started`.

`ERROR_ELEVATION_REQUIRED` (740) surfaces as `error{stage:"create", win32:740}` (BELIEVED [rea-process §11 #10]).

**Lifecycle loop (adopt/spawn).** Two threads plus main:
- **Port thread:** `NEW_PROCESS` → `proc-start`; `EXIT_PROCESS` / `ABNORMAL_EXIT_PROCESS` → `proc-exit`; at most 256
  events, then `proc-events-truncated`. `ACTIVE_PROCESS_ZERO` → zero event. `JOB_MEMORY_LIMIT` → `memory-limit`.
- **Control thread:** §5.3.
- **Main:**

```
wait(root, killEvent)
├─ root exited: emit root-exit{code, activeAfterRoot}
│     if active > 0:
│        --kill-on-root-exit: terminate("root-exit-policy")
│        default: loop { if active==0 break; wait(zero, kill, 250 ms); on kill → terminate(reason) }   <- stragglers live
└─ kill (control/EOF): terminate(reason); wait root ≤ 2 s → root-exit{code, byKill:true}
settle: while active>0 && < 2 s: wait(zeroEvent, 25 ms)       // ActiveProcesses is the truth; port msgs are hints
emit settled{active, timedOut, peakJobMemoryBytes, elapsedMs}; ExitProcess(rootCode | 0xBEA)
```

`ActiveProcesses` counts `conhost.exe` for console targets (VERIFIED: `activeAfterRoot:1` for a lone console target), so
BEA never reads it as "target processes".

**watch:**
1. Open with `SYNCHRONIZE | QUERY_LIMITED` only, and run the identity check (creation time).
2. Emit `watching`.
3. Wait for the root → `root-exit{activeAfterRoot:null}` → exit 0.
4. EOF → `watch-ended` → exit 0. The open handle pins the pid while BEA watches (no reuse while a handle is open,
   BELIEVED [rea-process §11 #12]).

**inspect.** Opens `SYNCHRONIZE|QUERY_LIMITED`, falling back to `QUERY_LIMITED` on `ERROR_ACCESS_DENIED`. It resolves
`IsWow64Process2`, `IsProcessCritical` and `GetProcessInformation(ProcessProtectionLevelInfo)` with `GetProcAddress`, so
the exe loads on any Windows 10. It reads token elevation, integrity RID and `TokenUser` equality with the helper's own
user. Each field is `null` when unobtainable. It modifies nothing.

**probe** proves containment by doing it, not by inferring it from the OS version [rea-process §12]:
1. `makeJob` with read-back.
2. A suspended self-child with `JOB_LIST` → membership → resume → exit code `0x5EA`
   (`assignedBeforeFirstInstruction`).
3. A second suspended self-child created outside the job → `AssignProcessToJobObject` (the adopt path) → membership →
   `TerminateJobObject` → exit code `0xBEA`.
4. `ok` only if every step passed. VERIFIED in 39–48 ms.

### 5.5 Exit codes (fallback only; the status events are authoritative)

| Code | Meaning |
|---|---|
| root's code | the root exited (an NTSTATUS for crashes, e.g. `0xC0000005`, VERIFIED) |
| `0xBEA` (3050) | BEA terminated the job. Every job member gets this code |
| `0xBEA1` … `0xBEA9` | usage, open, identity, job, assign, create, membership, status, probe failures |
| `0x5EA` | probe child (internal) |

`root-exit.byKill` tells a BEA kill apart from a target that happened to exit with 3050.

### 5.6 Build and locate

- `scripts/build-native.mjs` runs from `npm run build`:
  ```
  gcc -O2 -s -municode -D_WIN32_WINNT=0x0A00 -static -Wall -Wextra -Werror -Wl,--no-insert-timestamp
      -o dist/native/win32-x64/bea-jobhost.exe native/jobhost/bea-jobhost.c
  ```
  - MinGW needs `-D_WIN32_WINNT=0x0A00` and `-municode` [rea-process §7].
  - `--no-insert-timestamp` makes gcc builds byte-reproducible (VERIFIED for fixtures [rea-testing §0.7]).
  - It writes `dist/native/win32-x64/manifest.json` as
    `{file, sha256, bytes, protocol:1, version:"0.1.0", compiler:{path, version}, flags}`.
  - The binary is a build output and is never committed (orchestrator).
  - With no gcc on Windows the build fails with "install WinLibs MinGW-w64 or provide BEA_JOBHOST_PREBUILT". Non-Windows
    builds skip it.
- `HelperLocator.locate()` (memoized) resolves `new URL("../../dist/native/win32-x64/bea-jobhost.exe", import.meta.url)`
  relative to the package only, with no environment override in production (REA's rule [rea-process §2.1]). Tests inject
  a path through the constructor. It hashes the 66 KB file (<1 ms) and compares it with the manifest. A mismatch gives
  `capability_unavailable{capability:"jobhost", reason:"hash-mismatch"}`. Every run's `hello.protocol` must be 1.
- Unsigned executables against Defender or SmartScreen are untested (R18). The doctor runs `probe` and reports
  `job_object_containment: available` only on `ok:true`.

### 5.7 TS wrapper (`src/process/JobHost.ts`)

```ts
export interface JobHostBinary { readonly path: string; readonly sha256: string; readonly protocol: 1; readonly version: string }
export interface JobPolicy { readonly killOnClose: true; readonly dieOnUnhandledException: true; readonly breakawayAllowed: false; readonly memLimitBytes: number | null }

export interface AdoptRequest {
  readonly pid: number;
  readonly creationTime100ns: bigint;          // from Frida metadata `started` (µs) -> FILETIME (§8 step 5)
  readonly tolerance100ns: bigint;             // 10n (µs truncation, VERIFIED)
  readonly expectImage: string;                // the spawned program (absolute)
  readonly expectParentPid: number;            // process.pid (Frida local spawn makes a direct child, VERIFIED)
  readonly memLimitBytes?: number;
  readonly deadline: Deadline;                 // adoptMs
  readonly signal?: AbortSignal;
}
export interface SpawnRequest {
  readonly exe: string; readonly args: readonly string[]; readonly cwd: string; readonly env: Readonly<Record<string, string>>;
  readonly suspended: boolean; readonly stdin: "nul" | "pipe"; readonly killOnRootExit: boolean; readonly memLimitBytes?: number;
  readonly deadline: Deadline; readonly signal?: AbortSignal;
}
export interface WatchRequest { readonly pid: number; readonly creationTime100ns: bigint; readonly tolerance100ns: bigint; readonly deadline: Deadline }

export type JobHostState = "starting" | "contained" | "root-exited" | "killing" | "settled" | "helper-lost" | "failed";
export type KillReason = "close-session" | "server-shutdown" | "startup-failed" | "startup-cancelled" | "protocol-violation";
export interface RootExit { readonly code: number; readonly codeHex: string; readonly byKill: boolean; readonly activeAfterRoot: number | null; readonly at: number }
export interface JobSettlement {
  readonly method: "control-kill" | "eof" | "helper-terminated" | "natural" | "root-exit-policy";
  readonly observation: "observed-zero-active" | "kernel-enforced-unobserved" | "timed-out-with-active";
  readonly activeBefore: number | null;
  readonly active: number | null;
  readonly peakJobMemoryBytes: number | null;
  readonly helperExitCode: number | null;
  readonly outputComplete: boolean;            // spawn mode: stdout+stderr reached 'close'
  readonly elapsedMs: number;
}

export interface JobHostPort {                 // src/ports/OwnedTargetPort.ts (fakes implement this)
  readonly helperPid: number;
  readonly rootPid: number;
  readonly creationTime100ns: bigint;
  readonly imagePath: string | null;
  readonly policy: JobPolicy;
  readonly wasInJob: boolean | null;
  readonly state: JobHostState;
  readonly rootExit: RootExit | null;
  readonly lastActive: number | null;
  readonly settled: Promise<JobSettlement>;    // never rejects
  on(listener: (e: JobHostEvent) => void): () => void;
  resume(): Result<void, BeaError>;            // spawn --suspended only
  requestStatus(): void;
  kill(reason: KillReason, escalateAfterMs: number): Promise<JobSettlement>;   // idempotent, memoized
  readonly stdin: Writable | null;             // spawn --stdin-fd4: the target's stdin
  readonly stdout: Readable | null;            // spawn: target stdout (pass-through)
  readonly stderr: Readable | null;
}
export interface ProcessWatcherPort {
  readonly helperPid: number; readonly pid: number; readonly creationTime100ns: bigint; readonly imagePath: string | null;
  readonly rootExit: RootExit | null;
  readonly exited: Promise<RootExit | null>;   // null when stopped first
  on(listener: (e: JobHostEvent) => void): () => void;
  stop(): Promise<void>;                       // EOF; the target is never touched (VERIFIED)
}
export interface JobHostFactory {
  adopt(req: AdoptRequest): Promise<Result<JobHostPort, BeaError>>;
  spawn(req: SpawnRequest): Promise<Result<JobHostPort, BeaError>>;
  watch(req: WatchRequest): Promise<Result<ProcessWatcherPort, BeaError>>;
  inspect(pid: number, deadline: Deadline): Promise<Result<ProcessInspection, BeaError>>;
  probe(deadline: Deadline): Promise<Result<JobHostProbe, BeaError>>;
}
```

Child process launch (identical for every mode, apart from stdio):

```ts
const child = spawn(bin.path, args, {
  stdio: mode === "spawn" ? ["pipe", "pipe", "pipe", "pipe", ...(req.stdin === "pipe" ? ["pipe"] as const : [])]
                          : ["pipe", "ignore", "pipe", "pipe"],   // fd3 = status; stderr kept (bounded 4 KiB) for diagnostics
  detached: false,      // MUST stay in libuv's kill-on-close job: Node death -> helper death -> job death (VERIFIED H)
  windowsHide: true, shell: false,
  cwd: mode === "spawn" ? req.cwd : undefined,
  env: mode === "spawn" ? { ...req.env } : { SystemRoot: process.env.SystemRoot ?? "C:\\Windows" },
});
```

**Start.** The wrapper resolves when the first decisive event arrives (`adopted`/`started`/`watching`/`inspect`/`probe`)
or fails on `error`, helper exit, the deadline or an abort. On deadline or abort after the helper started it calls
`child.kill()`: TerminateProcess on the helper, so the kernel closes the job and anything adopted dies, which is correct
for an owned startup. Error mapping:

| Stage | Result |
|---|---|
| `identity` | `InstanceMismatch` |
| `open` win32 87 | `InputError` (no such process) |
| `open` win32 5 | `AccessDenied` |
| `assign` | `CapabilityUnavailable{capability:"containment"}` |
| `create` win32 740 | `AccessDenied{reason:"elevation-required"}` |
| `create` win32 2/3 | `InputError` |
| anything else | `ProviderFailure` |

**`kill(reason, escalateAfterMs)`**, memoized:
1. If already settled, return the settlement.
2. Set the state to `killing`. Write `kill\n` and end stdin (EOF is a second trigger).
3. Race `settled` against `escalateAfterMs`. On timeout, `child.kill()` with
   `method:"helper-terminated", observation:"kernel-enforced-unobserved"`: KILL_ON_JOB_CLOSE is kernel-enforced but not
   observed (VERIFIED G2, 108 ms [rea-process §7]).
4. Await the helper `exit`, at most 500 ms more.

The default `escalateAfterMs` is 900 for shutdown and 2000 for `close_session`. VERIFIED typical: settled 3 ms after
`kill` [S3-lab].

**`settled`** resolves when the helper process has exited **and**, in spawn mode, stdout and stderr have both closed
(complete output: the helper exits only after the job settled; a 1 s cap sets `outputComplete:false`). An exit without a
`settled` event and without a prior kill means the state is `helper-lost`. KILL_ON_JOB_CLOSE has then killed the tree,
and the session reports exited with the limitation "The containment helper exited unexpectedly; the kernel terminated the
job." `unref()` is never called: an owned target should keep the server alive until it is closed.

**`ProcessInspector`** (`src/process/ProcessInspector.ts`, port `ProcessInspectorPort`):

```ts
export interface ProcessInspection {
  readonly pid: number; readonly access: "limited" | "limited+synchronize";
  readonly exited: boolean | null; readonly exitCode: number | null; readonly creationTime100ns: bigint | null;
  readonly imagePath: string | null; readonly parentPid: number | null; readonly osSessionId: number | null;
  readonly critical: boolean | null; readonly protectionLevel: number | null; readonly protected: boolean | null;
  readonly wow64: boolean | null; readonly processMachine: number | null; readonly nativeMachine: number | null;
  readonly inJob: boolean | null; readonly elevated: boolean | null; readonly integrityRid: number | null;
  readonly sameUser: boolean | null;
}
export interface ProcessInspectorPort { inspect(pid: number, deadline: Deadline): Promise<Result<ProcessInspection, BeaError>> }
```

### 5.8 Attach refusal policy (`src/frida/attachPolicy.ts`, pure)

Rules are evaluated in order, and the first hit refuses. `self` holds the server's own facts: pid, ppid, helper pids,
pids already in BEA sessions, elevation and integrity RID (from one `inspect(process.pid)` at startup).

| # | Rule | Error |
|---|---|---|
| 1 | `pid ≤ 4` | `AccessDenied` "system idle/System process" |
| 2 | `pid == self.pid` or `pid == self.ppid` (the MCP client) or a BEA helper pid | `AccessDenied` "BEA's own process tree" |
| 3 | pid already has a BEA session | `InputError` "pid N already has session S" |
| 4 | `exited == true` | `InputError` "process N has exited" |
| 5 | `protected == true` | `AccessDenied` "protected process (PPL level 0x…)" |
| 6 | `critical == true` | `AccessDenied` "critical process; a fault would stop Windows" |
| 7 | `osSessionId == 0` and not `config.attach.allowSession0` | `AccessDenied` "session-0 (service) process" |
| 8 | `wow64 == true` or `processMachine ∉ {null, 0}` | `Unsupported` "32-bit (WoW64) targets are unsupported in v0.1" (orchestrator) |
| 9 | image under `%SystemRoot%` and basename ∈ {csrss, smss, wininit, winlogon, lsass, lsaiso, services, svchost, dwm, fontdrvhost, spoolsv, MsMpEng, NisSrv, MpDefenderCoreService, SecurityHealthService}.exe, plus `config.attach.extraDenylist` | `AccessDenied` "system process" |
| 10 | `sameUser == false` | `AccessDenied` "another user's process" |
| 11 | `elevated == true && !self.elevated`, or `integrityRid > self.integrityRid` | `AccessDenied` "higher integrity; BEA never elevates" |

`null` (unknown) fields never refuse on their own. Rules 5 and 6 being `null` adds the limitation "Protection or critical
status could not be read". Anti-cheat detection is out of scope; it is a skill rule (BRIEF Q5).

### 5.9 Why kill authority cannot reach attached processes

1. An attached session holds a `ProcessWatcherPort` and **no** `JobHostPort`, so the type system has no kill path for it.
2. The watch helper opens without `PROCESS_TERMINATE` and refuses `kill` (VERIFIED).
3. `device.kill` appears only in `spawnSession.ts` / `startupCleanup.ts`, for a pid our own `device.spawn` returned,
   before adoption. An oxlint `no-restricted-syntax` rule pins this.
4. Acceptance tests assert that the attached target is alive after `close_session` and after `closeAll` (VERIFIED in the
   lab).

---

## 6. Session model

### 6.1 Types (`src/frida/SessionRecord.ts`)

```ts
export type SessionId = string & { readonly __brand: "SessionId" };            // crypto.randomUUID()
export type SessionState =
  | "spawning" | "adopted" | "inspecting" | "attached" | "agent_loading" | "agent_ready"   // startup (not yet visible)
  | "paused" | "running"                                                                    // live
  | "exited" | "detached"                                                                   // target gone / agent gone
  | "failed"                                                                                // startup failed (resources may remain)
  | "closing" | "cleanup_pending" | "closed";
export type StartupStep = "preflight" | "reserve" | "spawn" | "metadata" | "adopt" | "inspect" | "policy" | "watch"
  | "attach" | "subscribe" | "create-script" | "load" | "ready" | "configure" | "verify-identity" | "promote" | "resume";
export type StateCause =
  | { readonly kind: "step"; readonly step: StartupStep }
  | { readonly kind: "tool"; readonly name: string }
  | { readonly kind: "detached"; readonly reason: DetachReason; readonly requestedByBea: boolean }
  | { readonly kind: "root-exit"; readonly code: number; readonly byKill: boolean }
  | { readonly kind: "helper-lost" }
  | { readonly kind: "error"; readonly tag: string }
  | { readonly kind: "shutdown" };

export interface ProcessIdentityFacts {
  readonly deviceId: "local";
  readonly pid: number;
  readonly startTime: { readonly source: "os-creation-time"; readonly value100ns: string }    // GetProcessTimes via jobhost
                    | { readonly source: "first-observed"; readonly value100ns: string };    // linux fallback (§19)
  readonly image: { readonly path: string; readonly sha256: string | null; readonly size: number | null; readonly machine: "x64";
                    readonly peTimestamp: number | null; readonly preferredBase: string | null };
  readonly parentPid: number | null;
  readonly osSessionId: number | null;
  readonly integrity: "low" | "medium" | "high" | "system" | "unknown";
  readonly launchedByBea: boolean;                    // governs kill authority [rea-evidence §10.2]
}
export interface ContainmentFacts {
  readonly kind: "win32-job" | "posix-best-effort" | "none";
  readonly helperPid: number | null;
  readonly killOnClose: boolean;
  readonly dieOnUnhandledException: boolean;
  readonly breakawayAllowed: false;
  readonly memLimitBytes: number | null;
  readonly wasInJobBeforeAdopt: boolean | null;
  readonly assignedBeforeResume: boolean;             // owned Path 1: adopted while Frida held it suspended
  readonly crashSafe: boolean;                        // dies with the BEA server even on a hard kill
}
export type Ownership =
  | { readonly kind: "owned"; readonly jobHost: JobHostPort | null; readonly bestEffort: BestEffortOwned | null;
      readonly piped: boolean; resumed: boolean }
  | { readonly kind: "attached"; readonly watcher: ProcessWatcherPort | null };
export interface DetachInfo { readonly reason: DetachReason | "unknown-before-subscribe"; readonly requestedByBea: boolean;
                              readonly crash: null | { readonly summary: string }; readonly at: TimeMark }
export interface TimeMark { readonly monoNs: string; readonly wall: string }   // S2 assigns seq / epochs
```

Internal record. It is never handed to services; they get `LiveSession` (§7.1).

```ts
interface SessionRecord {
  readonly id: SessionId; readonly kind: "live"; readonly createdAt: number;
  state: SessionState; readonly history: BoundedRing<{ state: SessionState; at: number; cause: StateCause }>;
  ownership: Ownership;
  identity: ProcessIdentityFacts | null;
  containment: ContainmentFacts | null;
  frida: { session: FridaSessionLike | null; script: FridaScriptLike | null };
  channel: AgentChannel | null; rpc: AgentRpcClient | null; pump: EventPump | null; crash: CrashProtocol | null;
  output: OutputCapture | null;
  readonly queue: SerialQueue;
  readonly ops: Set<RegisteredOp>;
  readonly closeController: AbortController;           // aborted with {kind:"session-closing"} at close start
  readonly disconnectors: Array<() => void>;           // LIFO; each wrapped in try/catch
  readonly hub: ConditionHub;
  detach: DetachInfo | null; exit: ProcessExit | null; tree: { active: number | null; settled: boolean } | null;
  detachRequested: boolean;
  visible: boolean;                                    // false until "promote"
  closing: Promise<Result<CloseReport, BeaError>> | null;
  retained: { resources: string[]; reason: string } | null;
  readonly startup: { steps: Array<{ step: StartupStep; ms: number }>; reservation: Reservation | null };
}
```

### 6.2 State machine (`src/frida/sessionStates.ts`)

`transition(record, to, cause)` throws a programmer error on an illegal edge, because the table is exhaustive and
unit-tested. Every transition calls `sink.stateChanged` and `hub.notify()`.

| From | To | Trigger |
|---|---|---|
| (admitted, owned) | `spawning` | before `device.spawn` |
| `spawning` | `adopted` | jobhost `adopted` |
| (admitted, attach) | `inspecting` | before `inspect` |
| `inspecting` | `attached` | `device.attach` resolved, detach subscribed and reconciled |
| `adopted` | `attached` | same |
| `attached` | `agent_loading` | `createScript` resolved, handlers connected |
| `agent_loading` | `agent_ready` | valid `ready` message (§10.2) |
| `agent_ready` | `paused` | owned, promoted without resume |
| `agent_ready` | `running` | attached promoted, or owned with `resume:true` |
| `paused` | `running` | `resume_process` succeeded |
| `paused`, `running` | `exited` | owned: jobhost `root-exit` or `helper-lost`; any: detach `process-terminated`; attached: watcher `root-exit` |
| `paused`, `running` | `detached` | detach reason ≠ `process-terminated` and not requested by BEA |
| `detached` | `exited` | later jobhost or watcher `root-exit` |
| any startup state | `failed` | step error, cancel or shutdown |
| `failed` | `closed` | startup cleanup completed |
| `failed` | `cleanup_pending` | a startup cleanup step failed (retained for `closeAll` retry) |
| `paused`, `running`, `exited`, `detached`, `cleanup_pending` | `closing` | `close_session` or `closeAll` |
| `closing` | `closed` | all resources released; record removed |
| `closing` | `cleanup_pending` | revert, unload, detach or kill failed; record kept with `retained` |

`exited` and `detached` are not terminal for the record. The session stays readable (status, evidence, streams) until
`close_session`, because stragglers may still be alive in an owned job (orchestrator).

### 6.3 Operations allowed per state (checked in `withSession`)

| Operation class | `paused` | `running` | `exited` | `detached` | `closing`, `cleanup_pending` |
|---|---|---|---|---|---|
| agent RPC tools (read, hook, scan, call, …) | yes [^1] | yes | `TargetExited` | `CapabilityUnavailable{reason:"agent-gone"}` | `CapabilityUnavailable{reason:"closing"}` |
| `resume_process` | yes [^2] | `InputError` "already running" | `TargetExited` | `CapabilityUnavailable` | refused |
| `session_status`, `wait`, `query_events`, evidence | yes | yes | yes | yes | yes (`wait` returns at once) |
| `close_session` | yes | yes | yes | yes | `closing`: joins the in-flight close; `cleanup_pending`: retries |

[^1]: On a paused target the main thread sits at `ntdll!RtlUserThreadStart` and the CRT is not initialized
    [ext-frida §1.4]. `call_function` is allowed but adds the limitation "called before process initialization".
[^2]: Refused while any script is `cleanup-pending` [rea-runtime §4.6].

Gates (`write_memory`, `override_function`, `run_script`, and `call_function` on attached targets) are checked by the
contract and service layer from `LiveSession.ownership`. The host enforces only kill authority.

### 6.4 Liveness (`LiveSession.liveness()`)

```ts
export type Liveness =
  | { readonly state: "alive"; readonly basis: "jobhost" | "watcher" | "frida-session" }
  | { readonly state: "exited"; readonly basis: "jobhost-root-exit" | "watcher-root-exit" | "frida-process-terminated" | "helper-lost-kernel-kill";
      readonly exit: ProcessExit | null; readonly tree: { readonly activeAfterRoot: number | null; readonly settled: boolean } | null }
  | { readonly state: "unknown"; readonly reason: string };
```

Owned sessions use the jobhost first and Frida detach as corroboration. Attached sessions use the watcher first, then
Frida `process-terminated` (exit code unknown). A detach for any other reason with no watcher gives `unknown`. **No code
path calls `enumerateProcesses({pids})` for liveness**; a test greps for it. A dead `stdio:'pipe'` target is still listed
there (VERIFIED [ext-frida §1.3]).

### 6.5 Status snapshot (sync, cheap, no RPC, not recorded as Evidence)

```ts
export interface SessionStatusSnapshot {
  readonly sessionId: SessionId; readonly kind: "live"; readonly ownership: "owned" | "attached";
  readonly state: SessionState; readonly stateSince: number; readonly pid: number;
  readonly image: { readonly basename: string; readonly sha256: string | null };
  readonly liveness: Liveness; readonly detach: DetachInfo | null; readonly exit: ProcessExit | null;
  readonly tree: { readonly active: number | null; readonly settled: boolean; readonly procStarted: number; readonly procAbnormalExits: number } | null;
  readonly containment: ContainmentFacts;
  readonly agent: { readonly health: AgentHealth; readonly protocol: number; readonly runtime: "QJS";
                    readonly faults: { readonly count: number; readonly recent: readonly AgentFault[] } };   // recent <= 3
  readonly channels: readonly ChannelCounters[];
  readonly crashes: { readonly count: number; readonly recent: readonly AgentCrashSummary[] };          // recent <= 3
  readonly output: { readonly stdoutTail: string; readonly stderrTail: string; readonly observedBytes: number; readonly truncated: boolean } | null; // tails <= 4 KiB
  readonly queue: { readonly pending: number; readonly running: string | null };
  readonly logs: { readonly count: number; readonly recent: readonly { level: LogLevel; text: string }[] };   // recent <= 5
}
```

All target-derived strings (logs, output, fault descriptions, image names) are untrusted. The delivery layer sets
`_meta.provenance.untrusted_content` [rea-mcp §4.6].

### 6.6 Wait primitive (`ConditionHub`)

```ts
export type WaitCondition =
  | { readonly kind: "process-exit" } | { readonly kind: "detach" }
  | { readonly kind: "channel-events"; readonly channel: number; readonly atLeast: number }
  | { readonly kind: "channel-end"; readonly channel: number }
  | { readonly kind: "agent-job"; readonly jobId: string };
export interface WaitOutcome { readonly satisfied: boolean; readonly timedOut: boolean; readonly cancelled: boolean;
                               readonly state: SessionState; readonly waitedMs: number }
```

- `waitFor(cond, op, timeoutMs ≤ 60_000)` never takes the session queue.
- It is re-evaluated on `hub.notify()`, which is coalesced with `setImmediate` so that a burst of batches costs one
  evaluation.
- Running out of time is a poll result (`timedOut:true`), not an error. Abort gives `cancelled:true`, and
  `wait_for_events` maps that to `Cancelled`. A close gives `satisfied:false` with the state.
- "A stop is read, not taken" [ext-landscape §3.3]: conditions read counters and never consume them.

---

## 7. SessionManager (`src/frida/SessionManager.ts`)

### 7.1 Surface (`src/ports/DynamicSessionPort.ts`)

```ts
export interface OperationContext {
  readonly opId: number;
  readonly name: string;                         // tool or internal op name (logged; inputs never logged)
  readonly signal: AbortSignal;                  // composed: caller ∪ shutdown ∪ session-closing ∪ deadline
  readonly deadline: Deadline;                   // absolute, <= maxToolCallMs from admission
  readonly progress?: (phase: string) => void;   // server layer rate-limits (100 ms) [rea-mcp §1.8]
}
export interface AdmitRequest { readonly signal?: AbortSignal; readonly timeoutMs?: number; readonly sessionId?: SessionId }

export interface SpawnInput {
  readonly program: string;                      // drive-absolute path to a PE32+ x64 .exe (no .bat/.cmd)
  readonly argv: readonly string[];              // argv[1..]; Frida receives [program, ...argv] (round-trip VERIFIED)
  readonly cwd?: string;                         // default: dirname(program)  (ASSUMPTION: games load assets relative to their dir)
  readonly env?: Readonly<Record<string, string>>;
  readonly envMode: "merge" | "replace";         // merge -> Frida env (inherits BEA's env); replace -> envp (VERIFIED semantics)
  readonly captureOutput: boolean;               // true: stdio:'pipe' (<= 3 concurrent); false: 'inherit' (win32 only)
  readonly resume: boolean;                      // default false: stays paused for pre-resume instrumentation
  readonly memLimitBytes?: number;               // optional JOB_MEMORY limit
  readonly expectSha256?: string;                // optional pin (e.g. from REA/Ghidra); checked BEFORE spawning
}
export interface AttachInput {
  readonly pid: number;
  readonly expect?: { readonly imagePath?: string; readonly sha256?: string; readonly creationTime100ns?: string };
}
export interface SessionObservation {
  readonly sessionId: SessionId;
  readonly ownership: "owned" | "attached";
  readonly state: "paused" | "running";
  readonly identity: ProcessIdentityFacts;
  readonly containment: ContainmentFacts;
  readonly agent: AgentReadyFacts;
  readonly output: { readonly captured: boolean; readonly mode: "frida-pipe" | "not-captured" };
  readonly startup: { readonly steps: readonly { step: StartupStep; ms: number }[]; readonly totalMs: number };
  readonly limitations: readonly string[];
}
export interface CloseOptions { readonly force: boolean }   // attached: continue past unreverted effects
export interface ProcessExit {
  readonly code: number; readonly codeHex: string;
  readonly kind: "normal" | "ntstatus-error" | "bea-kill" | "unknown";
  readonly name: string | null;                  // e.g. "STATUS_ACCESS_VIOLATION" (§14.3)
  readonly source: "jobhost" | "watcher" | "frida-detach-only";
}
export interface CloseReport {
  readonly sessionId: SessionId; readonly ownership: "owned" | "attached";
  readonly targetState: "killed" | "already-exited" | "alive-detached" | "exited-during-close" | "unknown";
  readonly termination: { readonly method: "terminate-job" | "helper-terminated" | "frida-kill-suspended-root" | "posix-best-effort" | "none";
                          readonly activeBefore: number | null;
                          readonly settled: "observed-zero-active" | "kernel-enforced-unobserved" | "timed-out-with-active" | "not-applicable" | "unknown";
                          readonly elapsedMs: number } | null;
  readonly exit: ProcessExit | null;
  readonly revert: { readonly attempted: boolean; readonly report: RevertReport | null } | null;   // RevertReport from agentProtocol
  readonly agentUnloaded: boolean | null;
  readonly fridaDetached: boolean;
  readonly streamsFinalized: readonly StreamManifestRef[];
  readonly cleanup: { readonly status: "complete" } | { readonly status: "incomplete"; readonly resources: readonly string[]; readonly reason: string };
  readonly limitations: readonly string[];
}

export interface DynamicSessionPort {
  admit<T>(name: string, req: AdmitRequest, fn: (op: OperationContext) => Promise<Result<T, BeaError>>): Promise<Result<T, BeaError>>;
  spawn(input: SpawnInput, op: OperationContext): Promise<Result<SessionObservation, BeaError>>;
  attach(input: AttachInput, op: OperationContext): Promise<Result<SessionObservation, BeaError>>;
  resume(sessionId: SessionId, op: OperationContext): Promise<Result<{ readonly state: "running"; readonly resumedAt: TimeMark }, BeaError>>;
  close(sessionId: SessionId, options: CloseOptions, op: OperationContext): Promise<Result<CloseReport, BeaError>>;
  withSession<T>(sessionId: SessionId, op: OperationContext, mode: "exclusive" | "concurrent",
                 fn: (s: LiveSession) => Promise<Result<T, BeaError>>): Promise<Result<T, BeaError>>;
  status(sessionId: SessionId): Result<SessionStatusSnapshot, BeaError>;
  list(): readonly SessionSummary[];
  hostStatus(): HostStatus;
  ownedTargets(): readonly OwnedTargetRecord[];       // test leak ledger + diagnostics
  registerExternal(kind: "emulation", factory: ExternalSessionFactory, op: OperationContext): Promise<Result<SessionId, BeaError>>;
  closeAll(reason: ShutdownReason): Promise<CloseAllReport>;   // memoized; rejects AggregateError when incomplete; retryable
  readonly closing: boolean;
}
export interface LiveSession {
  readonly id: SessionId; readonly kind: "live";
  readonly ownership: "owned" | "attached";
  readonly state: SessionState;
  readonly identity: ProcessIdentityFacts;
  readonly agent: AgentRpc;
  readonly channels: ChannelBinder;              // §12.2
  readonly output: OutputCapture | null;
  liveness(): Liveness;
  waitFor(cond: WaitCondition, op: OperationContext, timeoutMs: number): Promise<WaitOutcome>;
}
export type ShutdownReason = "stdin-end" | "SIGINT" | "SIGTERM" | "server-close" | "cli-exit" | "test";
export interface OwnedTargetRecord { readonly sessionId: SessionId; readonly pid: number; readonly creationTime100ns: string; readonly helperPid: number | null }
export interface ExternalSessionDriver {          // implemented by the emulator session (other design)
  readonly kind: "emulation";
  shutdown(deadline: Deadline): Promise<Result<void, BeaError>>;   // closeAll fast path
  close(deadline: Deadline): Promise<Result<CloseReport | Record<string, unknown>, BeaError>>;
  status(): Readonly<Record<string, unknown>>;
}
export type ExternalSessionFactory = (id: SessionId, op: OperationContext) => Promise<Result<ExternalSessionDriver, BeaError>>;
```

`HostStatus` (for `bea_status`):
`{ frida: FridaAvailability; jobhost: {state, sha256, probe?}; limits: {liveSessions:{used,max}, pipedTargets:{used,max:3}, pendingOpsPerSession:16}; sessions: SessionSummary[]; startups: {id, kind, state, elapsedMs}[]; counters: {orphanOutputBytes, protocolViolations, handlerErrors, unknownChannelBatches}; closing: boolean }`.

### 7.2 Admission gate and operation registry

```ts
async admit(name, req, fn) {
  if (this.#closing) return err(capabilityUnavailable("frida", "shutting-down",
    "BEA is shutting down; no new work is admitted. This release has no runtime override."));
  const deadline = Deadline.after(Math.min(req.timeoutMs ?? this.#limits.maxToolCallMs, this.#limits.maxToolCallMs));
  const controller = new AbortController();                         // per-op; aborted by closeAll / session close
  const composed = AbortSignal.any([req.signal ?? neverSignal, this.#shutdown.signal, controller.signal, deadline.signal()]);
  const op: RegisteredOp = { id: ++this.#nextOp, name, sessionId: req.sessionId ?? null, startedAt: now(), controller, done: null! };
  if (composed.aborted) return err(classifyAbort(composed, name));   // re-check at dispatch [rea-runtime §4.2]
  const p = fn({ opId: op.id, name, signal: composed, deadline }).catch((e) => err(internal(name, e)));
  op.done = p; this.#ops.add(op);
  if (op.sessionId) this.#records.get(op.sessionId)?.ops.add(op);
  try { return await p; } finally { this.#ops.delete(op); if (op.sessionId) this.#records.get(op.sessionId)?.ops.delete(op); }
}
```

`classifyAbort` checks the sources in priority order: shutdown, then session-closing, then the caller (`Cancelled` with
the caller's reason kept as `cause` [rea-runtime §6]), then the deadline (`Timeout{timeout_ms}`). Abort reasons are typed:
`{kind:"shutdown"} | {kind:"session-closing", sessionId} | {kind:"deadline", ms}`. A foreign caller reason is wrapped as
`{kind:"caller", reason}`.

### 7.3 Per-session FIFO (`SerialQueue`)

```ts
export class SerialQueue {
  #tail: Promise<void> = Promise.resolve(); #pending = 0; #running: string | null = null;
  constructor(private readonly max = 16) {}
  async run<T>(name: string, signal: AbortSignal, fn: () => Promise<Result<T, BeaError>>): Promise<Result<T, BeaError>> {
    if (this.#pending >= this.max) return err(resourceLimit("capacity", { max_pending_ops: this.max },
      "This session already has 16 queued operations. Wait for some to finish. This release has no runtime override."));
    this.#pending++;
    const prev = this.#tail; let release!: () => void;
    this.#tail = prev.then(() => new Promise<void>((r) => (release = r)));
    try {
      await abortable(prev, signal);                  // an aborted waiter leaves the line without breaking FIFO
      if (signal.aborted) return err(classifyAbort(signal, name));
      this.#running = name;
      return await fn();
    } finally { this.#running = null; this.#pending--; release?.(); }
  }
  get pending() { return this.#pending; } get running() { return this.#running; }
}
```

- `exclusive` mode: every operation that sends an RPC to the agent or changes session state (resume, hook install and
  removal, call, scan start, close).
- `concurrent` mode: status, `wait`, `query_events` and evidence. These read host state only.

The agent's single JS thread serializes RPCs anyway [ext-frida §1.7]. The host queue gives read-after-write ordering and
a clean place to drain before teardown.

### 7.4 Capacity and reservations

- `reserve(kind, piped)` runs synchronously at the start of `spawn` or `attach`, before any await, so concurrent startups
  cannot overshoot.
- It counts `records.size + reservations` for live sessions (max 4), and piped records plus piped reservations (max 3).
- The reservation is released on promotion (the record counts from then on) or on failure.
- Refusals are `ResourceLimit{resource:"capacity", limit:{max_live_sessions:4}}` or `{max_piped_targets:3}` with the
  remediation "Close a session (close_session) …; or spawn with capture_output:false (Windows)". `retryable:true`.
- External (emulation) sessions have their own cap, owned by the emulator design (ASSUMPTION: 4).

### 7.5 `close_session` (`src/frida/closeSession.ts`)

Concurrent closes are deduplicated through `record.closing` (`??=` memo). On failure the memo is cleared and the record
stays (`cleanup_pending`), so the next `close_session` retries only what is left [rea-runtime §4.9].

**Owned** (kill first):
1. `transition(closing)`. `record.closeController.abort({kind:"session-closing"})` ends in-flight RPCs at once (host-side
   cancel VERIFIED). Then `crash.ackAll("closing")`.
2. If the job is still alive, `jobHost.kill("close-session", 2000)` (VERIFIED: 3 ms to settled; ~100 ms typical
   [rea-process §7 G1]). Pre-adoption, `device.kill(pid)` with `method:"frida-kill-suspended-root"`: the root was suspended
   and had run no code, so it has no descendants. That is a derivation and is recorded as a limitation.
3. Wait up to 500 ms for `session.detached('process-terminated')` (VERIFIED 0–3 ms). If it does not arrive,
   `session.detach(cancel 1 s)` frees Frida-side state.
4. `queue` drain, bounded 2 s (ops fail fast with `Script is destroyed`, which maps to `target_exited`).
5. Wait for output EOF on fd1/fd2, at most 200 ms (VERIFIED EOF arrives at exit). Unregister the output route.
6. `pump.endAll("process-killed" | "process-exited")`, then disconnect all of the record's handlers (LIFO).
7. `await sink.sessionEnded({report, deadline: 5 s})`: S2 finalizes stream manifests, marks effects `implicit-end`, and
   adds a `process-killed` Effect when the kill happened.
8. `transition(closed)` and delete the record.

**Attached:**
1. `closing`, abort the session's ops, `ackAll`.
2. Drain the queue (bounded 2 s).
3. `rpc.call("revertAll", [], {timeoutMs:5000})` returns a `RevertReport` with per-instrument results: hooks detached
   and verified, debug registers disarmed (the agent must disarm through `nativeContext` [ext-frida §3.9]), patches
   restored from their before-bytes.
   - If any result failed and `!force`: `transition(cleanup_pending)` and return
     `EffectUnreverted{effect_ids}` (`effect_unreverted`, retryable, recovery `revert_effects`). The agent stays loaded so
     the caller can retry.
   - With `force`: continue and report the leftovers as `revert-failed`.
4. `script.unload(cancel 2 s)`. A failure with `!script.isDestroyed` means `cleanup_pending`, and the script stays owned
   [rea-runtime §4.7].
5. `record.detachRequested = true`, then `session.detach(cancel 2 s)`.
6. `watcher.stop()` (EOF; the target is untouched, VERIFIED).
7. Disconnect, `sink.sessionEnded`, `closed`.

The report's `targetState` is `alive-detached`, or `exited-during-close` if the watcher saw an exit. It always carries
the footprint limitation "frida-agent.dll and 24 system DLLs were loaded; 11 remain after detach" [ext-frida §4].

### 7.6 `closeAll` (`src/frida/closeAll.ts`): the 2 s shutdown

```ts
closeAll(reason) {
  this.#closing = true;
  this.#closeAllPromise ??= this.#closeAllOnce(reason).catch((e) => { this.#closeAllPromise = undefined; throw e; });
  return this.#closeAllPromise;
}
```

Timeline (offsets from t0; budget 2,000 ms from the SDK's stdin EOF [rea-testing §0.5]):

| t | Action | Bound |
|---|---|---|
| 0 | `#closing = true` (admission refuses); `#shutdown.abort({kind:"shutdown"})` aborts every admitted op's signal, so RPC `Cancellable`s fire | sync |
| 0 | **Owned FIRST:** for every record that holds a `jobHost` (registered, `exited` with stragglers, or a pending startup): `jobHost.kill("server-shutdown", 900)`. Owned startups not yet adopted: `device.kill(pid)`. All fire-and-collect | escalate at 900 → `TerminateProcess(helper)` |
| 0 | `crash.ackAll("shutdown")` on every record | sync |
| 0 | External sessions: `driver.shutdown(deadline t0+1200)` | 1200 |
| 0 → 1000 | **Attached, concurrently:** wait for the queue (≤ 300) → `revertAll` (≤ 400) → `script.unload` (≤ 300) → `session.detach` (≤ 300) → `watcher.stop()`. Failures are recorded and teardown continues (no retry is possible after exit) | each step its own cancel |
| ≤ 1000 | Await all owned kills; for owned Frida sessions, await `detached` (≤ 100 ms after settled) | 1000 |
| ≤ 1300 | `Promise.allSettled(ops)` with a deadline. Ops still running are listed in `abandonedOps` | 1300 |
| ≤ 1500 | `sink.sessionEnded({report, deadline: t0+1500})` for each record (S2: manifests, ledger flush, fsync at finalize per the orchestrator) | 1500 |
| ≤ 1500 | Disconnect every remaining handler: scripts (`message`, `destroyed`, `logHandler = noop`), sessions (`detached`), jobhost listeners | sync |
| ≤ 1800 | `host.close(deadline t0+1800)`: disconnect `device.output`, `await dm.close()` | 300 (VERIFIED 63–68 ms) |
| end | Return `CloseAllReport`, or throw `AggregateError(failures, "BEA session cleanup was incomplete")`. The memo resets so a retry covers the retained owners only | |

```ts
export interface CloseAllReport {
  readonly reason: ShutdownReason; readonly elapsedMs: number;
  readonly owned: readonly { sessionId: SessionId; pid: number; termination: CloseReport["termination"] }[];
  readonly attached: readonly { sessionId: SessionId; pid: number; revert: RevertReport | null; agentUnloaded: boolean | null;
                                fridaDetached: boolean; targetAlive: boolean | null }[];
  readonly external: readonly { sessionId: SessionId; ok: boolean }[];
  readonly abandonedOps: readonly string[];
  readonly deviceManagerClosed: boolean;
  readonly failures: readonly BeaError[];
}
```

**Why not drain ops first (as BRIEF §1.8 step 1 proposes)?** A drain can wait on a hung RPC or a 60 s `wait`. Aborting
first and killing in parallel keeps the kill inside the budget; the drain becomes bounded bookkeeping. With
unload → detach → kill ordering, 6 of 6 targets leaked [rea-testing §0.5]. Measured with this design: 67–72 ms total
(VERIFIED).

**Entry-point wiring** (owned by the server/CLI design; the contract is stated here):
- Triggers: stdio mode on stdin `end`/`close`, `SIGINT`, `SIGTERM` and `server.server.onclose`; HTTP mode on signals only
  [rea-mcp §6.5].
- On the first trigger, arm `setTimeout(() => process.exit(code), 1900).unref()` as a safety net. It fires only if
  something still pins the loop.
- Then `await runtime.closeAll(reason)`, close the transport and set `process.exitCode` (0, or 130/143 after a signal,
  or 1 on incomplete cleanup).
- Natural exit follows (VERIFIED: 1 ms after `dm.close()` with every handler disconnected).

**Hard death of the server** (TerminateProcess from the client after 2 s, or a crash): owned targets die by kernel chain
(libuv job → jobhost → BEA job, VERIFIED H [rea-process §7]). Attached targets lose their Frida connection, and the agent
unloads its scripts (BELIEVED). **Risk:** debug registers armed by `watch_memory(debug-register)` survive a script
destroy, and a later trap with no handler would crash the user's process. The agent design must address this (§22, C9).

---

## 8. Spawn path (`src/frida/spawnSession.ts`)

### 8.1 Steps

| # | Step | Call | Bound / cancel | State | On failure or abort |
|---|---|---|---|---|---|
| 0 | admit | `admit("spawn_process")` | op deadline ≤ 120 s | – | – |
| 1 | preflight | `realpath(program)`; must be drive-absolute, a regular file, not `.bat`/`.cmd`. `peHeader(program)`: `MZ`, `PE\0\0`, machine `0x8664` (`0x14c` → `Unsupported` WoW64; others → `Unsupported`); ImageBase and TimeDateStamp. Start `sha256(program)`; if `expectSha256` is set, **await it here** and refuse a mismatch with `InstanceMismatch` | – | – | nothing to clean |
| 2 | reserve | §7.4 (+ piped when `captureOutput`) | sync | – | release |
| 3 | spawn | `device.spawn([program, ...argv], {cwd, env\|envp, stdio:"pipe"\|"inherit"})` | **no cancellable**; guard 10 s | `spawning` | guard expiry: return `Timeout`, keep the startup record. When the spawn resolves later, `device.kill(pid)` (retained-owner pattern) |
| 4 | route output | `host.routeOutput(pid, capture.onChunk)` when piped | sync | – | unregister |
| 5 | metadata | `device.enumerateProcesses({pids:[pid], scope:"metadata"})` → `started` (µs ISO) → FILETIME (§8.2) | cancel 2 s | – | `device.kill(pid)`: a suspended root with no tree |
| 6 | adopt | `jobHosts.adopt({pid, creationTime100ns, tolerance100ns:10n, expectImage:program, expectParentPid:process.pid, memLimitBytes})` | 3 s | `adopted` | jobhost `error` → `device.kill(pid)`; any later failure → `jobHost.kill("startup-failed")` |
| 7 | attach | `device.attach(pid, {}, cancel)` | cancel 10 s | – | `jobHost.kill` |
| 8 | subscribe | `session.detached.connect(onDetached)`, **then** `if (session.isDetached())` record `detach{reason:"unknown-before-subscribe"}`; jobhost or watcher state then decides `exited` versus `detached` [rea-runtime §4.4] | sync | `attached` | disconnect |
| 9 | create script | `session.createScript(bundle.source, {name:"bea-agent", runtime:"qjs"}, cancel)`, then **in the same synchronous block**: `script.logHandler = channel.onLog; script.message.connect(channel.onMessage); script.destroyed.connect(channel.onDestroyed)` | cancel 10 s | `agent_loading` | `jobHost.kill` |
| 10 | load | `script.load(cancel)` | cancel 10 s | – | `jobHost.kill` |
| 11 | ready | `await channel.ready`, which rejects on a `type:"error"` message, `{bea:"fatal"}`, detach or destroy (§10.2) | 5 s after load | `agent_ready` | `jobHost.kill` |
| 12 | configure | `rpc.call("configure", [agentConfig])`, with `crash: "report-and-ack"`, module and thread observers on, batch flush 50 ms | 5 s | – | `jobHost.kill` |
| 13 | identity | join the sha256 from step 1 and build `ProcessIdentityFacts` (`startTime.source:"os-creation-time"` from `adopted.creationTime100ns`). Compare `ready.main.path` with the program; a difference (e.g. an 8.3 short name) is a limitation | – | – | `jobHost.kill` |
| 14 | promote | `visible = true`, release the reservation, `sink.targetEffect("process-spawned"/"agent-injected")` | sync | `paused` | – |
| 15 | resume (optional) | `device.resume(pid)` | **no cancellable**; guard 5 s | `running` | rare failure: `jobHost.kill` plus a `ProviderFailure` (the spawn is atomic) |

After every await: `if (op.signal.aborted) → cleanup → Cancelled` [rea-runtime §6]. The first failure stays primary;
cleanup failures go to `cleanup.reason` and the code becomes `cleanup_incomplete` with `details.execution_failure`
[rea-evidence §2.3].

Expected latency: about 50 ms warm, about 160 ms for the first spawn in a process (attach plus device acquisition), and
680–720 ms in a cold fresh process [rea-testing §10].

### 8.2 FILETIME from Frida `started`

```ts
export function isoToFiletime100ns(iso: string): { value: bigint; precision100ns: bigint } | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})$/u.exec(iso);
  if (!m) return null;
  const [, Y, Mo, D, h, mi, s, frac = "", tz] = m;
  let ms = Date.UTC(+Y!, +Mo! - 1, +D!, +h!, +mi!, +s!);
  if (tz !== "Z") { const sg = tz![0] === "-" ? -1 : 1; ms -= sg * (+tz!.slice(1, 3) * 60 + +tz!.slice(-2)) * 60_000; }
  const digits = Math.min(frac.length, 7);
  const units = digits ? BigInt(frac.slice(0, 7).padEnd(7, "0")) : 0n;
  return { value: BigInt(ms) * 10_000n + units + 116_444_736_000_000_000n, precision100ns: 10n ** BigInt(7 - digits) };
}
```

`tolerance100ns = precision100ns`, which is 10 for the observed 6 digits (VERIFIED: 8 of 8 adopts). Without `started` (null or
unparseable), adopt runs with `tolerance = 2^63-1` and relies on `--expect-image` plus `--expect-parent`, with the
limitation "creation time not cross-checked".

### 8.3 Startup cleanup records

```ts
interface PendingStartup {
  readonly record: SessionRecord;              // state spawning..agent_ready|failed, visible:false
  pid: number | null; spawnPromise: Promise<number> | null;   // step 3 guard expiry keeps the promise
  jobHost: JobHostPort | null; watcher: ProcessWatcherPort | null;
  session: FridaSessionLike | null; script: FridaScriptLike | null;
  unrouteOutput: (() => void) | null;
}
```

Owned cleanup, in order: `jobHost.kill("startup-failed"|"startup-cancelled", 2000)` if it exists, else
`device.kill(pid)` if `pid`, else (pending spawn) chain `spawnPromise.then(kill)`. Then wait ≤ 500 ms for the detach;
`session.detach` if it is still attached; disconnect; unroute output. Each step is wrapped. A failure leaves the record in
`cleanup_pending` with `retained.resources` such as `["pid:1234", "jobhost:5678"]` (labels only; they never authorize
signals [rea-process §4.2]), and `closeAll` retries it.

The window between `device.spawn` and `adopted` is about 15–35 ms (spawn, metadata and adopt, VERIFIED). A hard crash of
the server inside it leaves a **suspended, uncontained** root (Frida targets outlive the host [rea-process §7 F3]); it
never runs, but it lingers. Residual risk R-S3-1 (§22). Optional v0.2 mitigation: a "pre-armed adopt" (start the helper
before `device.spawn` and send it the pid on stdin), which shrinks the window to about 10 ms.

---

## 9. Attach path (`src/frida/attachSession.ts`)

| # | Step | Detail | Bound | State | Cleanup (never kill) |
|---|---|---|---|---|---|
| 0 | admit | `attach_process` | – | – | – |
| 1 | reserve | live ≤ 4 | sync | – | release |
| 2 | inspect | `jobHosts.inspect(pid)` | 3 s | `inspecting` | – |
| 3 | policy | §5.8, rules 1–11 | sync | – | – |
| 4 | expect | if `expect.imagePath` / `creationTime100ns` / `sha256` are given, compare them (hash the inspected image path; a locked file gives `sha256:null` plus a limitation) → `InstanceMismatch` | – | – | – |
| 5 | watch | `jobHosts.watch({pid, creationTime100ns: insp.creationTime100ns, tolerance100ns: 0n})` waits for `watching`. **The pid is pinned from here** | 3 s | – | `watcher.stop()` |
| 6 | attach | `device.attach(pid, {}, cancel)`. Frida errors: access denied → `AccessDenied`; not found → `InputError`; else `ProviderFailure` | 10 s | – | `watcher.stop()` |
| 7 | subscribe | detach connect, then reconcile | sync | `attached` | disconnect |
| 8–10 | script, load, ready | as in spawn steps 9–11; `ready.pid` must equal `pid` | 10 / 10 / 5 s | `agent_loading` → `agent_ready` | unload (2 s), detach (2 s) |
| 11 | configure | as in spawn step 12 (crash capture on: the crash report is the only Windows crash channel [ext-frida §1.5]) | 5 s | – | same |
| 12 | verify identity | `watcher.rootExit == null`; `ready.main.path` equals `insp.imagePath` (case-insensitive) or a limitation | sync | – | same |
| 13 | promote | `visible`, `sink.targetEffect("process-attached"/"agent-injected")` | sync | `running` | – |

`startTime.source` is `"os-creation-time"` (inspect, 100 ns). Every attach observation carries the footprint limitation
(§7.5).

---

## 10. Agent channel (`src/frida/AgentChannel.ts`)

### 10.1 Host view of the agent→host envelope

The agent design owns this envelope in `src/shared/agentProtocol.ts`. This is the shape S3 consumes (ASSUMPTION until
that design confirms it):

```ts
export const AGENT_PROTOCOL_VERSION: number;          // 1
export type AgentToHost =
  | { bea: "ready"; v: number; pid: number; arch: string; platform: string; runtime: "QJS" | "V8"; fridaVersion: string;
      agentVersion: string; agentThreadId: number; main: { name: string; path: string; base: string; size: number };
      capabilities: string[] }
  | { bea: "batch"; v: number; channel: number; seq0: number; count: number; dropped: number; schema: string; final?: boolean } // + ArrayBuffer
  | { bea: "crash"; v: number; id: number; type: string; address: string; memory: { operation: string; address: string } | null;
      tid: number; regs?: Record<string, string>; backtrace?: string[] }   // agent then blocks on recv(`ack:${id}`)
  | { bea: "notice"; v: number; code: string; detail?: Record<string, unknown> }
  | { bea: "job"; v: number; jobId: string; state: "done" | "failed" | "cancelled"; summary?: Record<string, unknown> }
  | { bea: "fatal"; v: number; code: string; message: string };
export const agentToHostSchemas: { readonly [K in AgentToHost["bea"]]: z.ZodType<Extract<AgentToHost, { bea: K }>> };
// host -> agent posts: only { type: `ack:${id}` } (crash acks). Everything else is RPC.
```

### 10.2 Ready handshake

`channel.ready` settles exactly once.

**Resolves** on a `ready` payload that passes all of these:
- the schema;
- `v === AGENT_PROTOCOL_VERSION` (else `ProviderFailure` "agent/host protocol mismatch");
- `pid === expected pid` (else `InstanceMismatch`);
- `arch === "x64"` (else `Unsupported`; this catches WoW64 if injection somehow succeeded);
- `fridaVersion === "17.23.2"`;
- `runtime === "QJS"`.

**Rejects** on:
- `{type:"error"}` before ready: `load()` resolves even when the top level throws [ext-frida §1.6]. This gives
  `ProviderFailure{stage:"agent-load", diagnostics:{description, fileName, lineNumber}}`; the strings are untrusted and
  bounded to 4 KiB;
- `{bea:"fatal"}`;
- a detach or destroy;
- the 5 s timer.

### 10.3 Routing (never throws into Frida)

```ts
onMessage = (message: FridaMessage, data: Buffer | null): void => {
  try {
    if (message.type === "error") return this.#onAgentError(message);       // pre-ready: reject ready; post: fault ring
    const p = message.payload as { bea?: unknown } | null;
    if (p === null || typeof p !== "object" || typeof p.bea !== "string") { this.#counters.protocolViolations++; return; }
    switch (p.bea) {
      case "batch": return this.#pump.onBatch(p, data);                   // hot path: header checks only (§12)
      case "crash": return this.#crash.onCrash(this.#parse("crash", p));
      case "ready": return this.#onReady(this.#parse("ready", p));
      case "notice": return this.#onNotice(this.#parse("notice", p));
      case "job": return this.#onJob(this.#parse("job", p));
      case "fatal": return this.#onFatal(this.#parse("fatal", p));
      default: this.#counters.protocolViolations++;
    }
  } catch (e) { this.#counters.handlerErrors++; this.#logger.warn({ err: String(e) }, "agent message handler failed"); }
};
onLog = (level: LogLevel, text: string): void => { this.#logs.push({ level, text: boundUtf8(text, 4096), at: now() }); };
onDestroyed = (): void => { this.#rpc.markScriptDestroyed(); this.#crash.ackAll("destroyed"); this.#hub.notify(); };
```

- **logHandler.** It is set in the same tick as `createScript` resolves, and is never left at the default, because the
  default handler prints to host stdout, which would corrupt stdio MCP (VERIFIED [rea-runtime §7 #6]; load-time
  `console.log` reached the handler, [S3-lab]). Logs go to a ring of 256 entries / 256 KiB. They are never written to
  stdout and only at debug level to stderr.
- **Faults** after ready (`type:"error"`, e.g. a throw in a timer) go to a ring of 32 entries, to
  `sink.agentFault` and to a counter. A fault does not end the session.
- `notice`: e.g. `channel-overflow` or `thread-observer-failed` goes to the session diagnostics and the sink.
  `job` notifies the hub.

---

## 11. Agent RPC (`src/ports/AgentRpc.ts`, `src/frida/AgentRpcClient.ts`)

### 11.1 Conventions required of the agent (agent design; ASSUMPTION until confirmed)

- `rpc.exports` method names are plain identifiers and never `then`/`catch`/`finally` (reserved by frida.js
  [ext-frida §1.1]).
- Every method returns `AgentReply<T> = {ok:true, value:T} | {ok:false, error:AgentErrorData}` and **does not throw for
  expected failures** (access violations, unmapped addresses, hook install failures). A throw means a bug.
- A binary result is the tuple `[AgentReply<Meta>, ArrayBuffer]`, which the host receives as `[reply, Buffer]`
  (VERIFIED).
- Binary input is a trailing `Buffer`, which the agent receives as its last argument, an `ArrayBuffer` (VERIFIED).
- `AgentMethods` maps every name to `{params, result, binary?: true}`, and `agentReplySchemas` holds a zod schema per
  method.
- S3 itself calls only `ping`, `configure` and `revertAll`.

### 11.2 Interface and algorithm

```ts
export type AgentHealth =
  | { readonly state: "ok" }
  | { readonly state: "suspect"; readonly since: number; readonly method: string }     // after a timeout, until a ping answers
  | { readonly state: "unresponsive"; readonly since: number }                         // ping failed: JS thread blocked
  | { readonly state: "gone"; readonly reason: DetachReason | "script-destroyed" };
export interface AgentCallOptions { readonly op: OperationContext; readonly timeoutMs?: number; readonly data?: Buffer }
export interface AgentRpc {
  call<M extends AgentMethodName>(method: M, params: AgentParams<M>, opts: AgentCallOptions): Promise<Result<AgentValue<M>, BeaError>>;
  readonly health: AgentHealth;
}
```

```ts
async call(method, params, { op, timeoutMs, data }) {
  if (this.#health.state === "gone") return err(this.#goneError(method));
  if (this.#health.state === "unresponsive") return err(timeout(method, 0, "agent JS thread is blocked"));
  if (op.signal.aborted) return err(classifyAbort(op.signal, method));
  const ms = Math.min(timeoutMs ?? this.#limits.rpcDefaultTimeoutMs, op.deadline.remaining());
  const nc = this.#host.nativeCancel({ deadline: Deadline.after(ms), signal: op.signal });
  try {
    const fn = this.#script.exports[method]!;
    const raw = await (data ? fn(...params, data, nc.token) : fn(...params, nc.token));
    return this.#decode(method, raw);                     // zod: AgentReply / [AgentReply, Buffer]; mismatch => ProviderFailure
  } catch (e) {
    return err(await mapRpcRejection(e, { method, why: nc.outcome(), op, terminal: () => this.#terminalInfo(50) }));
  } finally { nc.dispose(); }
}
```

- A timeout moves `health` to `suspect`, and a background `ping` with a 1 s deadline follows. A ping failure means
  `unresponsive`: later calls fail fast until a ping succeeds (one ping per 2 s at most).
- The likely cause is a `call_function` that never returns: `NativeFunction` runs on the agent's JS thread, and a cancel
  only stops the host from waiting (VERIFIED busy-cancel).
- The remediation names `close_session`, which kills an owned target. For an attached target, detach may not complete
  while the thread is blocked, and that case is reported honestly.

### 11.3 Rejection mapping (`src/frida/rpcErrors.ts`)

| Rejection | Condition | BeaError | Code |
|---|---|---|---|
| `Script is destroyed` | detach `process-terminated`, or jobhost/watcher root-exit (wait ≤ 50 ms for that info) | `TargetExited{exit}` | `target_exited` (recovery `reattach`) |
| `Script is destroyed` | detach for another reason | `CapabilityUnavailable{capability:"agent", reason:"agent-gone", detach_reason}` | `capability_unavailable` |
| `Script is destroyed` | BEA is closing | `CapabilityUnavailable{reason:"closing"}` | `capability_unavailable` |
| `Operation was cancelled` | `why == "deadline"` | `Timeout{timeout_ms}` | `provider_timeout` (retryable, `inspect_timeout_state`) |
| `Operation was cancelled` | `why == "aborted"` | as classified (§7.2) | `cancelled` / … |
| `unable to find method` | – | `Internal` ("agent/host protocol skew") | `execution_failure` |
| other `Error` (an agent throw) | – | `ProviderFailure{diagnostics:{agent_error_name}}`, with the message curated and the agent text kept in diagnostics as untrusted | `execution_failure` |
| reply `{ok:false, error}` | schema-valid | the agent's tag mapped 1:1 into the BeaError union (plain data [rea-evidence §10.1]) | per tag |
| reply fails the schema | – | `ProviderFailure` "agent reply did not match protocol" | `execution_failure` |

---

## 12. Event pump (`src/frida/EventPump.ts`)

### 12.1 Interfaces required from S2

```ts
export type StreamKind = "hook" | "watch" | "trace" | "exception" | "stdio" | "module" | "thread" | "api";
export type StreamDropReason = "agent-buffer" | "seq-gap" | "host-queue-full" | "quota" | "malformed";
export type StreamEndReason = "stopped" | "process-exited" | "process-killed" | "detached" | "limit" | "install-failed" | "shutdown";
export interface StreamWriter {
  readonly streamId: string;                                // st_…
  append(batch: { firstSeq: number; count: number; agentDropped: number; payload: Buffer; receivedAtNs: bigint }):
    "accepted" | "queue-full" | "quota-exceeded" | "closed";  // SYNC enqueue; never blocks; S2 writes raw chunks async (D12)
  noteDropped(n: number, reason: StreamDropReason): void;
  close(end: { reason: StreamEndReason; deadline: Deadline }): Promise<Result<StreamManifestRef, BeaError>>;
  stats(): { accepted: number; bytes: number; queuedBytes: number; dropped: Readonly<Record<StreamDropReason, number>> };
}
export interface StreamStore {
  open(spec: { sessionId: SessionId; instanceId: string; kind: StreamKind; schema: string; recordBytes: number | null;
               sourceEffectId: string | null }): Result<StreamWriter, BeaError>;
}
export interface StreamManifestRef { readonly streamId: string; readonly evidenceId: string | null; readonly endReason: StreamEndReason }
```

### 12.2 Channel binding (host-allocated ids)

```ts
export interface ChannelBinder {
  allocate(spec: { kind: StreamKind; schema: string; recordBytes: number | null; sourceEffectId: string | null }):
    Result<{ channel: number; streamId: string }, BeaError>;      // BEFORE the instrumenting RPC; channel passed to the agent
  end(channel: number, reason: StreamEndReason, deadline: Deadline): Promise<Result<StreamManifestRef, BeaError>>;
  counters(channel: number): ChannelCounters | null;
}
export interface ChannelCounters {
  readonly channel: number; readonly streamId: string; readonly kind: StreamKind;
  readonly received: number; readonly batches: number; readonly agentDropped: number;
  readonly hostDropped: Readonly<Record<"seq-gap" | "host-queue-full" | "quota" | "malformed", number>>;
  readonly ended: boolean; readonly endReason: StreamEndReason | null;
}
```

The host allocates the channel id and binds the stream **before** calling the agent, so a hit that races the RPC reply
still has a home. If the instrumenting RPC fails, the channel ends with `install-failed`. Channel 0 is reserved for the
agent's exception stream and channel 1 for module and thread events. Both are bound in startup step 12 (ASSUMPTION; the
agent design confirms).

### 12.3 `onBatch` (hot path; O(1); never awaits, never throws)

```ts
onBatch(h: { channel: unknown; seq0: unknown; count: unknown; dropped: unknown; final?: unknown }, data: Buffer | null) {
  const b = typeof h.channel === "number" ? this.#bindings.get(h.channel) : undefined;
  if (!b) { this.#counters.unknownChannelBatches++; return; }
  if (!isU32(h.seq0) || !isU32(h.count) || !isU32(h.dropped) || data === null
      || (b.recordBytes !== null && data.length !== h.count * b.recordBytes)) {
    const n = isU32(h.count) && h.count > 0 ? h.count : 1;           // best estimate of the events lost
    b.hostDropped.malformed += n; b.writer.noteDropped(n, "malformed"); return;
  }
  if (h.seq0 > b.expectedSeq) { const gap = h.seq0 - b.expectedSeq; b.hostDropped["seq-gap"] += gap; b.writer.noteDropped(gap, "seq-gap"); }
  else if (h.seq0 < b.expectedSeq) { b.hostDropped.malformed += h.count; return; }   // duplicate/reorder: never expected
  b.agentDropped += h.dropped;
  const r = b.writer.append({ firstSeq: h.seq0, count: h.count, agentDropped: h.dropped, payload: data, receivedAtNs: process.hrtime.bigint() });
  if (r === "queue-full") b.hostDropped["host-queue-full"] += h.count;
  else if (r === "quota-exceeded") { b.hostDropped.quota += h.count; this.#onQuota(b); }   // sink notice; instrument service may stop it
  else if (r === "accepted") b.received += h.count;
  b.expectedSeq = h.seq0 + h.count; b.batches++;
  if (h.final === true) b.ended = true;
  this.#hub.notify();
}
```

The send ceiling is about 8K msg/s and batches are required [ext-frida §1.9]. At 16,384 events per batch, 1.2M events/s
is about 73 messages/s, well within budget. On `exited`, `detached` or close, `endAll(reason)` closes every writer in the
background, and the close promises are tracked so close and `closeAll` can await them. Coverage follows S2's rule:
`complete` only if nothing was dropped and the end reason is normal [rea-evidence §10.6].

---

## 13. Crash protocol (`src/frida/CrashProtocol.ts`)

```ts
export interface AgentCrashReport {               // validated `crash` payload plus host facts (all target fields untrusted)
  readonly id: number; readonly type: string; readonly address: string;
  readonly memory: { readonly operation: string; readonly address: string } | null;
  readonly tid: number; readonly regs: Readonly<Record<string, string>> | null; readonly backtrace: readonly string[] | null;
  readonly receivedAt: TimeMark;
  ack: { readonly at: TimeMark; readonly via: "recorded" | "timeout" | "closing" | "shutdown" | "destroyed" } | null;
}
```

Sequence (VERIFIED end to end under the job [S3-lab]):

```
agent (faulting thread, first chance)       host (Node main thread)                     jobhost
send({bea:'crash', id:N, …}) ───────────►  onCrash: dedupe id; push ring (16);
recv('ack:N').wait()   (blocks)            arm 5 s timer;
                                           sink.crashReport({report, deadline 5 s})
                                             └─ resolves (Evidence recorded) or timer fires
                           ◄────────────── script.post({type:'ack:N'})   (exactly once)
return false  → SEH → unhandled
→ DIE_ON_UNHANDLED_EXCEPTION ───────────────────────────────────────────────────────►  root-exit 0xC0000005
                                           detached('process-terminated', crash=null)
```

- **Per-crash ack type `ack:<id>`.** `recv(type)` takes the next message of that type, so concurrent crashes on several
  threads must not steal each other's acks. VERIFIED with id 1.
- **Record before ack.** `sink.crashReport` writes the `bea.exception.report` Evidence (observed, live-process) and the
  exception-stream event first. On a 5 s timeout the ack goes anyway, `ack.via:"timeout"`, with the limitation
  "Crash acknowledged before its Evidence write completed". The target is never held more than 5 s.
- **Immediate acks:** `ackAll(via)` on session close, `closeAll`, script destroy, and before `unload`.
- **Derived crash conclusion** (`crash_summary` in status and in the close report):
  - Root exit with an NTSTATUS error code (§14.3), together with a report received ≤ 2 s before it, gives
    `{crashed:true, report_id, exit}`.
  - An error exit with no report gives `{crashed:true, report:null}` plus the limitation "No in-process exception report
    (fail-fast exceptions such as 0xC0000409 bypass in-process handlers)". The bypass is BELIEVED.
  - Owned targets get the exit code from the jobhost and attached ones from the watcher. Windows `crash` is always
    `null` (VERIFIED [ext-frida §1.5]).
- First-chance exceptions that the app handles also reach the handler [ext-frida §3.11]. Which ones the agent
  block-acks (for example, only crash-class types and the first occurrence per `(type, pc)`) is the agent design's
  policy. The host side is identical either way.

---

## 14. Detach and exit handling

### 14.1 Detach handler (`onDetached`, connected at step 8)

| Reason | Requested by BEA? | New state | Liveness | Notes |
|---|---|---|---|---|
| `application-requested` | yes (close) | (`closing`) | unchanged | normal |
| `application-requested` | no | `detached` | jobhost/watcher | unexpected; recorded |
| `process-terminated` | – | `exited` | `exited` | kill, exit and crash all look like this; `crash` null on Windows (VERIFIED) |
| `process-replaced` | – | `detached` | alive (new image) | POSIX exec; not expected on Windows (BELIEVED) |
| `connection-terminated`, `device-lost` | – | `detached` | jobhost/watcher | owned: the target is still in the job (`close_session` kills it); attached: it runs on, agent gone |

On any detach:
1. Record `DetachInfo`.
2. `rpc.markGone`: pending RPCs reject with `Script is destroyed` (VERIFIED) and map through §11.3.
3. `crash.ackAll("destroyed")`.
4. `pump.endAll(reason)`.
5. `sink.detached`; S2 marks effects `implicit-end` (hooks die with the script). Memory writes persist; the effect
   design decides how to label them.
6. `hub.notify()`.

### 14.2 jobhost and watcher events → session

| Event | Effect |
|---|---|
| `root-exit` | `record.exit` (`source:"jobhost"`/`"watcher"`); `transition(exited)` unless already; `sink.rootExit` |
| `settled` | `record.tree = {active, settled:true}` |
| `proc-start`, `proc-exit` | `sink.procEvent` (behaviour tracing: "what does this program start"); counts in `tree` |
| `memory-limit` | `sink` notice; the owned target keeps running (allocations fail) |
| helper exit without `settled` and not killing | `helper-lost` → `exited` with basis `helper-lost-kernel-kill` |

Event order varies; the lab saw `detached` 1 ms before `root-exit`. The record converges whatever the order: `exited`
holds the earliest observation, and later events add the exit code and tree data.

### 14.3 `src/process/ntstatus.ts`

| Code | Name |
|---|---|
| `0xC0000005` | STATUS_ACCESS_VIOLATION |
| `0xC000001D` | STATUS_ILLEGAL_INSTRUCTION |
| `0xC0000094` | STATUS_INTEGER_DIVIDE_BY_ZERO |
| `0xC0000095` | STATUS_INTEGER_OVERFLOW |
| `0xC000008E` | STATUS_FLOAT_DIVIDE_BY_ZERO |
| `0xC000008F` | STATUS_FLOAT_INEXACT_RESULT |
| `0xC0000090` | STATUS_FLOAT_INVALID_OPERATION |
| `0xC0000091` | STATUS_FLOAT_OVERFLOW |
| `0xC0000092` | STATUS_FLOAT_STACK_CHECK |
| `0xC0000093` | STATUS_FLOAT_UNDERFLOW |
| `0xC00000FD` | STATUS_STACK_OVERFLOW |
| `0xC0000409` | STATUS_STACK_BUFFER_OVERRUN (fail-fast) |
| `0xC0000602` | STATUS_FAIL_FAST_EXCEPTION |
| `0xC0000374` | STATUS_HEAP_CORRUPTION |
| `0xC0000420` | STATUS_ASSERTION_FAILURE |
| `0xC0000017` | STATUS_NO_MEMORY |
| `0xC0000135` | STATUS_DLL_NOT_FOUND |
| `0xC0000142` | STATUS_DLL_INIT_FAILED |
| `0xC000013A` | STATUS_CONTROL_C_EXIT |
| `0xE06D7363` | MSVC C++ exception |
| `0x80000003` | STATUS_BREAKPOINT |
| `0x80000004` | STATUS_SINGLE_STEP |
| `0xBEA` | BEA terminated the job (meaningful only with `byKill`) |

`kind` is `bea-kill` when `byKill`; `ntstatus-error` when `code ≥ 0xC0000000`; otherwise `normal`.

---

## 15. Output capture (`src/process/BoundedCapture.ts`, `OutputCapture`)

```ts
export interface StreamTextCapture {
  readonly head: string; readonly tail: string;                 // UTF-8 decoded with replacement, trimmed to code-point boundaries
  readonly observedBytes: number; readonly retainedBytes: number; readonly omittedBytes: number;
  readonly truncated: boolean; readonly invalidUtf8: boolean; readonly eof: boolean;
}
export interface OutputSnapshot { readonly stdout: StreamTextCapture; readonly stderr: StreamTextCapture; readonly otherFds: readonly { fd: number; bytes: number }[] }
export interface OutputCapture {
  readonly pid: number;
  onChunk(fd: number, data: Buffer): void;     // zero-length => EOF on that fd (VERIFIED)
  snapshot(): OutputSnapshot;
  readonly eof: Promise<void>;                 // both fd1 and fd2 reached EOF
  close(): void;                               // stops accepting; idempotent
}
export function createOutputCapture(o: { pid: number; headBytes: number; tailBytes: number; stream: StreamWriter | null }): OutputCapture;
```

- Every byte is drained. The first `headBytes` (64 KiB) are kept, plus a ring of the last `tailBytes` (192 KiB) per fd.
  Observed and retained bytes are counted separately, and truncation is evidence, not failure [rea-process §8.2].
- `invalidUtf8` comes from a fatal `TextDecoder` over the retained bytes. Windows console programs may emit OEM code
  pages.
- Every chunk is also appended to the session's `stdio` stream (schema `stdio.v1`: `u8 fd` + bytes, one event per chunk)
  for `query_events`. Once the stream quota is hit, output still drains into head and tail, and the drop is counted.
- `captureOutput:false` (Windows only) uses `stdio:"inherit"`. Output is then not observed [rea-runtime §7 #19], and
  this does not corrupt the MCP channel on Windows (VERIFIED [rea-testing §0.6]). On Linux `inherit` would share the
  JSON-RPC stdout (BELIEVED), so Linux always pipes.

---

## 16. Cancellation discipline

1. Every public async entry takes an `OperationContext`. Check `op.signal` at dispatch (after the queue) and after
   **every** await (`checkpoint(op)`).
2. The first observed failure is primary. Cleanup failures go to `cleanup.reason` and turn the code into
   `cleanup_incomplete` with `details.execution_failure`. A native failure that happened before an abort is kept as
   `diagnostics.native_failure` [rea-runtime §6].
3. Native calls that create or start OS resources are **never cancelled**: `device.spawn`, `device.resume`,
   `device.kill`. They are awaited under a guard timer and compensated afterwards. A cancelled spawn could lose the pid of
   a suspended child.
4. Native calls that only wait get one fresh `NativeCancel` bound to the step deadline and `op.signal`: `getDeviceById`,
   `enumerateProcesses`, `attach`, `createScript`, `load`, `unload`, `detach`, `dm.close`, and every RPC.
5. An RPC cancel stops the host waiting; agent work continues (VERIFIED). Hence `health: suspect`, then a ping.
6. Startup is atomic: a cancel or failure during `spawn_process` or `attach_process` kills (owned) or detaches
   (attached). Committed effects of other tools (a hook installed, a function called) are not rolled back on cancel;
   they are reported.
7. After a cancellation the SDK suppresses the reply [rea-mcp §1.9]. The service layer records partial Evidence through
   the sink. The host returns `Cancelled` with `partial` details (stage reached, pid, whether it was killed).
8. Abort reasons are typed (`shutdown`, `session-closing`, `caller`, `deadline`), and `classifyAbort` distinguishes
   cancelled from timeout [rea-process §4.2].
9. Every background promise (spawn guard, writer close, ping, kill) is tracked on its record or in the registry. None is
   orphaned.
10. Frida callbacks (`message`, `output`, `detached`, `destroyed`, `logHandler`) and jobhost event listeners are O(1).
    They never await and never throw.

---

## 17. Errors produced by the host

Tags follow the BeaError union [rea-evidence §10.1] and codes follow BRIEF §1.6.

| Situation | Tag | Code |
|---|---|---|
| shutting down; agent gone; jobhost missing or hash mismatch; containment assign failed; binding failed; platform unsupported (macOS) | `CapabilityUnavailable{capability, reason}` | `capability_unavailable` |
| capacity (live, piped, queued ops) | `ResourceLimit{resource:"capacity"}` | `resource_constraint` (retryable) |
| unknown or closed session id | `SessionNotFound` (ASSUMPTION: the tag exists) | `session_not_found` |
| bad program path, `.bat`/`.cmd`, pid not found, pid already in session, op not allowed in state | `InputError{issues}` | `invalid_request` |
| non-x64 PE, WoW64 | `Unsupported` | `unsupported_target` |
| protected, critical, session 0, system denylist, other user, higher integrity, elevation required (740), Frida "access denied" | `AccessDenied{reason}` | `access_denied` |
| adopt identity mismatch, ready pid mismatch, `expectSha256` mismatch, creation time changed | `InstanceMismatch` | `instance_mismatch` |
| process gone (RPC, resume) | `TargetExited{exit}` | `target_exited` |
| deadline (device lookup, attach, load, ready, RPC) | `Timeout{timeout_ms, stage}` | `provider_timeout` |
| cancel | `Cancelled` | `cancelled` |
| revert failed on close | `EffectUnreverted{effect_ids}` | `effect_unreverted` |
| agent load error, protocol skew, malformed reply, helper protocol violation, unexpected Frida error | `ProviderFailure` / `Internal` | `execution_failure` |

Messages are curated and never contain raw Frida, agent or helper text. Raw text, bounded and untrusted, goes to
`diagnostics` [rea-evidence §2.4].

---

## 18. Hooks into Evidence (required from the application layer, backed by S2)

```ts
export interface SessionEventSink {
  stateChanged(e: { sessionId: SessionId; from: SessionState; to: SessionState; cause: StateCause; at: TimeMark }): void;
  targetEffect(e: { sessionId: SessionId; kind: "process-spawned" | "process-attached" | "agent-injected" | "process-resumed"
                    | "process-killed" | "agent-unloaded" | "process-detached"; facts: Readonly<Record<string, JsonValue>>; at: TimeMark }): void;
  rootExit(e: { sessionId: SessionId; exit: ProcessExit; activeAfterRoot: number | null; at: TimeMark }): void;
  procEvent(e: { sessionId: SessionId; kind: "proc-start" | "proc-exit"; pid: number; abnormal: boolean | null; at: TimeMark }): void;
  detached(e: { sessionId: SessionId; info: DetachInfo }): void;
  agentFault(e: { sessionId: SessionId; fault: AgentFault }): void;
  crashReport(e: { sessionId: SessionId; report: AgentCrashReport; deadline: Deadline }): Promise<void>;   // before the ack (§13)
  sessionEnded(e: { sessionId: SessionId; report: CloseReport; deadline: Deadline }): Promise<void>;     // manifests, effects, flush
}
export interface AgentFault { readonly kind: "error-message" | "fatal" | "notice"; readonly description: string; readonly fileName: string | null;
                              readonly lineNumber: number | null; readonly at: TimeMark }
```

Synchronous methods must not throw and must queue their work. The async methods must honour `deadline`. Identity and
containment facts for the `pi_` record come from `SessionObservation` [rea-evidence §10.2].

---

## 19. Linux and macOS

**Linux x64, best effort.**
- `ProcessInspector` reads `/proc/<pid>/stat`: field 22 is `starttime` in clock ticks since boot, turned into an
  absolute time with `btime` from `/proc/stat` and `CLK_TCK` 100 (BELIEVED default). It also reads `/proc/<pid>/exe` and
  `/proc/<pid>/status` (Uid).
- Attach refusals: pid 1, kernel threads (no `exe`, ppid 2), another uid (`AccessDenied`), and
  `kernel.yama.ptrace_scope ≥ 2` (`CapabilityUnavailable`).
- Spawn is Frida spawn with `stdio:"pipe"` and no jobhost. `BestEffortOwnership` records `{pid, startTicks}`.
- Kill:
  1. Re-verify `starttime`.
  2. Snapshot the descendants by walking `/proc/*/stat` ppid links from the root, keeping only those with
     `starttime ≥ root`.
  3. If the root leads its own process group (`pgid == pid`), send `SIGKILL` to `-pid`.
  4. `SIGKILL` the root and each descendant, re-verifying start time per pid.
  5. Poll until `/proc/<pid>` is gone (≤ 1 s).
- Containment `{kind:"posix-best-effort", crashSafe:false}` with this exact limitation:
  > "Linux: BEA could not place this Frida-spawned target in a kernel container. On close BEA kills the target, its
  > process group if it leads one, and the descendants it finds by walking /proc parent links at that moment (pid and
  > start time verified). Daemonized descendants (setsid or double fork) can escape, and if the BEA server is killed
  > without running its cleanup, the target and its descendants keep running."
- The whole Linux path is BELIEVED and untested on this host (L10). A `bea-reaper` subreaper is later work
  [rea-process §9.1].

**macOS:** `spawn` and `attach` return `CapabilityUnavailable{capability:"platform", reason:"macOS targets are not
supported in BEA v0.1"}`, and `bea_status` reports `platform.support:"unsupported"`.

---

## 20. Runtime wiring

- **One runtime per process.** `FridaHost`, `SessionManager` and the jobhost factory are created once in `createRuntime`
  and shared by every MCP server instance the stdio factory creates. `serveStdio` may call the factory twice
  [rea-mcp §1.10], so a discarded probe instance owns nothing. A server instance's `close` does not close the runtime;
  process shutdown does (§7.6).
- **`bea mcp --http`.** The same runtime serves every HTTP client. Sessions are process-global (UUIDs are unguessable),
  and a client disconnect does not close sessions in v0.1. Shutdown comes from signals only.
- **CLI one-shots.** `withRuntime(async (rt) => …)` creates a runtime per command and always awaits `rt.closeAll("cli-exit")`
  with a 5 s budget. Help text says that an attach injects the agent and leaves 11 DLLs [rea-cli §9.7].
- **`bea doctor`** runs `jobhost probe`, `jobhost inspect <own pid>` (inspect self-test), `FridaHost.device()` and the
  agent bundle hash check. An opt-in `--probe` spawns the fixture-like `node -e` child and attaches to it. Doctor never
  touches foreign processes.

---

## 21. Tests for this subsystem (REA layering [rea-testing §11])

**Fast lane (fake Frida, in-memory MCP).**
- `tests/support/frida/fakeFrida.ts` implements the §4.1 ports. Every native call is gated with `gate()`, every signal
  `connect`/`disconnect` is counted, and failures can be injected.
- A `FakeJobHost` implements `JobHostPort`/`ProcessWatcherPort` with scriptable events.

Must-have cases:
1. State machine table, exhaustive, with illegal edges throwing.
2. Capacity: the 5th live session, the 4th piped session and the 17th queued op are refused with exact messages; a
   concurrent spawn race does not overshoot (reservations).
3. Admission: `closeAll` during an in-flight `attach` (gate on attach) aborts it, and the startup is cleaned up.
4. Startup interleavings: cancel at each of steps 3–12, with the right cleanup (owned → kill, attached → unload/detach,
   **never** kill).
5. Spawn guard expiry, then a late spawn resolve leads to a kill.
6. Detach `process-terminated` while an RPC is pending gives `target_exited`; `connection-terminated` gives
   `agent-gone`.
7. Crash: a report triggers `sink.crashReport` and then exactly one ack; a sink stalled past 5 s still acks;
   `ackAll` on close.
8. Pump: seq gap, malformed batch, unknown channel, queue-full and quota counters.
9. `closeAll` order assertions: the kill on every owned jobhost is issued before the first attached `unload`; then
   disconnects; then `dm.close` **last**; every `connect` has a matching `disconnect` (counter = 0).
10. Retry: detach throws once, so `closeAll` rejects with an `AggregateError`. The second `closeAll` retries only that
    owner, and the third is a no-op [rea-testing §6.2].
11. Liveness never calls `enumerateProcesses({pids})` (spy).
12. Attach policy table, rules 1–11.

**Process-boundary lane** (serial; real `bea-jobhost.exe`; win32): port the cases in `jh-smoke.mjs` and `jh-fd4.mjs` 1:1
(probe, inspect, identity refusals, nested-job adopt, EOF kill, stragglers kept and then killed, watch never kills,
fd4, kill while suspended). The protocol zod schema validates every line seen.

**Acceptance lane** (real Frida + gcc fixtures, owned-PID ledger with creation times, leak assertion):
- the `frida-lab.mjs` cases through the MCP stdio server;
- `close` < 2,000 ms and server `exitCode 0` with 4 live sessions (3 piped owned + 1 attached, started by the test via
  `child_process`) plus an emulator session;
- the attached target is alive afterwards;
- a hard `taskkill /F` of the server leaves no owned target alive (`hardKillTargetSurvived:false`, expected now that
  adopt is in place) [rea-testing §11.4 #3];
- the crash fixture gives `0xC0000005` with a report.

Skips are named (`it.skipIf(reason)`), and `retry: 0`.

---

## 22. Assumptions, conflicts with other designs, open questions

**Conflicts and deviations (for the orchestrator).**
- **C1.** `adopt` takes `--tolerance-100ns`, `--expect-image` and `--expect-parent` beyond the requested
  `adopt <pid> <creationTime100ns>`. The extra checks are needed because Frida's `started` has µs precision (VERIFIED).
- **C2.** The jobhost adds `watch` and `inspect` modes beyond adopt/spawn/probe. Attach identity, the refusal policy and
  attached-target exit codes depend on them.
- **C3.** BRIEF §3.1 suggests the shared `getDeviceManager()`. This design uses an owned `new DeviceManager()` (H1).
- **C4.** BRIEF §1.8 drains admitted ops before killing. This design aborts, kills at t0 and drains with a bound (§7.6).
- **C5.** BRIEF §2.5 and the labs use `{type:'ack'}`. This design requires a per-crash `ack:<id>`, so the agent must
  match.
- **C6.** The jobhost default is now **keep stragglers** (orchestrator). The lab default was kill; `--kill-on-root-exit`
  stays for BEA's own helpers.
- **C7.** Channel ids are allocated by the host and passed into the instrumenting RPC. The agent must accept them, and
  channels 0 and 1 are reserved.
- **C8.** Agent RPC methods must return `AgentReply<T>` (or `[AgentReply<Meta>, ArrayBuffer]`) and not throw for
  expected failures. Every reply is zod-validated.
- **C9 (agent design).** Debug registers armed on an **attached** target survive a script destroy if the BEA server dies
  (BELIEVED). A later trap with no handler would crash the user's process. The agent should prefer page-guard watches on
  attached targets, or clear DR7 on every observed thread in `revertAll`. The residual risk must be documented.
- **C10.** `SessionNotFound` is assumed to exist as a BeaError tag; BRIEF has the code `session_not_found`, but the
  rea-evidence tag list lacks it.

**Assumptions.**
- **A1.** The default `cwd` is `dirname(program)`; games load assets relative to their own directory.
- **A2.** The emulator session cap is separate (4) and owned by the emulator design. Emulator bridges run under
  `jobhost spawn --stdin-fd4 --kill-on-root-exit --mem-limit` (fd4 plumbing VERIFIED).
- **A3.** `sink.sessionEnded` and `sink.crashReport` honour their deadlines; S2's fsync happens at finalize
  (orchestrator).
- **A4.** Frida delivers each script's messages FIFO, so an RPC reply cannot overtake earlier batches (BELIEVED; it held
  in every lab). Pre-binding (C7) makes this harmless anyway.
- **A5.** A failed `import("frida")` is cached by the ESM loader, which makes it permanent (BELIEVED).

**Residual risks.**
- **R-S3-1.** A server crash in the 15–35 ms spawn→adopt window leaves a suspended, uncontained root. v0.2: pre-armed
  adopt.
- **R-S3-2.** Protected/critical detection was verified only on non-protected processes (lab rule). Behaviour on real
  PPL or critical processes is BELIEVED.
- **R-S3-3.** Launchers such as Steam relaunch the game outside the job: a root exit within seconds with code 0 and
  `activeAfterRoot` about 1 (conhost only). The session then reports the limitation "Program exited quickly; it may have
  relaunched itself through a launcher (outside BEA's job). Use list_processes + attach_process on the relaunched game,
  or start it in a way that avoids the relaunch (e.g. a steam_appid.txt next to the executable)" [rea-process §11 #9].
  The steam_appid.txt advice is BELIEVED.
- **R-S3-4.** The `stdio:'pipe'` slowdown at 4+ targets has an unknown root cause (L1); the cap is a workaround.
- **R-S3-5.** Unsigned `bea-jobhost.exe` versus Defender/SmartScreen is untested (R18). The doctor probe detects a
  blocked helper.

**Resolved here (previously open):**
- L2: Frida `started` is µs-truncated FILETIME UTC (VERIFIED).
- L3: the agent handler runs before `DIE_ON_UNHANDLED_EXCEPTION` termination, and report → ack → exit `0xC0000005`
  works, for the report-and-die case (VERIFIED, N=1, QJS).
- Nested-job adopt (VERIFIED).
- `Cancellable` does not pin the loop (VERIFIED).
- Owned DM close plus disconnects gives a natural exit (VERIFIED).

---

## Appendix A. `native/jobhost/bea-jobhost.c` (protocol 1; tested source)

Lab copy:
`<scratch>/bea-lab/design-S3-host/bea-jobhost.c`
(801 lines, source sha256 `8141780b17b1c1cc8e417a05f638b69c2efe3737bc7ade486a561be1714c3812`).

Built with `gcc -O2 -s -municode -D_WIN32_WINNT=0x0A00 -static -Wall -Wextra` (no warnings); the exe is 66,560 B with
sha256 `7d89f5db9fc51e19a825d76fe94a25c945144ec873088c21659b80c898df2c53`. The build script adds
`-Werror -Wl,--no-insert-timestamp`.

```c
/*
 * bea-jobhost.c -- BEA Windows process-containment helper, protocol 1.
 *
 * One helper process per BEA-owned target (adopt/spawn) or per attached target (watch).
 *
 *   bea-jobhost adopt   <pid> <creationTime100ns> [--tolerance-100ns N] [--expect-image PATH]
 *                       [--expect-parent PID] [--mem-limit BYTES] [--kill-on-root-exit]
 *   bea-jobhost spawn   [--suspended] [--stdin-fd4] [--mem-limit BYTES] [--kill-on-root-exit]
 *                       -- <absolute-exe> [args...]
 *   bea-jobhost watch   <pid> <creationTime100ns> [--tolerance-100ns N]
 *   bea-jobhost inspect <pid>
 *   bea-jobhost probe
 *   bea-jobhost version
 *
 * Containment (adopt/spawn): ONE unnamed, non-inheritable Job Object with
 * KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION [| JOB_MEMORY], no breakaway (policy read back).
 * If this helper dies for any reason the kernel closes the last job handle and kills the tree.
 * watch/inspect never create a job and never request PROCESS_TERMINATE: they cannot kill.
 *
 * Control (fd0, ASCII lines): "kill" | "resume" | "status".  EOF or broken pipe:
 *   adopt/spawn -> terminate the job (owner went away);  watch -> exit 0 without touching the target.
 * Status: NDJSON lines on fd3 when the parent supplied one (CRT lpReserved2), otherwise stdout.
 *   spawn mode REQUIRES fd3 because fd1/fd2 carry the target's stdout/stderr.
 * 64-bit values that can exceed 2^53 (creation times) are JSON strings.
 *
 * Build (MinGW-w64): gcc -O2 -s -municode -D_WIN32_WINNT=0x0A00 -static -Wall -Wextra
 *                    -o bea-jobhost.exe bea-jobhost.c
 */
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <io.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define JH_VERSION "0.1.0"
#define JH_PROTOCOL 1

/* Exit codes: status events are authoritative; these are only a fallback. */
#define JH_EXIT_KILLED 0xBEAu /* BEA terminated the job; every job member exits with this code */
#define JH_EXIT_USAGE 0xBEA1u
#define JH_EXIT_OPEN 0xBEA2u
#define JH_EXIT_IDENTITY 0xBEA3u
#define JH_EXIT_JOB 0xBEA4u
#define JH_EXIT_ASSIGN 0xBEA5u
#define JH_EXIT_CREATE 0xBEA6u
#define JH_EXIT_MEMBERSHIP 0xBEA7u
#define JH_EXIT_STATUS 0xBEA8u
#define JH_EXIT_PROBE 0xBEA9u
#define JH_PROBE_CHILD_CODE 0x5EAu
#define JH_MAX_PROC_EVENTS 256
#define JH_SETTLE_MS 2000

typedef enum { M_NONE, M_ADOPT, M_SPAWN, M_WATCH, M_INSPECT, M_PROBE, M_VERSION, M_PROBE_CHILD } Mode;

static CRITICAL_SECTION g_emitLock;
static HANDLE g_status = INVALID_HANDLE_VALUE;
static int g_statusFd3 = 0;
static Mode g_mode = M_NONE;
static HANDLE g_job, g_port, g_root, g_rootThread, g_killEvent, g_zeroEvent;
static DWORD g_rootPid;
static volatile LONG g_killReason; /* 0 none, 1 control, 2 eof */
static volatile LONG g_procEvents;
static int g_killOnRootExit;
static ULONGLONG g_t0;

/* ---------- output helpers (raw WriteFile, never CRT FILE*: see lab deadlock note) ---------- */

static void emitLine(const char* buf, int n) {
  DWORD w;
  EnterCriticalSection(&g_emitLock);
  WriteFile(g_status, buf, (DWORD)n, &w, NULL);
  LeaveCriticalSection(&g_emitLock);
}

static void emitf(const char* fmt, ...) {
  char buf[8192];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if (n > (int)sizeof buf - 2) n = (int)sizeof buf - 2;
  buf[n++] = '\n';
  emitLine(buf, n);
}

static void u64dec(ULONGLONG v, char out[24]) {
  char t[24];
  int i = 0;
  do { t[i++] = (char)('0' + (v % 10)); v /= 10; } while (v);
  int o = 0;
  while (i) out[o++] = t[--i];
  out[o] = 0;
}

/* JSON string literal (quoted) from a wide string, or `null` if absent/too long. */
static void jsonStrW(const wchar_t* w, char* out, size_t cap) {
  static char tmp[4 * 4096];
  if (!w) { strcpy(out, "null"); return; }
  int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, tmp, (int)sizeof tmp, NULL, NULL);
  if (n <= 0) { strcpy(out, "null"); return; }
  size_t o = 0;
  out[o++] = '"';
  for (int i = 0; tmp[i]; i++) {
    unsigned char c = (unsigned char)tmp[i];
    if (o + 8 >= cap) { strcpy(out, "null"); return; }
    if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
    else if (c < 0x20) { o += (size_t)sprintf(out + o, "\\u%04x", c); }
    else out[o++] = (char)c;
  }
  out[o++] = '"';
  out[o] = 0;
}

static void emitError(const char* stage, DWORD win32, const char* detail) {
  emitf("{\"event\":\"error\",\"stage\":\"%s\",\"win32\":%lu,\"detail\":\"%s\"}", stage, win32,
        detail ? detail : "");
}

static __attribute__((noreturn)) void finish(UINT code) {
  /* No CRT exit(): a thread blocked on stdin must not deadlock shutdown (lab-verified). */
  ExitProcess(code);
}

/* ---------- small Win32 helpers ---------- */

static ULONGLONG creationTime(HANDLE h) {
  FILETIME c, e, k, u;
  if (!GetProcessTimes(h, &c, &e, &k, &u)) return 0;
  return ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime;
}

static int imagePath(HANDLE h, wchar_t* out, DWORD cap) {
  DWORD n = cap;
  return QueryFullProcessImageNameW(h, 0, out, &n) ? 1 : 0;
}

typedef LONG(NTAPI* NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct {
  LONG ExitStatus;
  PVOID PebBaseAddress;
  ULONG_PTR AffinityMask;
  LONG BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
} BEA_PBI;

static LONGLONG parentPid(HANDLE h) {
  static NtQIP q;
  if (!q) q = (NtQIP)(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
  BEA_PBI pbi;
  ULONG len = 0;
  if (!q || q(h, 0 /* ProcessBasicInformation */, &pbi, sizeof pbi, &len) != 0) return -1;
  return (LONGLONG)pbi.InheritedFromUniqueProcessId;
}

static DWORD activeCount(void) {
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;
  memset(&a, 0, sizeof a);
  if (!QueryInformationJobObject(g_job, JobObjectBasicAccountingInformation, &a, sizeof a, NULL)) return 0;
  return a.ActiveProcesses;
}

static ULONGLONG peakJobMemory(void) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION x;
  memset(&x, 0, sizeof x);
  if (!QueryInformationJobObject(g_job, JobObjectExtendedLimitInformation, &x, sizeof x, NULL)) return 0;
  return (ULONGLONG)x.PeakJobMemoryUsed;
}

static int sameImage(const wchar_t* a, const wchar_t* b) {
  return CompareStringOrdinal(a, -1, b, -1, TRUE) == CSTR_EQUAL;
}

/* ---------- job creation (policy read back, completion port associated BEFORE assignment) ---------- */

static DWORD g_policyFlags;
static ULONGLONG g_memLimit;

static int makeJob(void) {
  g_job = CreateJobObjectW(NULL, NULL); /* unnamed; NULL SA => handle not inheritable */
  if (!g_job) { emitError("job-create", GetLastError(), NULL); return 0; }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
  memset(&info, 0, sizeof info);
  g_policyFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
  if (g_memLimit) {
    g_policyFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    info.JobMemoryLimit = (SIZE_T)((g_memLimit + 4095) & ~(ULONGLONG)4095);
  }
  info.BasicLimitInformation.LimitFlags = g_policyFlags;
  if (!SetInformationJobObject(g_job, JobObjectExtendedLimitInformation, &info, sizeof info)) {
    emitError("job-policy", GetLastError(), "set");
    return 0;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION rb;
  memset(&rb, 0, sizeof rb);
  if (!QueryInformationJobObject(g_job, JobObjectExtendedLimitInformation, &rb, sizeof rb, NULL) ||
      rb.BasicLimitInformation.LimitFlags != g_policyFlags) {
    emitError("job-policy", GetLastError(), "readback-mismatch");
    return 0;
  }
  g_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp;
  acp.CompletionKey = (PVOID)1;
  acp.CompletionPort = g_port;
  if (!g_port || !SetInformationJobObject(g_job, JobObjectAssociateCompletionPortInformation, &acp, sizeof acp)) {
    emitError("job-port", GetLastError(), NULL);
    return 0;
  }
  return 1;
}

static void policyJson(char* out, size_t cap) {
  char mem[24];
  u64dec(g_memLimit, mem);
  snprintf(out, cap,
           "{\"killOnClose\":true,\"dieOnUnhandledException\":true,\"breakawayAllowed\":false,"
           "\"memLimitBytes\":%s}",
           g_memLimit ? mem : "null");
}

/* ---------- threads ---------- */

static void emitStatusSnapshot(void) {
  int alive = g_root && WaitForSingleObject(g_root, 0) == WAIT_TIMEOUT;
  emitf("{\"event\":\"status\",\"rootAlive\":%s,\"active\":%lu,\"elapsedMs\":%lu}", alive ? "true" : "false",
        g_job ? activeCount() : 0UL, (unsigned long)(GetTickCount64() - g_t0));
}

static void handleCommand(const char* cmd) {
  if (!strcmp(cmd, "kill")) {
    if (g_mode == M_WATCH) { emitError("control", 0, "kill-not-permitted-in-watch"); return; }
    InterlockedCompareExchange(&g_killReason, 1, 0);
    SetEvent(g_killEvent);
  } else if (!strcmp(cmd, "resume")) {
    HANDLE t = InterlockedExchangePointer((PVOID*)&g_rootThread, NULL);
    if (!t) { emitError("resume", 0, "not-suspended"); return; }
    DWORD prev = ResumeThread(t);
    if (prev == (DWORD)-1) emitError("resume", GetLastError(), NULL);
    else emitf("{\"event\":\"resumed\",\"previousSuspendCount\":%lu}", prev);
    CloseHandle(t);
  } else if (!strcmp(cmd, "status")) {
    emitStatusSnapshot();
  } else if (cmd[0]) {
    emitError("control", 0, "unknown-command");
  }
}

static DWORD WINAPI controlThread(LPVOID unused) {
  (void)unused;
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  char buf[256], line[64];
  size_t len = 0;
  int overflow = 0;
  DWORD n;
  while (ReadFile(in, buf, sizeof buf, &n, NULL) && n > 0) {
    for (DWORD i = 0; i < n; i++) {
      char c = buf[i];
      if (c == '\r') continue;
      if (c != '\n') {
        if (len < sizeof line - 1) line[len++] = c;
        else overflow = 1;
        continue;
      }
      line[len] = 0;
      if (overflow) emitError("control", 0, "line-too-long");
      else handleCommand(line);
      len = 0;
      overflow = 0;
    }
  }
  if (g_mode == M_WATCH) { /* owner went away: stop watching; never touch the target */
    emitf("{\"event\":\"watch-ended\",\"reason\":\"eof\"}");
    finish(0);
  }
  InterlockedCompareExchange(&g_killReason, 2, 0);
  SetEvent(g_killEvent);
  return 0;
}

static void procEvent(const char* name, DWORD pid, int abnormal) {
  LONG k = InterlockedIncrement(&g_procEvents);
  if (k <= JH_MAX_PROC_EVENTS) {
    if (abnormal < 0) emitf("{\"event\":\"%s\",\"pid\":%lu}", name, pid);
    else emitf("{\"event\":\"%s\",\"pid\":%lu,\"abnormal\":%s}", name, pid, abnormal ? "true" : "false");
  } else if (k == JH_MAX_PROC_EVENTS + 1) {
    emitf("{\"event\":\"proc-events-truncated\",\"limit\":%d}", JH_MAX_PROC_EVENTS);
  }
}

static DWORD WINAPI portThread(LPVOID unused) {
  (void)unused;
  DWORD msg;
  ULONG_PTR key;
  LPOVERLAPPED ov;
  while (GetQueuedCompletionStatus(g_port, &msg, &key, &ov, INFINITE)) {
    DWORD pid = (DWORD)(ULONG_PTR)ov;
    switch (msg) {
      case JOB_OBJECT_MSG_NEW_PROCESS: procEvent("proc-start", pid, -1); break;
      case JOB_OBJECT_MSG_EXIT_PROCESS: procEvent("proc-exit", pid, 0); break;
      case JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS: procEvent("proc-exit", pid, 1); break;
      case JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: SetEvent(g_zeroEvent); break;
      case JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: emitf("{\"event\":\"memory-limit\",\"pid\":%lu}", pid); break;
      default: break;
    }
  }
  return 0;
}

/* ---------- lifecycle loop shared by adopt and spawn ---------- */

static const char* killReasonName(void) {
  switch (g_killReason) {
    case 1: return "control";
    case 2: return "eof";
    default: return "root-exit-policy";
  }
}

static void terminateJob(const char* reason) {
  DWORD before = activeCount();
  BOOL ok = TerminateJobObject(g_job, JH_EXIT_KILLED);
  emitf("{\"event\":\"killed\",\"reason\":\"%s\",\"activeBefore\":%lu,\"ok\":%s,\"win32\":%lu}", reason, before,
        ok ? "true" : "false", ok ? 0UL : GetLastError());
}

static void emitRootExit(DWORD code, int byKill) {
  emitf("{\"event\":\"root-exit\",\"pid\":%lu,\"code\":%lu,\"codeHex\":\"0x%08lX\",\"activeAfterRoot\":%lu,"
        "\"byKill\":%s}",
        g_rootPid, code, code, activeCount(), byKill ? "true" : "false");
}

static __attribute__((noreturn)) void runLoop(void) {
  CreateThread(NULL, 0, portThread, NULL, 0, NULL);
  CreateThread(NULL, 0, controlThread, NULL, 0, NULL);
  DWORD code = STILL_ACTIVE;
  HANDLE w1[2] = {g_root, g_killEvent};
  DWORD which = WaitForMultipleObjects(2, w1, FALSE, INFINITE);
  if (which == WAIT_OBJECT_0) {
    GetExitCodeProcess(g_root, &code);
    emitRootExit(code, 0);
    if (activeCount() > 0) {
      if (g_killOnRootExit) {
        terminateJob("root-exit-policy");
      } else {
        /* Default policy: stragglers keep running until BEA kills the job (close_session) or they exit. */
        for (;;) {
          if (activeCount() == 0) break;
          HANDLE w2[2] = {g_zeroEvent, g_killEvent};
          DWORD r = WaitForMultipleObjects(2, w2, FALSE, 250);
          if (r == WAIT_OBJECT_0 + 1) { terminateJob(killReasonName()); break; }
        }
      }
    }
  } else {
    terminateJob(killReasonName());
    if (WaitForSingleObject(g_root, JH_SETTLE_MS) == WAIT_OBJECT_0) {
      GetExitCodeProcess(g_root, &code);
      emitRootExit(code, 1);
    }
  }
  /* Settle: ActiveProcesses is the source of truth; the port message is only a wake-up hint. */
  ULONGLONG s0 = GetTickCount64();
  while (activeCount() > 0 && GetTickCount64() - s0 < JH_SETTLE_MS) WaitForSingleObject(g_zeroEvent, 25);
  char peak[24];
  u64dec(peakJobMemory(), peak);
  DWORD left = activeCount();
  emitf("{\"event\":\"settled\",\"active\":%lu,\"timedOut\":%s,\"peakJobMemoryBytes\":%s,\"elapsedMs\":%lu}", left,
        left ? "true" : "false", peak, (unsigned long)(GetTickCount64() - g_t0));
  finish(code == STILL_ACTIVE ? JH_EXIT_KILLED : code);
}

/* ---------- argument parsing ---------- */

static int parseU64(const wchar_t* s, ULONGLONG* out) {
  if (!s || !*s) return 0;
  ULONGLONG v = 0;
  for (; *s; s++) {
    if (*s < L'0' || *s > L'9') return 0;
    ULONGLONG nv = v * 10 + (ULONGLONG)(*s - L'0');
    if (nv / 10 != v) return 0;
    v = nv;
  }
  *out = v;
  return 1;
}

static int isDriveAbsolute(const wchar_t* p) {
  return p && ((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) && p[1] == L':' &&
         (p[2] == L'\\' || p[2] == L'/');
}

/* ---------- identity check shared by adopt and watch ---------- */

static int checkIdentity(HANDLE h, ULONGLONG expected, ULONGLONG tol, const wchar_t* expectImage,
                         LONGLONG expectParent, ULONGLONG* actualOut, wchar_t* img, DWORD imgCap) {
  ULONGLONG actual = creationTime(h);
  *actualOut = actual;
  char a[24], e[24];
  u64dec(actual, a);
  u64dec(expected, e);
  ULONGLONG diff = actual > expected ? actual - expected : expected - actual;
  if (!actual || diff > tol) {
    emitf("{\"event\":\"error\",\"stage\":\"identity\",\"win32\":0,\"detail\":\"creation-time\",\"expected\":\"%s\","
          "\"actual\":\"%s\"}",
          e, a);
    return 0;
  }
  if (WaitForSingleObject(h, 0) == WAIT_OBJECT_0) { emitError("identity", 0, "already-exited"); return 0; }
  int haveImg = imagePath(h, img, imgCap);
  if (expectImage && (!haveImg || !sameImage(img, expectImage))) { emitError("identity", 0, "image-path"); return 0; }
  if (expectParent >= 0 && parentPid(h) != expectParent) { emitError("identity", 0, "parent-pid"); return 0; }
  if (!haveImg) img[0] = 0;
  return 1;
}

/* ---------- modes ---------- */

static __attribute__((noreturn)) void modeAdopt(int argc, wchar_t** argv) {
  ULONGLONG pid64 = 0, expected = 0, tol = 0;
  const wchar_t* expectImage = NULL;
  LONGLONG expectParent = -1;
  if (argc < 4 || !parseU64(argv[2], &pid64) || !parseU64(argv[3], &expected)) {
    emitError("usage", 0, "adopt <pid> <creationTime100ns>");
    finish(JH_EXIT_USAGE);
  }
  for (int i = 4; i < argc; i++) {
    ULONGLONG v;
    if (!wcscmp(argv[i], L"--tolerance-100ns") && i + 1 < argc && parseU64(argv[i + 1], &v)) { tol = v; i++; }
    else if (!wcscmp(argv[i], L"--expect-image") && i + 1 < argc) { expectImage = argv[++i]; }
    else if (!wcscmp(argv[i], L"--expect-parent") && i + 1 < argc && parseU64(argv[i + 1], &v)) { expectParent = (LONGLONG)v; i++; }
    else if (!wcscmp(argv[i], L"--mem-limit") && i + 1 < argc && parseU64(argv[i + 1], &v)) { g_memLimit = v; i++; }
    else if (!wcscmp(argv[i], L"--kill-on-root-exit")) g_killOnRootExit = 1;
    else { emitError("usage", 0, "unknown-option"); finish(JH_EXIT_USAGE); }
  }
  g_rootPid = (DWORD)pid64;
  g_root = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                       g_rootPid);
  if (!g_root) { emitError("open", GetLastError(), NULL); finish(JH_EXIT_OPEN); }
  static wchar_t img[4096];
  ULONGLONG actual = 0;
  if (!checkIdentity(g_root, expected, tol, expectImage, expectParent, &actual, img, 4096)) finish(JH_EXIT_IDENTITY);
  if (!makeJob()) finish(JH_EXIT_JOB);
  BOOL wasInJob = FALSE, inOurs = FALSE;
  IsProcessInJob(g_root, NULL, &wasInJob);
  if (!AssignProcessToJobObject(g_job, g_root)) {
    emitf("{\"event\":\"error\",\"stage\":\"assign\",\"win32\":%lu,\"detail\":\"\",\"wasInJob\":%s}", GetLastError(),
          wasInJob ? "true" : "false");
    finish(JH_EXIT_ASSIGN);
  }
  if (!IsProcessInJob(g_root, g_job, &inOurs) || !inOurs) { emitError("membership", GetLastError(), NULL); finish(JH_EXIT_MEMBERSHIP); }
  char ct[24], path[8192], pol[256];
  u64dec(actual, ct);
  jsonStrW(img[0] ? img : NULL, path, sizeof path);
  policyJson(pol, sizeof pol);
  emitf("{\"event\":\"adopted\",\"pid\":%lu,\"creationTime100ns\":\"%s\",\"wasInJob\":%s,\"imagePath\":%s,"
        "\"active\":%lu,\"policy\":%s}",
        g_rootPid, ct, wasInJob ? "true" : "false", path, activeCount(), pol);
  runLoop();
}

typedef struct {
  wchar_t* p;
  size_t n, cap;
  int overflow;
} WBuf;

static void wput(WBuf* b, wchar_t c) {
  if (b->n + 1 < b->cap) b->p[b->n++] = c;
  else b->overflow = 1;
  b->p[b->n] = 0;
}

/* MSVCRT/CommandLineToArgvW-compatible quoting (round-trip verified in the rea-process lab, case G5). */
static void appendArg(WBuf* b, const wchar_t* arg) {
  if (b->n) wput(b, L' ');
  if (*arg && !wcspbrk(arg, L" \t\n\v\"")) {
    for (const wchar_t* p = arg; *p; p++) wput(b, *p);
    return;
  }
  wput(b, L'"');
  for (const wchar_t* p = arg;; p++) {
    size_t bs = 0;
    while (*p == L'\\') { p++; bs++; }
    if (!*p) { for (size_t i = 0; i < bs * 2; i++) wput(b, L'\\'); break; }
    if (*p == L'"') { for (size_t i = 0; i < bs * 2 + 1; i++) wput(b, L'\\'); wput(b, L'"'); }
    else { for (size_t i = 0; i < bs; i++) wput(b, L'\\'); wput(b, *p); }
  }
  wput(b, L'"');
}

static HANDLE inheritable(HANDLE h, HANDLE fallbackNul) {
  if (h == NULL || h == INVALID_HANDLE_VALUE || GetFileType(h) == FILE_TYPE_UNKNOWN) return fallbackNul;
  SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  return h;
}

static __attribute__((noreturn)) void modeSpawn(int argc, wchar_t** argv) {
  int suspended = 0, stdinFd4 = 0, i = 2;
  ULONGLONG v;
  for (; i < argc; i++) {
    if (!wcscmp(argv[i], L"--suspended")) suspended = 1;
    else if (!wcscmp(argv[i], L"--stdin-fd4")) stdinFd4 = 1;
    else if (!wcscmp(argv[i], L"--kill-on-root-exit")) g_killOnRootExit = 1;
    else if (!wcscmp(argv[i], L"--mem-limit") && i + 1 < argc && parseU64(argv[i + 1], &v)) { g_memLimit = v; i++; }
    else break;
  }
  if (i < argc && !wcscmp(argv[i], L"--")) i++;
  if (i >= argc || !isDriveAbsolute(argv[i])) { emitError("usage", 0, "spawn [opts] -- <absolute-exe> [args]"); finish(JH_EXIT_USAGE); }
  if (!g_statusFd3) { emitError("status", 0, "spawn-requires-fd3"); finish(JH_EXIT_STATUS); }
  static wchar_t cmd[32768];
  WBuf b = {cmd, 0, 32768, 0};
  cmd[0] = 0;
  for (int k = i; k < argc; k++) appendArg(&b, argv[k]);
  if (b.overflow) { emitError("usage", 0, "command-line-too-long"); finish(JH_EXIT_USAGE); }
  if (!makeJob()) finish(JH_EXIT_JOB);

  SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
  HANDLE nul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
                           0, NULL);
  HANDLE hin = nul;
  if (stdinFd4) {
    intptr_t h4 = _get_osfhandle(4);
    if (h4 == -1 || h4 == -2) { emitError("usage", 0, "stdin-fd4-missing"); finish(JH_EXIT_USAGE); }
    hin = inheritable((HANDLE)h4, nul);
  }
  HANDLE hout = inheritable(GetStdHandle(STD_OUTPUT_HANDLE), nul);
  HANDLE herr = inheritable(GetStdHandle(STD_ERROR_HANDLE), nul);
  HANDLE list[3];
  int k = 0;
  list[k++] = hin;
  if (hout != hin) list[k++] = hout;
  if (herr != hin && herr != hout) list[k++] = herr;

  SIZE_T size = 0;
  InitializeProcThreadAttributeList(NULL, 2, 0, &size);
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
  if (!attrs || !InitializeProcThreadAttributeList(attrs, 2, 0, &size) ||
      !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &g_job, sizeof g_job, NULL, NULL) ||
      !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, (SIZE_T)k * sizeof(HANDLE), NULL,
                                 NULL)) {
    emitError("create", GetLastError(), "attributes");
    finish(JH_EXIT_CREATE);
  }
  STARTUPINFOEXW si;
  memset(&si, 0, sizeof si);
  si.StartupInfo.cb = sizeof si;
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES; /* no STARTF_USESHOWWINDOW: GUI targets show normally */
  si.StartupInfo.hStdInput = hin;
  si.StartupInfo.hStdOutput = hout;
  si.StartupInfo.hStdError = herr;
  si.lpAttributeList = attrs;
  PROCESS_INFORMATION pi;
  if (!CreateProcessW(argv[i], cmd, NULL, NULL, TRUE,
                      CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                      NULL, NULL, &si.StartupInfo, &pi)) {
    emitError("create", GetLastError(), NULL); /* 740 = ERROR_ELEVATION_REQUIRED */
    finish(JH_EXIT_CREATE);
  }
  BOOL inOurs = FALSE;
  if (!IsProcessInJob(pi.hProcess, g_job, &inOurs) || !inOurs) {
    TerminateProcess(pi.hProcess, JH_EXIT_MEMBERSHIP);
    emitError("membership", GetLastError(), NULL);
    finish(JH_EXIT_MEMBERSHIP);
  }
  g_root = pi.hProcess;
  g_rootPid = pi.dwProcessId;
  static wchar_t img[4096];
  if (!imagePath(g_root, img, 4096)) img[0] = 0;
  char ct[24], path[8192], pol[256];
  u64dec(creationTime(g_root), ct);
  jsonStrW(img[0] ? img : NULL, path, sizeof path);
  policyJson(pol, sizeof pol);
  if (suspended) g_rootThread = pi.hThread;
  else { ResumeThread(pi.hThread); CloseHandle(pi.hThread); }
  emitf("{\"event\":\"started\",\"pid\":%lu,\"tid\":%lu,\"creationTime100ns\":\"%s\",\"suspended\":%s,"
        "\"imagePath\":%s,\"policy\":%s}",
        g_rootPid, pi.dwThreadId, ct, suspended ? "true" : "false", path, pol);
  runLoop();
}

static __attribute__((noreturn)) void modeWatch(int argc, wchar_t** argv) {
  ULONGLONG pid64 = 0, expected = 0, tol = 0, v;
  if (argc < 4 || !parseU64(argv[2], &pid64) || !parseU64(argv[3], &expected)) {
    emitError("usage", 0, "watch <pid> <creationTime100ns>");
    finish(JH_EXIT_USAGE);
  }
  for (int i = 4; i < argc; i++) {
    if (!wcscmp(argv[i], L"--tolerance-100ns") && i + 1 < argc && parseU64(argv[i + 1], &v)) { tol = v; i++; }
    else { emitError("usage", 0, "unknown-option"); finish(JH_EXIT_USAGE); }
  }
  g_rootPid = (DWORD)pid64;
  /* No PROCESS_TERMINATE / SET_QUOTA: this mode cannot kill or contain by construction. */
  g_root = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_rootPid);
  if (!g_root) { emitError("open", GetLastError(), NULL); finish(JH_EXIT_OPEN); }
  static wchar_t img[4096];
  ULONGLONG actual = 0;
  if (!checkIdentity(g_root, expected, tol, NULL, -1, &actual, img, 4096)) finish(JH_EXIT_IDENTITY);
  char ct[24], path[8192];
  u64dec(actual, ct);
  jsonStrW(img[0] ? img : NULL, path, sizeof path);
  emitf("{\"event\":\"watching\",\"pid\":%lu,\"creationTime100ns\":\"%s\",\"imagePath\":%s}", g_rootPid, ct, path);
  CreateThread(NULL, 0, controlThread, NULL, 0, NULL);
  WaitForSingleObject(g_root, INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(g_root, &code);
  emitf("{\"event\":\"root-exit\",\"pid\":%lu,\"code\":%lu,\"codeHex\":\"0x%08lX\",\"activeAfterRoot\":null,"
        "\"byKill\":false}",
        g_rootPid, code, code);
  finish(0);
}

typedef BOOL(WINAPI* PIsWow64Process2)(HANDLE, USHORT*, USHORT*);
typedef BOOL(WINAPI* PIsProcessCritical)(HANDLE, PBOOL);
typedef BOOL(WINAPI* PGetProcessInformation)(HANDLE, PROCESS_INFORMATION_CLASS, LPVOID, DWORD);

static const char* tri(int known, int value) { return !known ? "null" : value ? "true" : "false"; }

static void numOrNull(int have, ULONGLONG v, char out[24]) {
  if (have) u64dec(v, out);
  else strcpy(out, "null");
}

static __attribute__((noreturn)) void modeInspect(int argc, wchar_t** argv) {
  ULONGLONG pid64 = 0;
  if (argc < 3 || !parseU64(argv[2], &pid64)) { emitError("usage", 0, "inspect <pid>"); finish(JH_EXIT_USAGE); }
  DWORD pid = (DWORD)pid64;
  const char* access = "limited+synchronize";
  HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h && GetLastError() == ERROR_ACCESS_DENIED) {
    access = "limited";
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  }
  if (!h) { emitError("open", GetLastError(), NULL); finish(JH_EXIT_OPEN); }
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  PIsWow64Process2 pWow = (PIsWow64Process2)(void*)GetProcAddress(k32, "IsWow64Process2");
  PIsProcessCritical pCrit = (PIsProcessCritical)(void*)GetProcAddress(k32, "IsProcessCritical");
  PGetProcessInformation pInfo = (PGetProcessInformation)(void*)GetProcAddress(k32, "GetProcessInformation");

  ULONGLONG ct = creationTime(h);
  char cts[24];
  u64dec(ct, cts);
  static wchar_t img[4096];
  int haveImg = imagePath(h, img, 4096);
  char path[8192];
  jsonStrW(haveImg ? img : NULL, path, sizeof path);
  int exitedKnown = strcmp(access, "limited") != 0;
  int exited = exitedKnown && WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
  DWORD exitCode = 0;
  int haveExit = exited && GetExitCodeProcess(h, &exitCode);
  LONGLONG ppid = parentPid(h);
  DWORD sess = 0;
  int haveSess = ProcessIdToSessionId(pid, &sess);
  BOOL crit = FALSE;
  int haveCrit = pCrit && pCrit(h, &crit);
  PROCESS_PROTECTION_LEVEL_INFORMATION pli;
  int haveProt = pInfo && pInfo(h, ProcessProtectionLevelInfo, &pli, sizeof pli);
  USHORT pm = 0, nm = 0;
  int haveWow = pWow && pWow(h, &pm, &nm);
  BOOL inJob = FALSE;
  int haveJob = IsProcessInJob(h, NULL, &inJob);
  int haveElev = 0, haveIl = 0, haveUser = 0, elevated = 0, sameUser = 0;
  DWORD ilRid = 0;
  HANDLE tok = NULL, self = NULL;
  if (OpenProcessToken(h, TOKEN_QUERY, &tok)) {
    TOKEN_ELEVATION te;
    DWORD len;
    if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &len)) { haveElev = 1; elevated = te.TokenIsElevated != 0; }
    BYTE ilb[256];
    if (GetTokenInformation(tok, TokenIntegrityLevel, ilb, sizeof ilb, &len)) {
      PSID sid = ((TOKEN_MANDATORY_LABEL*)ilb)->Label.Sid;
      ilRid = *GetSidSubAuthority(sid, (DWORD)(*GetSidSubAuthorityCount(sid) - 1));
      haveIl = 1;
    }
    BYTE ub[512], sb[512];
    if (GetTokenInformation(tok, TokenUser, ub, sizeof ub, &len) && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &self) &&
        GetTokenInformation(self, TokenUser, sb, sizeof sb, &len)) {
      haveUser = 1;
      sameUser = EqualSid(((TOKEN_USER*)ub)->User.Sid, ((TOKEN_USER*)sb)->User.Sid) != 0;
    }
  }
  char ppidS[24], protS[24], exitS[24], sessS[24], ilS[24], ctS[32], pmS[24], nmS[24];
  numOrNull(ppid >= 0, (ULONGLONG)ppid, ppidS);
  numOrNull(haveProt, haveProt ? pli.ProtectionLevel : 0, protS);
  numOrNull(haveExit, exitCode, exitS);
  numOrNull(haveSess, sess, sessS);
  numOrNull(haveIl, ilRid, ilS);
  numOrNull(haveWow, pm, pmS);
  numOrNull(haveWow, nm, nmS);
  if (ct) snprintf(ctS, sizeof ctS, "\"%s\"", cts); else strcpy(ctS, "null");
  int isProtected = haveProt && pli.ProtectionLevel != PROTECTION_LEVEL_NONE;
  emitf("{\"event\":\"inspect\",\"pid\":%lu,\"access\":\"%s\",\"exited\":%s,\"exitCode\":%s,"
        "\"creationTime100ns\":%s,\"imagePath\":%s,\"parentPid\":%s,\"sessionId\":%s,\"critical\":%s,"
        "\"protectionLevel\":%s,\"protected\":%s,\"wow64\":%s,\"processMachine\":%s,\"nativeMachine\":%s,"
        "\"inJob\":%s,\"elevated\":%s,\"integrityRid\":%s,\"sameUser\":%s}",
        pid, access, tri(exitedKnown, exited), exitS, ctS, path, ppidS, sessS, tri(haveCrit, crit), protS,
        tri(haveProt, isProtected), tri(haveWow, pm != IMAGE_FILE_MACHINE_UNKNOWN), pmS, nmS, tri(haveJob, inJob),
        tri(haveElev, elevated), ilS, tri(haveUser, sameUser));
  finish(0);
}

/* Probe: prove containment by doing it, not by OS-version inference. */
static int probeChild(HANDLE job, int useJobList, PROCESS_INFORMATION* pi) {
  wchar_t self[MAX_PATH];
  GetModuleFileNameW(NULL, self, MAX_PATH);
  static wchar_t cmd[1024];
  WBuf b = {cmd, 0, 1024, 0};
  cmd[0] = 0;
  appendArg(&b, self);
  appendArg(&b, L"probe-child");
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &size);
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
  InitializeProcThreadAttributeList(attrs, 1, 0, &size);
  if (useJobList) UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &job, sizeof job, NULL, NULL);
  STARTUPINFOEXW si;
  memset(&si, 0, sizeof si);
  si.StartupInfo.cb = sizeof si;
  si.lpAttributeList = attrs;
  return CreateProcessW(self, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        NULL, NULL, &si.StartupInfo, pi);
}

static __attribute__((noreturn)) void modeProbe(void) {
  int jobOk = makeJob();
  int jobListOk = 0, jobListExit = 0, adoptOk = 0, terminateOk = 0;
  PROCESS_INFORMATION a, c;
  if (jobOk && probeChild(g_job, 1, &a)) {
    BOOL in = FALSE;
    jobListOk = IsProcessInJob(a.hProcess, g_job, &in) && in;
    ResumeThread(a.hThread);
    DWORD code = 0;
    if (WaitForSingleObject(a.hProcess, 5000) == WAIT_OBJECT_0 && GetExitCodeProcess(a.hProcess, &code))
      jobListExit = code == JH_PROBE_CHILD_CODE;
    else TerminateProcess(a.hProcess, JH_EXIT_PROBE);
  }
  if (jobOk && probeChild(NULL, 0, &c)) { /* the adopt path: assign a suspended process created outside the job */
    BOOL in = FALSE;
    adoptOk = AssignProcessToJobObject(g_job, c.hProcess) && IsProcessInJob(c.hProcess, g_job, &in) && in;
    if (adoptOk && TerminateJobObject(g_job, JH_EXIT_KILLED)) {
      DWORD code = 0;
      terminateOk = WaitForSingleObject(c.hProcess, 5000) == WAIT_OBJECT_0 && GetExitCodeProcess(c.hProcess, &code) &&
                    code == JH_EXIT_KILLED;
    }
    if (!terminateOk) TerminateProcess(c.hProcess, JH_EXIT_PROBE);
  }
  BOOL helperInJob = FALSE;
  IsProcessInJob(GetCurrentProcess(), NULL, &helperInJob);
  int ok = jobOk && jobListOk && jobListExit && adoptOk && terminateOk;
  emitf("{\"event\":\"probe\",\"ok\":%s,\"jobPolicyVerified\":%s,\"jobListAttribute\":%s,\"assignedBeforeFirstInstruction\":%s,"
        "\"adoptAssign\":%s,\"terminateJob\":%s,\"helperInJob\":%s,\"statusFd3\":%s}",
        ok ? "true" : "false", jobOk ? "true" : "false", jobListOk ? "true" : "false", jobListExit ? "true" : "false",
        adoptOk ? "true" : "false", terminateOk ? "true" : "false", helperInJob ? "true" : "false",
        g_statusFd3 ? "true" : "false");
  finish(ok ? 0 : JH_EXIT_PROBE);
}

int wmain(int argc, wchar_t** argv) {
  InitializeCriticalSection(&g_emitLock);
  g_t0 = GetTickCount64();
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  SetConsoleCtrlHandler(NULL, TRUE); /* lifetime is governed by stdin/kill/parent death, not console Ctrl-C */
  if (argc >= 2 && !wcscmp(argv[1], L"probe-child")) finish(JH_PROBE_CHILD_CODE);

  intptr_t fd3 = _get_osfhandle(3);
  if (fd3 != -1 && fd3 != -2 && GetFileType((HANDLE)fd3) == FILE_TYPE_PIPE) {
    g_status = (HANDLE)fd3;
    g_statusFd3 = 1;
  } else {
    g_status = GetStdHandle(STD_OUTPUT_HANDLE);
  }
  g_killEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  g_zeroEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

  const wchar_t* m = argc >= 2 ? argv[1] : L"";
  g_mode = !wcscmp(m, L"adopt") ? M_ADOPT : !wcscmp(m, L"spawn") ? M_SPAWN : !wcscmp(m, L"watch") ? M_WATCH
         : !wcscmp(m, L"inspect") ? M_INSPECT : !wcscmp(m, L"probe") ? M_PROBE : !wcscmp(m, L"version") ? M_VERSION
         : M_NONE;
  static const char* names[] = {"none", "adopt", "spawn", "watch", "inspect", "probe", "version", "probe-child"};
  BOOL helperInJob = FALSE;
  IsProcessInJob(GetCurrentProcess(), NULL, &helperInJob);
  emitf("{\"event\":\"hello\",\"protocol\":%d,\"version\":\"%s\",\"mode\":\"%s\",\"helperPid\":%lu,"
        "\"helperInJob\":%s,\"statusFd3\":%s}",
        JH_PROTOCOL, JH_VERSION, names[g_mode], GetCurrentProcessId(), helperInJob ? "true" : "false",
        g_statusFd3 ? "true" : "false");
  switch (g_mode) {
    case M_ADOPT: modeAdopt(argc, argv);
    case M_SPAWN: modeSpawn(argc, argv);
    case M_WATCH: modeWatch(argc, argv);
    case M_INSPECT: modeInspect(argc, argv);
    case M_PROBE: modeProbe();
    case M_VERSION: finish(0);
    default: emitError("usage", 0, "mode: adopt|spawn|watch|inspect|probe|version"); finish(JH_EXIT_USAGE);
  }
}
```
