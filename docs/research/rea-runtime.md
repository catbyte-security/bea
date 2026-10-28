# REA runtime/dynamic subsystems: study notes for BEA

Key: `rea-runtime`. Sources: local REA clone `<rea-checkout>` (read-only), plus a Windows lab run of
Frida 17.23.2 in `scratchpad/bea-lab/rea-runtime/`.

Legend: **VERIFIED-src** = I read the code at the cited path:line. **VERIFIED-run** = I ran it on this host
(Windows 11 x64, Node 24.18.0, frida 17.23.2 from REA's `node_modules`, imported read-only). **BELIEVED** = docs or
memory, not checked here.

---

## 0. TL;DR

- REA's dynamic side is thin and mostly **raw passthrough**. Frida = generic caller-authored JS sessions (8 MCP tools +
  one CLI one-shot). GDB = unrestricted MI console (`-interpreter-exec console`), **Linux only**. Rizin debugger =
  unrestricted NUL-framed console, **Linux only**. LLDB = one **structured** tracer (`observe_native_calls`),
  **macOS Mach-O only**, entry-only breakpoints with raw argument registers. pwndbg/pwntools = **core-file only**
  (no live process). Process capture = PTY, Linux/macOS only. JS runtime = passive CDP (2 commands).
- On **Windows**, the only live dynamic primitive REA has is the Frida session tools. GDB/Rizin refuse to start
  (`GdbSessionManager.ts:618-628`, `RizinDebugSessionManager.ts:346-353`), LLDB tracing is macOS-only, process capture
  refuses Windows (`docs/process-capture.md:15-31`).
- REA's Frida manager (`src/frida/FridaInstrumentationManager.ts`, 1599 lines) is a high-quality **lifecycle/ownership
  template**: lazy binding load, per-session promise-chain lock, admission gate + drain on shutdown, startup-failure
  cleanup records, remote-device refcounting, script state machine (`active`→`cleanup-pending`→`released`), bounded
  message capture with FIFO eviction and named truncation causes, secret redaction, typed cancellation with partial
  Evidence. **BEA should copy this structure almost verbatim**, then add what it lacks.
- What REA's Frida layer lacks (BEA must add): RPC (`script.exports`), host→agent `post`, `device.kill` (REA never
  kills targets, by design), stdio capture (`stdio:"pipe"` + `device.output`), a `logHandler` (agent `console.log`
  goes to host **stdout**, VERIFIED-run: a stdio-MCP hazard), crash capture (Windows `session.detached` gives
  `crash=null`, VERIFIED-run), `SessionOptions` (exceptor etc.), child gating, any structured primitive (hooks,
  memory read/scan, Stalker, watchpoints, function calls, dumps, module maps, ASLR rebasing). Its verifier lane
  `npm run verify:frida` is documented as **Linux-only** (`docs/frida-instrumentation.md:29`): no Windows Frida
  verification exists in REA.
- Lab findings that directly shape BEA (all VERIFIED-run on Windows): spawn/attach/createScript/load/resume/RPC/
  unload/detach/kill all work; `Interceptor.attach` **fails on a 4-byte function** ("unable to intercept function …
  please file a bug"); `script.load()` **resolves even when the agent throws** at top level (error arrives as a
  `type:"error"` message); hardware **watchpoints work** (`Thread.setHardwareWatchpoint`, delivered as
  `single-step` exceptions with PC = instruction **after** the writer); exception-handler `send()` is **lost** on a
  fatal crash unless the handler blocks on `recv('ack').wait()`; `DebugSymbol` names are **garbage** for MinGW/DWARF
  binaries (no PDB); Node does **not exit** while device signal handlers stay connected, even after
  `manager.close()`; `device.kill()` returns before the process is gone (`findProcessByPid` still non-null right
  after).

---

## 1. Inventory (VERIFIED-src; non-test line counts)

| Area | Files | Lines |
|---|---|---|
| Frida provider | `src/frida/FridaInstrumentationManager.ts` | 1599 |
| | `src/frida/fridaCaptureLimits.ts` | 97 |
| | `src/frida/frida-bindings.d.ts` (type shim) | 81 |
| Frida app layer | `src/application/frida/FridaInstrumentationPort.ts` | ~147 |
| | `src/application/frida/FridaInstrumentationService.ts` | 660 |
| | `src/application/frida/fridaInputErrors.ts` | ~27 |
| Frida adapters | `src/server/registerFridaTools.ts` (MCP) | 350 |
| | `src/cli/fridaCommands.ts` (CLI) | 300 |
| Frida contracts | `src/contracts/fridaToolContracts.ts` | 313 |
| | `src/contracts/fridaRemoteAddress.ts` | ~20 |
| | `src/domain/fridaSessionStatus.ts` | ~28 |
| Frida verify | `scripts/verify-frida.mjs`, `scripts/verify/fridaBindingsCompatibility.ts`, `tsconfig.frida-verification.json` | 214 + 28 |
| GDB | `src/gdb/GdbSessionManager.ts`, `src/gdb/GdbCommandRecords.ts`, `src/contracts/gdbToolContracts.ts` | 2336 + small + 107 |
| Rizin debug | `src/rizin/RizinDebugSessionManager.ts`, `src/rizin/RizinCommand.ts`, `src/contracts/rizinDebugToolContracts.ts` | 1678 + 19 + 108 |
| LLDB tracer | `bridge/native/rea_lldb_tracer.py`, `src/native/LldbCallTracer.ts`, `src/native/NativeCallObservation.ts`, `src/native/LldbRetainedObservations.ts`, `src/native/LldbReadbackFiles.ts`, `src/domain/native/nativeCallObservation.ts` | 917 + 1310 + 280 + 280 + 118 + ~170 |
| pwndbg (core only) | `bridge/pwndbg/{launch.py,launch_impl.py,core_context.py}`, `src/native/pwndbg/PwndbgCoreContext.ts` | small + 286 |
| Process ownership | `src/process/ProviderProcess.ts`, `src/process/ownedDebuggerSession.ts`, `src/process/ProcessOwnership*.ts`, `src/windows/WindowsOwnedProcess.ts`, `native/windows/src/*.cc` (Job Object addon) | 953 + 314 + ~3.5k + 431 |

Frida wiring: `src/server/createServer.ts:404-405` (`options.fridaInstrumentation ?? new FridaInstrumentationManager()`),
`:425-476` (shared `closeProviders()` includes `fridaInstrumentation.closeAll()`, `gdbSessions.closeAll()`,
`rizinDebugSessions.closeAll()`), `:565` (`registerFridaTools`), `:257-266` (Frida load failure → availability policy).
Capability inventory: `src/application/CapabilityInventory.ts:201-202, 394, 691` (Frida tools need no open target;
availability only reflects a recorded load failure).

---

## 2. Frida: architecture and layering (VERIFIED-src)

```
contracts (zod, MCP schemas)  src/contracts/fridaToolContracts.ts
     │
adapters  MCP: src/server/registerFridaTools.ts   CLI: src/cli/fridaCommands.ts
     │
application service (shared CLI/MCP workflows, Evidence)  src/application/frida/FridaInstrumentationService.ts
     │  depends on
port (interface, no frida types)  src/application/frida/FridaInstrumentationPort.ts
     │  implemented by
provider (frida types, native handles)  src/frida/FridaInstrumentationManager.ts
```

- Port (`FridaInstrumentationPort.ts:103-147`):
  `availabilityFailure?()`, `listDevices(remote?)`, `listProcesses(selector)`, `startSession(input)`,
  `loadScript(sessionId, source, signal?)`, `resumeSession(sessionId, signal?)`,
  `unloadScript(sessionId, scriptId, signal?)`, `status(sessionId)` (sync), `closeSession(sessionId)`, `closeAll()`.
  All async methods return `Result<T, AnalysisError>` (tagged error algebra, `src/domain/result.ts`), never throw for
  expected failures.
- Input union (`:35-43`): `StartFridaSessionInput = FridaDeviceSelector & ({mode:"attach", pid} | {mode:"spawn",
  program, argv?})`. Script source union (`:45-47`): `{sourceKind:"inline", source} | {sourceKind:"file", path}`.
- Observations (`:49-96`): `FridaSessionObservation {sessionId, deviceId, target, pid, mode, state: "paused"|"running"|"detached"}`;
  `FridaScriptObservation {scriptId, sourceKind, sourcePath, sourceSha256, sourceRepresentation?, messages, messagesTruncated}`;
  `FridaSessionStatus` adds `targetResumeObserved`, `scripts[]`, `messages[]`, `messagesTruncated`.
- `FridaScriptLoadCancelledError extends AnalysisCancelledError` (`:73-85`) carries the partial script observation and
  `scriptHandleAcquired`.

The MCP server keeps **one shared manager for the whole server lifetime**; the CLI constructs a **disposable** manager
per command and awaits `closeAll()` after each one (`src/cli/fridaCommands.ts:34-62`, `withProviderCleanup`).

---

## 3. Lazy loading of the optional `frida` binding (VERIFIED-src)

1. `package.json`: `"optionalDependencies": { "frida": "17.23.2" }` and `"allowScripts": { "frida@17.23.2": true }`
   (frida's install script fetches the prebuilt native addon). If install fails, REA still installs.
2. Only **type** imports at module top (`FridaInstrumentationManager.ts:5-12`: `import type { Device, DeviceManager,
   FridaMessage, RemoteDeviceOptions, Script, Session } from "frida"`), so loading REA never loads the addon.
3. Constructor stores a loader; nothing is imported until first use (`:144-149`):

```ts
constructor(options: FridaInstrumentationManagerOptions = {}) {
  this.#deviceManager = options.deviceManager;          // test seam: inject fake
  this.#deviceManagerLoader =
    options.deviceManagerLoader ??
    (async () => (await import("frida")).getDeviceManager());
}
```

4. Single-flight load with failure memo (`:1113-1134`):

```ts
async #getDeviceManager(): Promise<DeviceManager> {
  if (this.#deviceManager !== undefined) return this.#deviceManager;
  if (this.#deviceManagerLoading !== undefined) return this.#deviceManagerLoading;
  const loading = Promise.resolve().then(this.#deviceManagerLoader);
  this.#deviceManagerLoading = loading;
  try {
    this.#deviceManager = await loading;
    if (this.#availabilityFailure?.providerId === "frida") this.#availabilityFailure = undefined;
    return this.#deviceManager;
  } catch (cause) {
    this.#availabilityFailure = { providerId: "frida",
      reason: boundedRedactedString(errorMessage(cause), 4096, []).value };
    throw cause;            // retried on the next call (not cached as permanent)
  } finally {
    if (this.#deviceManagerLoading === loading) this.#deviceManagerLoading = undefined;
  }
}
```

5. `availabilityFailure()` (`:151-153`) is polled by the server's availability policy
   (`createServer.ts:257-266`) so capability discovery reports "Adapter could not load: <reason>"
   (`OptionalObservationProviders.ts:38-46`) only **after** a failed load. Before first use, Frida tools are advertised
   as available (no eager probe).
6. Bundler keeps it external: `scripts/bundle-runtime.mjs:7-8,41` ("Keep dependencies external, dynamic imports
   lazy"); `dist/frida/FridaInstrumentationManager.js:43` still contains `await import("frida")`.
7. **Type shim instead of vendor types**: `src/frida/frida-bindings.d.ts` re-declares a minimal `declare module "frida"`
   (`FridaMessage`, `Signal<H>{connect,disconnect}`, `RemoteDeviceOptions`, `SpawnOptions`, `Process`, `Script
   {isDestroyed, message, load, unload}`, `Session {pid, detached, isDetached, createScript, detach}`, `Device {id,
   name, type, enumerateProcesses, getProcessByPid, spawn, resume, attach}`, `DeviceManager {enumerateDevices,
   getDeviceById(id, timeout), addRemoteDevice, removeRemoteDevice}`, `getDeviceManager()`).
   A separate compile-only check asserts the vendor classes are assignable to the shim
   (`scripts/verify/fridaBindingsCompatibility.ts:1-28`, run by `npm run verify:frida:bindings` with
   `tsconfig.frida-verification.json`). This keeps typecheck working when the optional package is absent and fails
   loudly if a frida upgrade narrows the API.

**BEA note:** the shim deliberately omits `Device.kill`, `Device.output`, `Device.processCrashed`, `Script.exports`,
`Script.post`, `Script.logHandler`, `Script.destroyed`, `Session.enableChildGating`, `SessionOptions`, the `Compiler`.
BEA needs most of these; either widen the shim (and the compat assertion) or depend on the vendor `.d.ts` directly
(it ships `build/src/frida.d.ts` + `frida_binding.d.ts`, 2753 lines) while keeping the runtime import lazy.

---

## 4. Frida: device / session / script lifecycle (VERIFIED-src)

### 4.1 Managed state (`FridaInstrumentationManager.ts:73-142`)

```ts
interface ManagedScript { id; name; script: Script; onMessage; state: "active" | "cleanup-pending" | "released"; }
interface ManagedRemoteConnection { deviceManager; remote?; remoteReferenceHeld: boolean; remoteRemovalPending: boolean; }
interface PendingStartupCleanup extends ManagedRemoteConnection { id; device; spawnedPid?: number; session?: Session; }
interface ManagedSession extends ManagedRemoteConnection {
  id; device; session; target; pid; mode: "attach" | "spawn";
  scripts: Map<string, ManagedScript>;
  messages: MessageFifo<CapturedMessage>;            // session-wide arrival order
  scriptCaptures: Map<string, ScriptMessageCapture>; // per-script view (for load replies)
  detached: boolean; targetResumeObserved: boolean; resumeAfterDetachPending: boolean;
  capturedBytes: number; messagesTruncated: boolean;
}
// manager-level
#sessions: Map<string, ManagedSession>; #pendingStartups: Set<PendingStartupCleanup>;
#sessionQueues: Map<string, Promise<void>>;      // per-session mutex (promise chain)
#sessionClosures: Map<string, Promise<Result>>;  // dedupe concurrent closes
#remoteDevices: Map<address, {references, optionsDigest, device: Promise<Device>}>;
#remoteQueues: Map<address, Promise<void>>;      // per-remote mutex
#operations: Set<Promise>;  #closing; #closeAllPromise;
```

Doc comment on the class (`:122`): "Owns Frida sessions and their scripts **without owning target process lifetime**."

### 4.2 Admission gate and per-session lock

`#withOperation(name, op, signal?)` (`:888-926`): refuses with `AnalysisCapabilityUnavailableError("frida", name,
"Frida instrumentation is shutting down.")` once `#closing`; otherwise registers the pending promise in `#operations`
(so `closeAll` can `Promise.allSettled` them) and re-checks `signal.aborted` right before dispatch.

`#withSessionLock(sessionId, op)` (`:928-947`) is a classic promise-chain mutex:

```ts
const previous = this.#sessionQueues.get(sessionId) ?? Promise.resolve();
let release; const current = new Promise<void>(r => { release = r; });
const tail = previous.then(() => current);
this.#sessionQueues.set(sessionId, tail);
await previous;
try { return await operation(); }
finally { release?.(); if (this.#sessionQueues.get(sessionId) === tail) this.#sessionQueues.delete(sessionId); }
```

`loadScript`, `resumeSession`, `unloadScript`, `closeSession`, and startup cleanup all serialize through it. Same
pattern for remote endpoints (`#withRemoteLock`, `:1228-1247`).

### 4.3 Device selection (`:1136-1164`, constants `:54-65`)

```ts
const DEVICE_LOOKUP_TIMEOUT_MS = 1_000;
const FRIDA_DEVICE_LOOKUP_TIMEOUT_MESSAGE = "Device not found"; // frida 17.23.2 message after timeout
...
return await manager.getDeviceById(selector.deviceId ?? "local", DEVICE_LOOKUP_TIMEOUT_MS);
// "Device not found" → AnalysisTimeoutError("frida_device_lookup", 1000, {userMessage, remediationAction})
```

Remote: `#retainRemote` (`:1166-1203`) calls `manager.addRemoteDevice(address, {token, certificate, origin,
keepaliveInterval})` once per address, refcounts it, and rejects a second retain with **different** options (sha256
digest of options) as `AnalysisInputError`. `#releaseRemote` (`:1205-1226`) calls `removeRemoteDevice` when the count
hits 0. Address validation: `isValidFridaRemoteAddress` (`src/contracts/fridaRemoteAddress.ts`) — `host[:port]`, no
credentials/path/query/fragment, parsed via `new URL("tcp://"+address)`.

### 4.4 Start (spawn or attach) — `#startSession` (`:282-377`)

```ts
manager = await this.#getDeviceManager();
device  = await this.#selectDevice(manager, input);
remoteHeld = input.remote !== undefined;
if (input.mode === "attach") {
  pid = input.pid; target = `pid ${pid}`;
  try { const p = await device.getProcessByPid(pid); target = `${p.name} (pid ${pid})`; }
  catch { /* Frida can attach to processes absent from its enumeration snapshot. */ }
} else {
  pid = await device.spawn(input.program,
        input.argv === undefined ? undefined : { argv: [input.program, ...input.argv] });  // argv[0] = program
  spawnedPid = pid; target = input.program;
}
session = await device.attach(pid);
const managed: ManagedSession = { id: randomUUID(), ..., detached: false, targetResumeObserved: false, ... };
session.detached.connect(() => { managed.detached = true; });
// Subscribe first, then reconcile: a detach emitted before the listener existed is not lost.
if (session.isDetached()) managed.detached = true;
this.#sessions.set(id, managed);
```

Notes:
- No `stdio` option → frida default `inherit`; no `env`/`cwd`; no `SessionOptions` (`realm`, `exceptor`,
  `persistTimeout`, …); no `enableChildGating`.
- The `detached` handler ignores `(reason, crash)` args — REA never records **why** a session detached.
- On any failure after a resource is acquired, it builds a `PendingStartupCleanup` (`:346-376`), adds it to
  `#pendingStartups` and runs `#cleanupStartup` (`:834-862`): detach session if any → **resume** the spawned pid (so a
  paused orphan is not left suspended) → release remote. If a step fails, the record stays in `#pendingStartups` and
  is retried by `closeAll()`. The original error stays primary; cleanup failure goes in `cleanup.reason`.

### 4.5 Load script — `#loadScript` (`:394-533`)

1. Abort check; session must exist and not be detached (`unknownFridaSession`, `fridaInputErrors.ts`).
2. Read source: inline string or `readFile(path)`; `sourceSha256 = sha256(selected bytes)`; invalid UTF-8 files are
   decoded with replacement and a second `loadedSourceSha256` is recorded (`:405-425`). EACCES/EPERM →
   `AnalysisAccessDeniedError`.
3. Allocate `scriptId = randomUUID()` and its per-script capture **before** creating the script, so messages emitted
   during `load()` are captured (`:450-458`).
4. Native calls (`:461-477`):

```ts
const nativeScript = await managed.session.createScript(scriptSource, { name: `rea-${scriptId}` });
entry = { id: scriptId, name: `rea-${scriptId}`, script: nativeScript, onMessage, state: "active" };
managed.scripts.set(scriptId, entry);
nativeScript.message.connect(onMessage);
if (!signal?.aborted) await nativeScript.load();
```

5. Outcome settling (`:478-532`): a native failure observed first stays primary even if abort arrives later; on
   failure or abort the new script is released (`#releaseScript`) while **keeping capture through cleanup**; abort
   returns `FridaScriptLoadCancelledError(observation, {scriptHandleAcquired, diagnostics.native_failure, cleanup})`.
6. Success returns `{scriptId, sourceKind, sourcePath, sourceSha256, messages: capture.messages.toArray(),
   messagesTruncated}` — i.e. the messages emitted **during load** are returned inline.

**Caveat VERIFIED-run (Windows):** `script.load()` resolves successfully even when the agent's top-level code throws;
the exception arrives as a message `{"type":"error","description":"Error: …","stack":…,"fileName":…,"lineNumber":…}`.
REA captures that message but still reports the load as `ok`. BEA should treat any `type:"error"` message emitted
during load as a failed/partial load (or have the agent post an explicit "ready" handshake).

### 4.6 Resume (`:553-595`)

Only `mode==="spawn" && !targetResumeObserved`; refuses if any script is `cleanup-pending` (a paused target must not
run with half-removed instrumentation). `await managed.device.resume(managed.pid); targetResumeObserved = true`.

### 4.7 Unload / release script (`:616-664`)

```ts
async #releaseScript(managed, entry, parentSessionReleased = false) {
  if (parentSessionReleased || entry.script.isDestroyed) entry.state = "released";
  if (entry.state !== "released") {
    entry.state = "cleanup-pending";
    try { await entry.script.unload(); entry.state = "released"; }
    catch (cause) { if (entry.script.isDestroyed) entry.state = "released"; else return sanitizeError(cause, managed.remote); }
  }
  try { entry.script.message.disconnect(entry.onMessage); } catch (cause) { return sanitizeError(cause, managed.remote); }
  managed.scripts.delete(entry.id); managed.scriptCaptures.delete(entry.id);
  return undefined;   // undefined = released; string = retained with reason
}
```

Ownership rule: a failed unload keeps the script **owned** (still in the map) for retry.

### 4.8 Status (`:666-681`)

Synchronous, reads in-memory state: observation + `targetResumeObserved` + script list + **all retained session
messages** + `messagesTruncated`. Messages are **not drained** on read (status is idempotent; `detail:"summary"`
returns counts and retains the full Evidence for later paging via `inspect_analysis_view`).

### 4.9 Close (`:683-785`)

- Concurrent closes are deduplicated through `#sessionClosures` (`:683-700`).
- Order inside the session lock:
  1. `managed.detached ||= session.isDetached()`;
  2. decide `shouldResumePausedSpawn = spawn && ((!released && !targetResumeObserved) || resumeAfterDetachPending)`;
  3. release every script (unload + disconnect);
  4. `await session.detach()` if not detached;
  5. if parent released, re-release remaining scripts with `parentSessionReleased=true` (their handles died with the
     session);
  6. **resume** the paused spawned target only if all scripts are released (never leave it suspended, never resume
     with live instrumentation pending); failure sets `resumeAfterDetachPending` for retry;
  7. release remote reference when everything else is released;
  8. any failure → `AnalysisCapabilityUnavailableError("frida","close_frida_session", first, {cleanup:{reason:
     all.join("; "), resources:[sessionId]}})` and the session **stays registered** for retry; success deletes it.
- The MCP reply is `{ target_state: "unknown" }` — REA never kills and never claims liveness.

### 4.10 closeAll (`:787-832`)

```ts
closeAll() { this.#closing = true; this.#closeAllPromise ??= this.#closeAll().catch(c => { this.#closeAllPromise = undefined; throw c; }); return this.#closeAllPromise; }
async #closeAll() {
  await Promise.allSettled(this.#operations);                       // drain admitted work
  const startupFailures = (await Promise.all([...this.#pendingStartups].map(p => this.#cleanupStartup(p)))).flat();
  const results = await Promise.all([...this.#sessions.keys()].map(id => this.closeSession(id)));
  // release unreferenced remotes, then throw AggregateError(failures, "Frida session cleanup was incomplete")
}
```

Retryable: a failed `closeAll` resets the memo so calling again retries the retained owners. Note: REA never calls
`DeviceManager.close()` (not in its shim). See §8 for why BEA should.

---

## 5. Frida message capture bounds and truncation reporting (VERIFIED-src)

### 5.1 Fixed caps (`src/frida/fridaCaptureLimits.ts:1-11`)

| Constant | Value | Applies to |
|---|---|---|
| `MAX_SESSION_CAPTURE_BYTES` | 16 MiB | total serialized retained messages per session (FIFO eviction) |
| `MAX_MESSAGE_METADATA_BYTES` | 128 KiB | reserve subtracted from the payload budget |
| `MAX_MESSAGE_TYPE_BYTES` | 4 KiB | `message.type` |
| `MAX_MESSAGE_TEXT_BYTES` | 32 KiB | `description`, `stack`, `fileName` each |
| `MAX_CAPTURE_JSON_NODES` | 250,000 | nodes visited in one payload |
| `MAX_JSON_DEPTH` | 64 | nesting depth |
| `MAX_BINARY_MESSAGE_BYTES` | floor((16 MiB − 1 MiB)·3/4) ≈ 11.25 MiB | `data` Buffer (base64 inflates 4/3) |

"This release has no runtime override" is stated in every limitation string.

### 5.2 Per-message processing `#recordMessage` (`FridaInstrumentationManager.ts:949-1111`)

1. `secrets = [remote.token, remote.certificate]` (non-empty) — redacted everywhere as `"[redacted]"`.
2. Payload → `boundedJsonValue(payload, 16 MiB − 128 KiB, secrets)` (`:1317-1438`): walks the value with a node
   counter, depth limit, cycle detection (`WeakSet`), byte budgets per array item / object entry; non-finite numbers
   and non-JSON types → `unrepresentable`; on overflow keeps the **prefix** and sets `truncated` + a named `limit`.
   Exceptions → `{payload_unavailable:true}` with `limit:"unrepresentable"`.
3. Binary `data`: if it contains a secret → `{data_redacted:true}`; if larger than the remaining per-message budget →
   `{data_truncated:true, data_bytes:N, data_capture_limit:"session_bytes"|"binary_bytes"}` (dropped entirely, not
   prefixed); else `{data_base64}`.
4. Strings `type/description/stack/fileName` → `boundedRedactedString` (UTF-8/JSON-escape aware, code-point safe)
   with `*_truncated: true` flags; `lineNumber/columnNumber` only if safe non-negative integers.
5. Observation shape (snake_case): `{script_id, type, payload?, payload_truncated?, payload_capture_limit?,
   description?, stack?, file_name?, line_number?, column_number?, data_base64? | data_truncated…}`.
6. Charge = `Buffer.byteLength(JSON.stringify(observation))`. If a single message exceeds 16 MiB → dropped, mark
   truncated. Otherwise **evict oldest** messages until it fits; evicting also shifts the per-script FIFO if the
   evicted item is its head (both are arrival-ordered, `:1098-1104`) and marks the evicted script truncated.
7. `MessageFifo<T>` (`:1567-1599`): head-offset queue, compacts when half evicted → amortized O(1) eviction.

### 5.3 Reporting

- `messages_truncated` flag at session and script level (`markMessageTruncated`, `:1553-1560`).
- `fridaCaptureLimitations(result)` (`fridaCaptureLimits.ts:58-97`) walks the **REA-owned** fields only (skips
  `payload`, because caller payload could contain look-alike flags) and maps each observed cap to a human limitation
  string; these go into `Evidence.limitations` (`FridaInstrumentationService.ts:478-486`).
- Principle (worth copying): name a cap **only when that observation actually dropped data**.

**Gap:** console output (`type:"log"`) never reaches this capture. frida-node intercepts `log` messages before user
handlers and routes them to `script.logHandler` (`node_modules/frida/build/src/frida.js:47-59, 203-217, 679`); the
default handler calls host `console.log/warn/error`. REA sets no `logHandler` (grep: no `logHandler` in `src/`). See §8.

---

## 6. Frida cancellation and cleanup semantics (VERIFIED-src + `docs/frida-instrumentation.md:11`)

- MCP passes `context.mcpReq.signal` (`registerFridaTools.ts:82,92,128,164,183,254,265`) to start/load/resume/unload
  /instrument. `listDevices`, `listProcesses`, `status`, `close` take no signal.
- Cutoff rule: "REA waits for that [native] call to return, then closes any session it created and returns the
  observed session as a partial observation." Frida native calls are not given a `Cancellable` (frida-node supports
  `cancellable?: Cancellable` on every async method; REA does not use it).
- Service-level `startSession` (`FridaInstrumentationService.ts:157-172`): if aborted after provider start succeeded →
  `#cancelSession` (`:174-207`) snapshots status, closes, and returns `AnalysisCancelledError` with
  `partialObservation` = Evidence containing `target_state_before_cleanup`, `target_resume_observed`,
  `instrumentation_cleanup: "released" | "incomplete_or_unknown"`, `target_liveness_after_cleanup: "unknown"`
  (`cancelledFridaSession`, `:490-532`).
- Script-load cancellation releases **only the new script**; the session and older scripts remain.
- After a provider **commits** a successful load, later cancellation does **not** unload it.
- Queued operations re-check the signal at dispatch time (`#withOperation`, and the lock bodies in `resumeSession`
  /`unloadScript`).
- Errors keep the **caller's abort reason** as `cause`; a native rejection observed during cancellation is retained as
  `diagnostics.native_failure`.
- MCP adapter `deliverPartialEvidenceError` (`registerFridaTools.ts:294-309`) records the partial Evidence in the
  session store and returns an error result that references its `evidence_id`.

### 6.1 One-shot workflow `instrument()` (`FridaInstrumentationService.ts:290-438`)

`rejectBeforeStart` (unreadable script file → fail before any attach/spawn effect) → start → load → (spawn: resume) →
`delay(durationMs, {signal})` (0..60,000 ms, default 1000) → status snapshot → close → Evidence with session status +
source identity + `cleanup_error`. Every await is followed by an abort check routing to `#cancelSession`. This is the
CLI `instrument-with-frida` and MCP `instrument_with_frida`.

### 6.2 Evidence envelope (`FridaInstrumentationService.ts:449-488`, `src/domain/evidence.ts:117-160, 356-470`)

```ts
createEvidence(undefined /* no subject: target identity unknown */, { id:"frida", name:"Frida", version:null }, {
  predicateType: "rea.frida.instrumentation-observation",
  operation, parameters /* session_id, device_id, remote.address/origin/keepalive (no token/cert), mode, pid|program+argv */,
  result, rawResult?: { source_representation },
  confidence: "observed", authority: "external-service", environment: null,
  limitations: ["The target operating system and architecture were not reported by this observation.",
                ...fridaCaptureLimitations(result), ...invalidUtf8Note],
});
```

`evidence_id = "ev_" + sha256(canonical semantic projection)` → deterministic IDs. Fields available but unused by
Frida: `subject` (artifact digest/format/arch), `environment {id, platform, architecture, isolation}`, `locations`
(address / address-range / file-offset), `evidence_links`, `relationship_coverage`. **BEA should populate
`environment` (Process.platform/arch from the agent) and `locations` (module+RVA) — REA leaves them null/empty.**

### 6.3 Tool contracts and effects (VERIFIED-src)

`src/contracts/fridaToolContracts.ts:65-313`: `list_frida_devices`, `list_frida_processes`, `start_frida_session`,
`load_frida_script`, `resume_frida_session`, `unload_frida_script`, `frida_session_status`, `close_frida_session`,
`instrument_with_frida`. Patterns: `z.strictObject`, `.refine` for mode/field exclusivity, `session_id:
z.string().uuid()`, `localPathStringSchema` for paths, `evidenceResultOf(schema)` wrappers, `analysisDetailOutputSchemaOf`
for complete/summary. Effects (`src/contracts/toolEffects.ts:203-252`) are a typed record per tool:
`{mutatesTarget, mutatesSession, writesFilesystem, launchesProcess, accessesNetwork, changesUiState, mayDiscardData,
executesForeignCode, mutatesDevice, idempotent}` → MCP annotations (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) are **derived** from effects. Example: `load_frida_script` = mutatesTarget +
mutatesSession + launchesProcess + accessesNetwork + executesForeignCode, not idempotent. `frida_session_status` =
`evidence` (mutatesSession only, because it records Evidence).

---

## 7. Frida lab on Windows (VERIFIED-run)

Lab: `scratchpad/bea-lab/rea-runtime/` — `target.c` (MinGW gcc -O1 -g; exports `bea_add` (4-byte body),
`bea_scale`, `bea_step` (hookable), globals `g_counter`, `g_speed`), `lab.mjs` (spawn/attach/agent/RPC/
Stalker/watchpoint/crash), `lab-inherit.mjs` (REA-shaped spawn with no stdio). Outputs `stderr-*.txt`. All spawned
targets were killed or exited; verified none remain.

| # | Check | Result |
|---|---|---|
| 1 | `await import(frida.js)` + `getDeviceManager()` + `getDeviceById("local",1000)` | ~55-95 ms to device `{id:"local", name:"Local System", type:"local"}` |
| 2 | `device.spawn(target, {argv:[target,"arg with space",'q"uote'], stdio:"pipe"})` | paused pid in ~15-40 ms; argv round-trips exactly (spaces, embedded quote) — REA's `argv:[program, ...argv]` convention is correct on Windows |
| 3 | attach → createScript → load (before resume) | load done ~130-500 ms after spawn |
| 4 | Agent Frida-17 API: `Process.mainModule`, `m.getExportByName`, `Process.enumerateThreads/Modules/Ranges` | OK; `Process.arch="x64"`, `platform="windows"` |
| 5 | `send(payload, ArrayBuffer)` | host gets `data` as `Buffer` (`deadbeef`) |
| 6 | `console.log` in agent | goes to `script.logHandler(level,text)`; **default handler prints to host stdout** (stdout file contained `BEA-LAB console.log from agent`) |
| 7 | `Interceptor.attach` on 4-byte `bea_add` (`8d 04 11 c3` = lea/ret) | **throws** `Error: unable to intercept function at …; please file a bug` |
| 8 | Uncaught throw at agent top level | `script.load()` **still resolves**; error delivered as `type:"error"` message with stack/file/line; later `rpc` → `unable to find method 'callAdd'` |
| 9 | `Interceptor.attach(bea_step)` onEnter/onLeave | args/ret/threadId/returnAddress correct; caller RVA `0x18ba` matches objdump |
| 10 | RPC `script.exports.callAdd(40,2)` using `NativeFunction(add,'int',['int','int'])` | `42` (in-process oracle call works, even on the un-hookable tiny function) |
| 11 | RPC `callScale(2.5,4)` with `double` args | `10` |
| 12 | `Memory.scanSync` over module `rw-` ranges for current counter value | 1 hit at RVA `0xf080` = `g_counter` export RVA |
| 13 | Stalker `follow(mainTid, {events:{call:true}, onCallSummary})` 300 ms | 33 distinct call targets; works; but `DebugSymbol.fromAddress` names were **bogus** (`target.exe!frida_value_take_file_descriptor_table_padder`) — no PDB for MinGW/DWARF |
| 14 | `thread.setHardwareWatchpoint(0, g_counter, 4, 'w')` + `Process.setExceptionHandler` | hits delivered as `type:"single-step"`; PC RVA `0x18ae` = instruction **after** `mov %eax,g_counter` at `0x18a8` (trap-after); `unsetHardwareWatchpoint(0)` from handler OK |
| 15 | `script.unload()` → `session.detach()` → `device.kill(pid)` | `script.destroyed` fires; `session.detached(reason="application-requested", crash=null)`; kill resolves; `findProcessByPid` right after kill **still non-null** (process gone moments later) |
| 16 | Crash run (write to 0x10), exception handler does `send()` and `return false` | **no exception message received**; `session.detached(reason="process-terminated", crash=null)`; `device.processCrashed` did **not** fire |
| 17 | Same, handler does `send(); recv('ack',()=>{}).wait();`, host `script.post({type:'ack'})` | message received: `{type:"access-violation", memory:{op:"write", addr:"0x10"}, pc RVA 0x1883, rcx, backtrace RVAs}` then termination |
| 18 | Node exit after work | with `device.output`/`processCrashed` handlers still connected Node **hung** (timeout exit 124) even after `manager.close()`; after `disconnect()` of those handlers + `await manager.close()` Node exited 0 |
| 19 | REA-shaped spawn (no `stdio`) | target's stdout did **not** appear in host stdout (N=1; where it went is unobserved — likely its own/hidden console) |

Caveats: N=1 for each scenario; one compiler; no PDB-bearing target tested; no attach to non-owned processes (by rule).

---

## 8. Defects / risks in REA's Frida approach that BEA must not inherit

1. **Agent `console.log` → host stdout** (VERIFIED-run for frida-node; REA source has no `logHandler`). For an MCP
   server on **stdio transport**, any caller script that logs would inject non-JSON-RPC lines into the protocol
   stream (BELIEVED impact on REA; I did not run REA). Also the text is not captured as Evidence. **BEA:** always set
   `script.logHandler = (level, text) => capture({type:"log", level, text})` immediately after `createScript` and
   before `load()`.
2. **`load()` success ≠ agent initialized** (VERIFIED-run). BEA's own agent should end top-level code with
   `send({bea:"ready", version, apis})` and the host should wait for it (bounded), failing the load if an `error`
   message arrives first.
3. **No crash information on Windows** via `session.detached` / `processCrashed` (VERIFIED-run: `crash=null`, no
   signal). BEA needs an in-agent exception handler with a **blocking ack** to deliver crash context before the
   process dies.
4. **No RPC / host→agent channel.** REA can only collect `send()` output over a time window. BEA's structured
   primitives (read memory, call function, set watchpoint) need `script.exports` request/response.
5. **Target lifetime not owned.** Correct for attach; but for BEA-spawned targets the user wants ownership
   (kill on close / on server exit). BEA should distinguish `owned: true` (spawned by BEA) vs `owned: false`
   (attached) and only `device.kill()` owned ones, then wait for exit (poll `findProcessByPid` → null, bounded).
6. **Signals keep Node alive; manager never closed.** Disconnect every handler BEA connects and call
   `await manager.close()` in `closeAll()`; otherwise CLI one-shots may hang (VERIFIED-run).
7. **`session.detached` reason ignored** — record `reason` (`application-requested | process-replaced |
   process-terminated | connection-terminated | device-lost`, `frida_binding.d.ts:1265-1271`).
8. **Interception failures are unstructured.** Tiny functions/thunks fail; BEA should pre-check and return a typed
   error with alternatives (hook caller sites, hardware breakpoint `setHardwareBreakpoint`, or Stalker probe).
9. **Symbols:** `DebugSymbol` is unreliable without PDBs (VERIFIED-run). BEA must express code locations as
   `{module, module_base, rva, static_va}` and resolve names via its own static map (REA/Ghidra export, PE exports),
   not via Frida's symbolizer.
10. **Windows coverage:** REA's real-provider lane `npm run verify:frida` is documented "requires a Linux host"
    (`docs/frida-instrumentation.md:29`); Windows Frida behavior is unverified in REA's own process.
11. `listProcesses` returns `identifier: null` always (`FridaInstrumentationManager.ts:248`); fine for desktop but
    not a model for BEA's process inventory (add path, ppid, arch where Frida's `ProcessQueryOptions{scope:"full"}`
    provides them — BELIEVED).

---

## 9. GDB console sessions (VERIFIED-src)

- Manager: `src/gdb/GdbSessionManager.ts`. Constants `:37-69`: startup 10 s, command 120 s, 16 MiB command output /
  16,384 records, 16 MiB per MI line, 64 KiB recent-records ring, 64 KiB stderr diagnostics, **max 8 sessions**,
  **max 16 pending commands** per session.
- Platform gate (`:618-628`): only `linux`. Windows message: "Persistent Windows GDB sessions are unavailable because
  owned Job Object cleanup can terminate debugger inferiors." macOS: no `/proc` descriptor verification.
- Launch (`:742-750`): `spawnOwnedProviderProcess({command: REA_GDB_COMMAND ?? "gdb", arguments: ["--nx","--quiet",
  "--interpreter=mi3"], stdin:"pipe", runId, hostEnvironment, signal})`; falls back to `mi2` if mi3 fails
  (`:699-726`). Waits for the `(gdb)` MI prompt before ready (startup timeout).
- Command: `execute(sessionId, command, signal)` (`:1128-1300`) sends `` `${token}-interpreter-exec console ${miQuote(command)}` ``
  through `#request`, correlates by numeric token, collects MI result/async/stream records for that command.
  Result schema `gdbCommandResultSchema` (`src/domain/commandObservation.ts:19-32`): `{command, mi, records[],
  console, target, log, process_exit_observed?, process_exit_code?, process_exit_signal?, output_truncated,
  output_invalid_utf8?, completion_status: "complete"|"unknown"}`. Evidence predicate
  `rea.debugger.console-observation`, provider `gnu.gdb`, limitation "The unrestricted GDB console can access local
  shell, filesystem, network, and target controls."
- Timeout/cancel: a timed-out or cancelled command makes later output uncorrelatable → session is **stopped**
  (`:1950-2110`), partial records returned with `completion_status:"unknown"`.
- Close (`:1344-1455`): `-list-thread-groups --recurse 1`; 0 inferiors → `-gdb-exit` (`target_state:"none_observed"`);
  1 inferior + caller-verified `inferior_tty` → `-inferior-tty-show` re-verify + `/proc` fd check + `-target-detach`;
  otherwise refuse with "Live GDB inferiors require an explicit disposition…" (caller must detach/kill via console).
  REA "never kills attached or remote targets".
- `closeAll()` (`:1475-1498`): abort active starts, wait command tails, `closeOwnedDebuggerSessions` stops only the
  debugger process (`src/process/ownedDebuggerSession.ts:177-314`, "never its process group or target").
- Contract: `start_gdb_session {inferior_tty?}`, `gdb_console {session_id, command, detail}`, `gdb_session_status`,
  `close_gdb_session` (`src/contracts/gdbToolContracts.ts:16-107`). A console command also "closes any active
  binary-analysis session" in a shared server (admission rule).

Takeaway for BEA: REA's GDB is a **raw console with excellent protocol hygiene** (token correlation, caps, stop on
desync), not a structured debugger API. BEA on Windows cannot reuse it.

## 10. Rizin debugger sessions (VERIFIED-src)

- `src/rizin/RizinDebugSessionManager.ts`. Limits `:35-56`: 8 sessions, 16 pending commands, 120 s frame timeout,
  30 s startup, 16 MiB frame/output, 4 MiB/4096 queued frames, 16 KiB recent frames.
- Linux only (`:346-353`), requires a caller TTY verified as a char device (`:354-380`).
- Launch args (`:392-404`): `["-N","-0","-d","-R","stdout=<tty>","-R","stderr=<tty>","-e","dbg.exitkills=false",
  ...("-D", backend)?, path]` — `-0` gives NUL-framed output, `dbg.exitkills=false` prevents killing the inferior on
  exit.
- Command framing (`:658-700`): writes `` `${command}\n!echo ${marker}\n` `` with a random
  `__REA_COMMAND_COMPLETE_<uuid>__` marker and collects NUL frames until the marker. Unsolicited frames before a
  command → session unavailable (ambiguous correlation). Output scope is explicitly
  `"command_and_interleaved_session_output"`.
- Contracts: `start_rizin_debug_session {path, inferior_tty, backend?}`, `rizin_debug_command {session_id, command
  (single line)}`, `rizin_debug_session_status`, `close_rizin_debug_session` (`src/contracts/rizinDebugToolContracts.ts`).

## 11. LLDB tracer `observe_native_calls` (VERIFIED-src)

The only **structured** dynamic primitive in REA. macOS Mach-O only (resolves `lldb` via `xcrun`,
`LldbCallTracer.ts:221-232`; provider id `native-macos`).

### 11.1 What it does (`bridge/native/rea_lldb_tracer.py:1-10`)
"Launch one owned process, stop at the requested functions and Objective-C methods, record each entry from registers
and memory reads only, continue, and kill the process once it exits, the event or aggregate resource limit is
reached, or the duration elapses. Target output is drained through bounded FIFOs. No expression is evaluated and no
target code runs on the tracer's behalf."

### 11.2 Invocation protocol (`src/native/LldbCallTracer.ts:449-511`)

Host writes `config.json` (mode 0600) into a `PrivateRuntimeRoot` temp dir, then runs:

```
lldb --batch --no-lldbinit --no-use-colors \
  -o "command script import <REA>/bridge/native/rea_lldb_tracer.py" \
  -o "rea_trace <dir>/config.json"
```

`__lldb_init_module` registers `command script add -f rea_lldb_tracer.run rea_trace` (`.py:916-917`). `run()` reads
the config, calls `trace()`, and writes JSON to `config["result_path"]`; exceptions become
`{"status":"tracer-error"}` (`.py:904-913`).

Config keys: `executable, architecture, expected_sha256, arguments, environment, working_directory, breakpoints[]
({kind:"function", name, module|null} | {kind:"objc-method", selector, class_name|null, method_type}), duration_ms,
max_events, argument_registers, backtrace_frames, max_output_bytes (1 MiB), stdout_path, stderr_path (FIFOs),
stdout_capture_path, stderr_capture_path, result_path, pid_path, identity_ack_path, observation_path (JSONL journal)`.

Handshakes via files:
1. Tracer creates target stopped at entry (`eLaunchFlagStopAtEntry`), writes the PID to `pid_path` (`.py:701-702`).
2. Host captures the OS process start identity (to prove ownership against PID reuse) and writes `"readable"` to
   `identity_ack_path`; tracer polls every 25 ms (`_wait_for_identity_ack`, `.py:129-139`). Any other ack → kill.
3. Tracer re-hashes the executable and compares file identity + LLDB module UUID before/after launch
   (`.py:598-633, 714-772`); mismatch → kill + `target-integrity-error`.

### 11.3 Tracing loop
- `target.skip-prologue=false` so the stop is at the symbol entry where ABI argument registers are intact
  (`.py:593-597`).
- Breakpoints by name (`BreakpointCreateByName`, optionally module-scoped; ObjC `-[Class sel]`/`+[…]`)
  (`.py:268-296`); script callback `breakpoint_hit` (`.py:464-475`) records synchronously while the frame is stopped:
  integer arg registers (`ARGUMENT_REGISTERS`: arm64 x0-x7, x86_64 rdi,rsi,rdx,rcx,r8,r9; `.py:22-27`), selector
  string from `_cmd`, receiver dynamic class via `eDynamicDontRunTarget`, optional backtrace locations
  `{load_address, file_address, module, module_path, symbol}` (`.py:247-261`).
- Event loop (`.py:785-806`): `listener.WaitForEvent(1)`, stop on `exited`, `duration-elapsed`, `event-limit`,
  `stop-limit` (256 signal/exception stops), `resource-limit` (8 MiB trace JSON or 65,536 frames); otherwise
  `process.Continue()`. Non-breakpoint signal/exception stops are recorded as `other_stops` descriptions.
- Always `process.Kill()` unless it exited; result JSON:
  `{status:"traced", version, pid, outcome, exit_status, exit_description, killed, terminated, elapsed_ms,
  breakpoints:[{index, location_count, locations[≤64]}], breakpoint_locations_truncated, events[], resource_limit_reached,
  target_output:{stdout_bytes, stderr_bytes, *_truncated, *_complete}, target_identity:{selected_file_sha256,
  loaded_image_sha256:null, file_device, file_inode, module_path, module_uuid, stable}, other_stops[]}`.
- Crash-safe partials: every accepted event is also appended to a bounded 8 MiB JSONL journal and flushed
  (`_ObservationJournal`, `.py:72-87`); on cancel/timeout/bridge error the host reads the journal and returns it as
  `details.partial_observation` with `coverage.status:"partial"` (`LldbRetainedObservations.ts`).
- Host side: deadline = `duration_ms + DEADLINE_GRACE_MS`; after LLDB exits the host independently verifies the
  target is gone using the start identity (`ensureTerminated`, `signalProcessWithStartIdentity`); unresolved cleanup is
  retained (`#pendingCleanup`) and retried before the next trace (`LldbCallTracer.ts:219`).
- Input schema (`src/domain/native/nativeCallObservation.ts`): `breakpoints (min 1)`, `arguments`, `environment`
  overrides, `working_directory?`, `duration_ms 100..600000 (10000)`, `max_events 1..100000 (1000)`,
  `argument_registers 0..8 (4)`, `backtrace_frames 0..64 (0)`.
- Evidence (`NativeCallObservation.ts:140-240`): explicit `coverage {status, event_limit_reached,
  resource_limit_reached, unresolved_breakpoints}` and many conditional limitations. Explicitly **not observed**:
  return values, floating-point and stack arguments, inlined/`objc_direct` calls (`docs/native-investigation.md:647-648`).

Takeaway: the LLDB tracer is the closest REA analogue to BEA's "function hook with structured capture", and its
**file-based config/result/journal protocol + identity-ack + integrity re-hash + coverage block** is a strong template.
Its limits (entry-only, integer registers only, no returns, macOS only, breakpoint-per-hit cost) are exactly what a
Frida-based BEA hook primitive fixes.

## 12. pwndbg / recorded crashes (VERIFIED-src, `docs/recorded-crashes.md`)

Core-file only. `inspect_recorded_crash` decodes Linux ELF64 cores (x86-64/AArch64) with pwntools/pyelftools in a
caller-provided venv (`REA_PWNTOOLS_PYTHON`); optional `include_debugger_context` runs GDB+pwndbg (`bridge/pwndbg/
launch_impl.py` execs `gdb -nx -nh --batch --quiet -iex "set auto-load off" -iex "set debuginfod enabled off" -iex
"set auto-solib-add off" -ex <fixed python>`; `core_context.py` loads the core, uses `pwndbg.aglib.vmmap`, pins
pwndbg version `2026.09.15`). "Historical PIDs are metadata. They never select a live process." Nothing for live
crash capture, nothing for Windows minidumps.

## 13. Other runtime-adjacent subsystems (VERIFIED-src from docs)

- **Process capture** (`docs/process-capture.md`): runs one command in a PTY, records terminal frames, interactions,
  exit, filesystem snapshots, process samples; compares captures. Linux/macOS only; "Native Windows capture is
  unavailable because the PTY adapter does not yet verify descendant cleanup." Behavioral, not instruction-level.
- **JS runtime observation** (`docs/javascript-runtime-observation.md`): passive V8 Inspector; sends only
  `Runtime.enable` and `Debugger.enable`; never evaluates/breaks/resumes. 8 MiB metadata budget.
- **Electron observation** (`docs/electron-observation.md`): file-page CDP observation and Playwright-driven scenarios.
- **Static↔runtime correlation** (`src/domain/staticRuntimeCorrelation.ts`): hypothesis-level correlation between
  *comparison Evidence* records (static function-diff vs process-capture diff). It is **not** address mapping.
  REA has no ASLR rebasing of Ghidra/REA addresses into a live process. The only implicit static↔runtime address
  pair anywhere is LLDB's `load_address` + `file_address` per event (`rea_lldb_tracer.py:247-261`). Static side does
  expose `image_base` from providers (`src/contracts/enhancedToolContracts.ts:65`, `src/domain/hopperValues.ts:516-548`)
  — BEA can consume that for rebasing.

## 14. Process ownership and Windows handling (VERIFIED-src)

- `spawnOwnedProviderProcess` (`src/process/ProviderProcess.ts:237-300`): on Windows uses `WindowsOwnedProcess`
  (`src/windows/WindowsOwnedProcess.ts`), a packaged Node-API addon (`native/windows/build/rea-windows-x64.node`,
  sources `native/windows/src/process.cc`) that launches into a **Job Object with kill-on-close**
  (`launchSchema: {jobAssigned: true, killOnOwnerClose: true}`, `WindowsOwnedProcess.ts:13-18`); optional job memory
  limit. POSIX uses detached process groups. Loader verifies manifest version/ABI/sha256 before loading
  (`src/windows/WindowsNativeLoader.ts`, `native/windows/README.md`).
- That Job Object is exactly why GDB is disabled on Windows: closing the debugger's job would kill inferiors that GDB
  launched (they inherit job membership).
- **Frida spawns are not under REA's process ownership at all**: `device.spawn` is performed by frida-core's own
  helper; REA records only the PID and never kills. No Job Object, no start-identity capture, no PID-reuse guard for
  Frida targets.
- `docs/tool-design.md:71-163` "Own the lifecycle" rules (owner per resource, separate admission/readiness/exit/
  release, cancellation through cleanup, retain failed cleanup owners, "A helper exit, missing reply, or missing PID
  does not establish target exit", "A Windows command leader's exit does not establish Job Object closure").
- Windows-specific handling in the Frida path: **none**. No special-casing of paths, consoles, PDB symbols, or
  architecture (x86 vs x64 targets; BELIEVED: 64-bit frida-core can inject into WoW64 32-bit processes via its
  helper, untested here).

---

## 15. Gap analysis: what REA does NOT cover dynamically (BEA scope)

| BEA capability | REA today | Gap |
|---|---|---|
| Spawn/attach, process list | Frida tools (generic) | No owned-target kill, no env/cwd/stdio, no crash reason, no PID start-identity, no arch/platform in Evidence |
| Module / export / memory map inspection | none (only via caller JS messages) | Need structured `list_modules`, `list_exports`, `list_ranges` with protections, file paths, sizes, digests |
| Live memory read / disassembly | none | Need bounded `read_memory` (hex/typed), `disassemble` (Instruction.parse or host Capstone over read bytes) |
| Memory scanning (Cheat Engine style) | none | Need value/pattern scan, next-scan narrowing (changed/unchanged/increased/exact), result sets with bounded storage |
| Function hooks w/ structured arg/ret capture | LLDB tracer (macOS, entry only, int regs) | Need cross-platform Interceptor hooks: typed args (int/ptr/float/double/struct deref), return values, backtrace as module+RVA, sampling/limits, failure for tiny functions |
| Stalker tracing + coverage export | none | Need call/block trace, coverage export (drcov / lighthouse format), bounded |
| Hardware watchpoints ("what writes") | none | Need per-thread DR0-3 management on all threads, trap-after PC correction (previous instruction), hit aggregation by writer |
| Call target functions (oracle) | none | Need NativeFunction calls with ABI/types, thread choice, timeouts, exception capture |
| Memory/module dumps | none | Need module dump (in-memory PE), range dump with digests; minidump (BELIEVED via MiniDumpWriteDump through agent or host) |
| Crash / exception capture | core-file decode only (Linux) | Need live exception capture (Process.setExceptionHandler + blocking ack), registers, faulting access, backtrace |
| Static↔runtime address mapping | none (hypothesis correlation only) | Need `static_va = runtime - module_base + preferred_base` with module identity check (PE timestamp/size/sha256) |
| Unicorn emulation / differential testing | none | Need emulator harness (Python unicorn 2.1.4 available) + compare to live oracle results |
| Windows support | Frida only; GDB/Rizin/LLDB/capture refuse | BEA's primary host is Windows; must verify there |

---

## 16. Patterns BEA should mirror (concrete)

1. **Port/Service/Provider/Adapter layering** with a `Result<T, AnalysisError>` algebra; MCP and CLI share the
   service (§2).
2. **Lazy optional binding**: `import type` only at top, injectable `deviceManagerLoader`, single-flight load,
   memoized failure surfaced via `availabilityFailure()` and capability discovery (§3). Keep `frida` as an
   optionalDependency pinned to an exact version (17.23.2) and a compile-time compatibility assertion against vendor
   types.
3. **Admission gate + operation registry** (`#withOperation`) and **closeAll that drains admitted work first**, is
   memoized, and is retryable on failure (§4.2, §4.10).
4. **Per-session promise-chain lock** for all mutating ops; **dedupe concurrent close**.
5. **Subscribe-then-reconcile** for detach (`session.detached.connect` then `if (session.isDetached())`).
6. **Startup-failure cleanup records** retained until every acquired resource (session, paused spawn, remote ref) is
   released; resume a paused spawn rather than orphan it (for attach mode) — BEA additionally kills owned spawns.
7. **Script state machine** `active → cleanup-pending → released`; failed unload keeps ownership; refuse resume while
   cleanup is pending.
8. **Capture before load**: allocate capture + connect handler before `load()`; return load-time messages inline.
9. **Bounded capture**: session byte budget with FIFO eviction, per-field caps, node/depth caps, cycle detection,
   base64 binary with 3/4 budget, `*_truncated` flags + named `*_capture_limit`, limitations only when data actually
   dropped, never trust flags inside caller payloads (§5).
10. **Secret redaction** of transport credentials in every string and binary field; credentials never in Evidence
    parameters.
11. **Cancellation**: check signal at dispatch and after every await; keep the first observed failure primary; on
    cancel close what you created and return partial Evidence with explicit `instrumentation_cleanup` and
    `target_liveness_after_cleanup: "unknown"` fields.
12. **Evidence**: deterministic `ev_` IDs, `confidence` (`observed` for runtime reads, `derived` for rebased/static
    joins, `inferred` for heuristics), `authority`, explicit `limitations`, coverage blocks (like the LLDB tracer's
    `coverage {status, event_limit_reached, resource_limit_reached, unresolved_breakpoints}`).
13. **Effects record per tool** → derived MCP annotations (§6.3).
14. **Status is sync, idempotent, and supports `detail: complete|summary`** with retained Evidence for paging.
15. From the LLDB tracer: **integrity checks** (hash executable before/after launch, module identity), **start-at-entry
    + identity ack**, **crash-safe JSONL journal** for partial results, **duration/event/resource outcomes**
    (`exited | duration-elapsed | event-limit | stop-limit | resource-limit`), **unresolved breakpoints make coverage
    partial**.
16. From GDB/Rizin: **token or marker correlation**, **stop the session on desync/timeout** rather than risk
    misattributed output, fixed session/queue capacities with explicit `AnalysisResourceConstraintError`.

## 17. Patterns BEA should change or avoid

- Do **not** expose only a raw "load arbitrary JS" tool as the main API. Ship a versioned BEA agent (compiled once
  with `frida.Compiler` or pre-bundled) exposing typed RPC methods; keep raw script loading as an escape hatch.
- Set `script.logHandler` always (stdio-MCP safety + capture logs).
- Use `script.exports` RPC with per-call timeouts (frida-node rejects pending RPC on `script.destroyed`, `frida.js:66-77`)
  and abort via `Cancellable` where needed.
- Own spawned targets: `device.kill(pid)` on close/shutdown for `owned` sessions; poll until gone (bounded);
  BELIEVED-useful: also spawn under a Windows Job Object is not possible through frida-core, so ownership is by
  PID + creation time (capture via agent `Process.id` + host `Get-Process StartTime`/`GetProcessTimes`).
- Disconnect all signal handlers and `await manager.close()` in `closeAll()`.
- Record `session.detached` `reason` and crash parameter; install an exception handler with blocking ack for crash
  capture.
- Don't rely on `DebugSymbol` on Windows binaries without PDBs; use module+RVA and the static map.
- Handle `Interceptor.attach` failures per target and suggest alternatives.
- For watchpoints, translate trap-after PC to the writer instruction (disassemble backwards from the static map or
  record `pc` + `previous_instruction_candidate` and let the host Capstone-disassemble from the function start).
- Add a **Windows real-provider verify lane** (REA's is Linux-only).

## 18. Sketch: BEA Frida session manager (derived from REA, with the gaps filled)

```ts
// src/frida/BeaSessionManager.ts (sketch)
export class BeaSessionManager implements DynamicSessionPort {
  #sessions = new Map<string, BeaSession>();
  #pendingStartups = new Set<PendingStartupCleanup>();
  #queues = new Map<string, Promise<void>>();
  #ops = new Set<Promise<unknown>>();
  #closing = false; #closeAll?: Promise<void>;
  #dm?: DeviceManager; #dmLoading?: Promise<DeviceManager>; #loadFailure?: { reason: string };
  constructor(private readonly loader = async () => (await import("frida")).getDeviceManager()) {}

  async #startSession(input: StartInput): Promise<Result<SessionObservation, AnalysisError>> {
    const dm = await this.#getDeviceManager();
    const device = await dm.getDeviceById(input.deviceId ?? "local", 1000);
    const owned = input.mode === "spawn";
    const pid = owned
      ? await device.spawn(input.program, { argv: [input.program, ...(input.argv ?? [])],
          ...(input.env ? { env: input.env } : {}), ...(input.cwd ? { cwd: input.cwd } : {}), stdio: "pipe" })
      : input.pid;
    const session = await device.attach(pid /*, { exceptor: "full" } (BELIEVED default) */);
    const s: BeaSession = { id: randomUUID(), device, session, pid, owned, detachReason: null, ... };
    const onDetached = (reason, crash) => { s.detached = true; s.detachReason = reason; s.crash = crash && pickCrash(crash); };
    session.detached.connect(onDetached); s.disconnectors.push(() => session.detached.disconnect(onDetached));
    if (session.isDetached()) s.detached = true;
    const onOutput = (opid, fd, data) => { if (opid === pid) s.stdio.push(fd, data); }; // bounded
    device.output.connect(onOutput); s.disconnectors.push(() => device.output.disconnect(onOutput));
    // load BEA agent
    const script = await session.createScript(BEA_AGENT_SOURCE, { name: `bea-agent-${s.id}` });
    script.logHandler = (level, text) => s.capture.log(level, text);       // never host stdout
    const onMsg = (m, d) => s.capture.record(m, d);                      // REA-style bounded capture
    script.message.connect(onMsg); s.disconnectors.push(() => script.message.disconnect(onMsg));
    await script.load();
    await s.capture.waitFor(m => m.payload?.bea === "ready" || m.type === "error", 5_000);  // fail on error
    ...
  }
  async #closeSession(s: BeaSession) {
    // unload agent → detach → (owned) kill + wait-until-gone → disconnect handlers → delete
  }
  async #closeAllImpl() {
    await Promise.allSettled(this.#ops); /* pending startups, sessions */;
    await this.#dm?.close();   // REA never does this; required for clean exit (VERIFIED-run)
  }
}
```

---

## 19. Open questions

1. Should BEA ever spawn without `stdio:"pipe"`? With `inherit` the target's output location on Windows is unobserved
   (lab #19); `pipe` gives Evidence and avoids stdout contamination.
2. Does `SessionOptions.exceptor` (`full | handler-only | off`, `frida_binding.d.ts:1254-1258`) change crash delivery
   or interfere with the target's own SEH/VEH on Windows? Untested.
3. Does `device.processCrashed` ever fire on Windows local devices (it did not in lab #16)? BELIEVED it's tied to
   platform crash reporters (macOS/iOS/Android).
4. Watchpoints on all threads: does `Process.attachThreadObserver` (Frida 17, BELIEVED) exist to apply DR registers
   to new threads? Needs a lab.
5. WoW64 (32-bit) targets from 64-bit Node/frida on Windows: untested here.
6. Ownership proof for frida-spawned PIDs on Windows (no Job Object): PID + process creation time is the REA-style
   identity; confirm a reliable creation-time source (Win32 `GetProcessTimes` via agent `Kernel32` NativeFunction, or
   host PowerShell).
7. Whether BEA's agent should be compiled with `frida.Compiler` at build time (TypeScript agent, `frida-compile`) vs
   plain JS source string; REA has no precedent.
8. Stdio MCP: confirm empirically that REA really leaks agent `console.log` into its MCP stdout (source + binding
   analysis says yes; I did not run REA).

## 20. Lab artifacts (scratchpad)

- `bea-lab/rea-runtime/target.c`, `target.exe` — owned test target.
- `bea-lab/rea-runtime/lab.mjs` — full lifecycle lab (`node lab.mjs <target.exe> normal|crash`; env
  `DEFAULT_LOG=1`, `NO_CLOSE=1`, `KEEP_SIGNALS=1`).
- `bea-lab/rea-runtime/lab-inherit.mjs` — REA-shaped spawn without stdio.
- `bea-lab/rea-runtime/stderr-normal.txt`, `stderr-crash.txt`, `stdout-defaultlog.txt`, `stderr-inherit.txt` — raw
  observations.
