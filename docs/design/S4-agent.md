# S4-agent: BEA in-target Frida agent design (implementation-ready)

**Scope.** This document designs the TypeScript agent that BEA injects into every live target. It covers the bundle
build, the module layout under `src/agent/`, the exact host↔agent wire contract in `src/shared/agentProtocol.ts`,
the single exception dispatcher, the event pipeline, and each feature area: inspection, memory, disassembly, scans,
hooks, API behavior profiles, watchpoints, Stalker, oracle calls, overrides, dumps and `run_script` isolation. It also
sets every agent-side bound.

**Out of scope.** Host-side design (tool contracts, ledger, CLI, jobhost, emulator bridge) belongs to other S-docs.
Where the agent needs something from the host, §21 states it as an obligation.

**Labels.**
- **VERIFIED** means observed on this host: Windows 11 Pro 10.0.26200, Frida 17.23.2 node binding, QJS unless
  stated. Sources are either a research note (`[ext-frida §3.9]`) or this design's own lab, cited `[S4-lab Fn]`.
- **BELIEVED** means from documentation, typings, Windows headers or memory, not exercised. Each BELIEVED item that
  matters is an explicit assumption in §20 with a lab check to run before or while implementing it.
- `[proposal]` marks a design choice of this document.

**Design lab.** `<scratch>/bea-lab/design-S4-agent/`.
- Fixture: `bt_fixture.c` / `bt_fixture.exe`, built with gcc 16.1 (MinGW, msvcrt). Modes: `ops` (20 marked Win32
  operations), `quick` (same, then exit immediately), `av N` (first-chance AVs handled by SEH).
- Host runner: `s4_host.mjs` (modes `levels | ex | exit | crash | guard`).
- Agents: `s4_levels.js`, `s4_memnative.js`, `s4_exitflush.js`, `s4_crash.js`, `s4_guard.js`.
- Raw results: `out_*.json`.
- Every process spawned there was killed. A `tasklist` check found none left.

---

## 0. Decisions at a glance

| # | Decision | Basis |
|---|---|---|
| A1 | One versioned agent bundle (`dist/agent/bea-agent.js`). It is built from `src/agent/**` and `src/shared/**` with `frida.Compiler` at **build time** (ESM bundle, `typeCheck:'full'`) from a staging directory, loaded with `runtime:'qjs'`, and never compiled at runtime | [ext-frida §1.8]; orchestrator decision |
| A2 | Every RPC returns plain data `AgentResult<T> = {ok:true,value} \| {ok:false,error:AgentError}`. Thrown errors are converted inside the agent. The only throws the host sees are transport failures ("Script is destroyed", "unable to find method", cancellation) | [ext-frida §1.7]; [rea-evidence §10.1] |
| A3 | Binary payloads travel as an RPC tuple `[AgentResult, ArrayBuffer]` (read_memory) or as `blob` messages in 4 MiB chunks (dumps) | **VERIFIED** tuple → host `[json, Buffer]` [S4-lab F1]; 600 MB/s binary [ext-frida §1.9] |
| A4 | Handshake: top-level `send({bea:'ready', protocol:'bea-agent/1', protocol_minor, agent_version, build_id, …})`, then host RPC `hello(config)`. Before `hello`, only `hello`, `ping` and `processInfo` are admitted | [rea-runtime §8.2] |
| A5 | **One** `Process.setExceptionHandler`, registered at agent load before anything else and never re-registered. It routes debug-register traps, BEA guard-page traps, BEA trap-flag steps and everything else (first-chance record, optional blocking crash report) | **VERIFIED**: a 2nd call in the same script *replaces* the 1st; handlers of different scripts run in registration order [S4-lab F15] |
| A6 | Crash capture has three layers. (1) A first-chance record (non-blocking), plus an optional blocking report for crash-class types. (2) A last-chance `kernelbase!UnhandledExceptionFilter` hook with a full report, flush and bounded ack. (3) A `ntdll!RtlExitUserProcess` hook with flush and bounded ack | **VERIFIED** UEF fires after first chance with code and params [S4-lab F13]; exit flush is required or every batched event is lost [S4-lab F11] |
| A7 | Every ack wait is bounded. A `recv('ack')` waiter calls `SetEvent`, and the waiting thread uses a cooperative `NativeFunction(WaitForSingleObject)(h, ms)`. There is no unbounded `recv().wait()` | **VERIFIED** on both the exit and crash paths, with and without ack [S4-lab F12] |
| A8 | Events never use a per-call `send`. Each instrument has a stream with a JSON row buffer (JS tier) or a native ring (native tier). Streams flush every 50 ms or at 2000 rows / 64 KiB. Per-reason dropped counters, agent-side caps and host flow-control acks bound target memory | [ext-frida §1.9] (21 GB without batching; 1.0–1.2M/s batched; 5.4M/s ring) |
| A9 | Two hook engines. **JS tier**: flexible capture (deref chains, strings, float bits from `xmmN`, backtrace), JSON rows, ~200k events/s. **Native tier**: CModule listener writes fixed 160-byte raw-register records into a multi-producer ring, JS drains them as binary batches, multi-million events/s | [ext-frida §3.6, §1.9]; [S4-lab F18] |
| A10 | API behavior profiles (`file`, `registry`, `network`, `process`, `module`, `memory`) hook **ntdll** for file, registry, loader, memory and process; **ws2_32/dnsapi** for network; **kernelbase** only for `CreateProcessInternalW` and the Win32 allocation family. They never hook **kernel32** | **VERIFIED** level map [S4-lab F5, F6, F16] |
| A11 | Hook deny-list: `ntdll!NtAllocateVirtualMemory` and `kernelbase!VirtualAlloc` are never hooked, by profiles or by `hook_function`. Hooking either wedged the target at the next `CreateThread` | **VERIFIED** 4/4 and 2/2 runs, JS and CModule listeners [S4-lab F8] |
| A12 | Watchpoints use two methods. `debug-register` (≤4 slots) has full validation, arms all threads plus new ones, and disarms on the handler side. `page-guard` is BEA's own `PAGE_GUARD` + trap-flag re-arm inside the single dispatcher, which is lossless, reports the exact faulting instruction and gives before/after values. `MemoryAccessMonitor` is only an opt-in fallback engine (§11.3.1) | debug-register [ext-frida §3.9]; guard+TF **VERIFIED** [S4-lab F19] |
| A13 | Long work never blocks the JS thread for more than ≈8 ms per slice: scans, dumps and pointer searches are **jobs** sliced with `setImmediate`. Oracle-call batches are time-sliced (≤50 ms) and return a continuation | [ext-frida §1.7] (one JS thread for all scripts; 400 ms head-of-line) |
| A14 | One global event sequence `g` and one µs clock, both served by the native core CModule, number every row from both engines (atomic). That gives a total order across hooks, watches, exceptions, modules and API events | [proposal]; atomics **VERIFIED** to compile and attach [S4-lab F18] |
| A15 | The agent emits raw numbers for flags and statuses. The host owns the symbolic decoding tables (`src/shared/winConstants.ts`) and the profile catalog ids (`src/shared/apiProfiles.ts`) | [proposal] (keeps per-event cost low) |
| A16 | Gates (`write_memory`, `override_function`, `call_function`) are enforced by the host, **and** the agent refuses with `GateClosed` according to the `hello` config (defense in depth). `run_script` never enters the BEA agent: it is a separate script | orchestrator decision |

---

## 1. New facts from the design lab (VERIFIED unless marked)

All runs used QJS, the 17.23.2 binding, `bt_fixture.exe` or ext-frida's `fixture_gcc.exe`, and spawn → attach →
load → resume.

| Id | Fact | Evidence |
|---|---|---|
| F1 | An RPC method returning `[jsonValue, ArrayBuffer]` arrives on the host as `[jsonValue, Buffer]`. A bare `ArrayBuffer` arrives as a `Buffer`. Matches frida.js `value = params.length > 1 ? [params[1], data] : data` | `out_levels_all_safe_qjs.json` `tuple`/`bare`; `frida/build/src/frida.js` ScriptServices |
| F2 | `Cloak.hasCurrentThread()` exists and is `true` on the agent JS thread. `Cloak` members: `addThread, removeThread, hasThread, hasCurrentThread, addRange, removeRange, hasRangeContaining, clipRange, addFileDescriptor, removeFileDescriptor, hasFileDescriptor`. No profile listener ever recorded a cloaked-thread call (`cloakedCounts:{}` in every run) | `out_levels_*.json` `info` |
| F3 | Interceptor re-entrancy guard: an `onEnter` that calls a hooked function (`NtQueryKey`) through a `NativeFunction` does **not** fire that function's listener (`nestedFired:0` over 30+ nested calls), while the target's own `NtQueryKey` calls are recorded | `out_levels_all_safe_qjs.json` |
| F4 | `this.depth` counts nesting across hooked functions on one thread, e.g. `LoadLibraryW d0 → LoadLibraryExW d1 → LdrLoadDll d2 → NtOpenFile d3 → NtProtectVirtualMemory d3` | same |
| F5 | kernel32 exports such as `CreateFileW/A`, `LoadLibraryW` and `VirtualProtect` are 16-byte `jmp qword ptr [rip+x]` stubs (`fnSize:16`), as is `advapi32!RegOpenKeyExW` (32 B). Attaching to the stub instruments the **kernelbase** implementation: both listeners fire for one call, **both at depth 0**. `kernel32!CreateProcessW` and `kernel32!GetProcAddress` are real wrappers. `kernel32!GetProcAddress` calls `ntdll!LdrGetProcedureAddressForCaller` directly and **never reaches `kernelbase!GetProcAddress`** | `info.presence`; marker 11 |
| F6 | Level map (operation → hooks that fired): see §10.1. Highlights: msvcrt `fopen` → `kernelbase!CreateFileA` → `NtCreateFile`; `RegGetValueW` → `NtOpenKeyEx` + `NtQueryValueKey` **without** `RegOpenKeyExW`; `DeleteFileW` → `NtOpenFile` + `NtSetInformationFile(class 64)` (not `NtDeleteFile`); `FindFirstFileW` → `NtOpenFile` + `NtQueryDirectoryFileEx` (pattern `"<.c"`); `CreateProcessW` on a missing image → `CreateProcessInternalW` only | `out_levels_all_safe_qjs.json` |
| F7 | ntdll syscall stubs are 24 bytes (`mov r10, rcx; …`, `findFunctionRange` size 24), and `Interceptor.attach` works on them | `info.presence` |
| F8 | Hooking **`ntdll!NtAllocateVirtualMemory`** (JS listener, 3/3 runs; CModule native listener, 1/1) or **`kernelbase!VirtualAlloc`** (JS, 2/2) deadlocks the target at the next `CreateThread`: the target stops and the agent stops answering RPCs. These hooks were safe through the full op sequence including `CreateThread`: `NtAllocateVirtualMemoryEx`, `VirtualAllocEx`, `VirtualAlloc2`, `VirtualFree`, `NtFreeVirtualMemory`, `NtProtectVirtualMemory`, `NtClose`, `NtDeviceIoControlFile`, `NtDuplicateObject`, `LdrLoadDll`, `LdrGetProcedureAddressForCaller`, the file and registry families, ws2_32, dnsapi, `CreateProcessInternalW`, `NtCreateThreadEx`, `NtOpenProcess`, `kernelbase!VirtualProtect` | `out_levels_qjs_{mem,memalloc,native,w32alloc,va,…}.json` |
| F9 | Decoder offsets confirmed on real calls: OBJECT_ATTRIBUTES `RootDirectory +0x8`, `ObjectName +0x10`, `Attributes +0x18`; UNICODE_STRING/ANSI_STRING `Length +0`, `Buffer +8`; IO_STATUS_BLOCK `Information +8` (FILE_CREATED 2, FILE_OPENED 1); CLIENT_ID `UniqueProcess +0`; KEY_NAME_INFORMATION `NameLength +0`, `Name +4`; sockaddr_in; WSABUF `len +0`. Argument positions are listed in §10.5. NT name forms: `\??\C:\…`, `\REGISTRY\MACHINE`, `\REGISTRY\USER\S-1-5-21-…`, `\Device\Afd\Endpoint` | `out_levels_all_safe_qjs.json` decoded events |
| F10 | `RegOpenKeyExW(HKEY_LOCAL_MACHINE)` reaches `NtOpenKeyEx` with a real root handle (`0x14c`). `NtQueryKey(root, KeyNameInformation=3)` called from inside the hook resolves it to `\REGISTRY\MACHINE`. For HKCU, kernelbase first runs `NtOpenKey("\REGISTRY\USER\<SID>")` and then a relative `NtOpenKeyEx` | same, markers 8–10 |
| F11 | A target that runs 182 hooked operations and exits about 25 ms after resume. Flushing on a 50 ms timer delivered **0/182**; sending the final batch in a `RtlExitUserProcess` `onEnter` without waiting also delivered **0/182**. Sending and then waiting for a host ack delivered **182/182** plus the exit code | `out_exit_qjs_{timer,exithook,exithookack}.json` |
| F12 | Bounded ack: `recv('ack', () => SetEvent(h))` plus a cooperative `NativeFunction(kernelbase!WaitForSingleObject)(h, ms)`. With the host acking it returns `WAIT_OBJECT_0` and the target exits promptly. Without an ack it returns `WAIT_TIMEOUT` (0x102) after 1503 ms, all data is still delivered, and the process proceeds. No deadlock on either the exit path or the crash path | `out_exit_qjs_exitevent*.json`, `out_crash_qjs_{ack,noack}.json` (detach at 148 ms vs 2144 ms) |
| F13 | A `kernelbase!UnhandledExceptionFilter` hook fires for an unhandled AV after the first-chance handler returned `false`. EXCEPTION_RECORD: `code +0` = 0xC0000005, `flags +4`, `address +0x10`, `NumberParameters +0x18` = 2, `Information +0x20` = [1 (write), 0x0]. CONTEXT: `Rip +0xF8`, `Rsp +0x98`, `Rax +0x78`, `EFlags +0x44`, `MxCsr +0x34`, `FltSave.ControlWord +0x100`. The `RtlExitUserProcess` hook does **not** fire on the crash path | `out_crash_qjs_ack.json` |
| F14 | Thread state of a gcc/msvcrt target at crash: **FPCW 0x37F, MXCSR 0x1FA0**. That is not the 0x027F/0x1F80 that bea-emu forces, so dumps must record the real values (§15) | same |
| F15 | Two scripts, each calling `Process.setExceptionHandler`, both see every exception when each returns `false`, in registration order. When script A re-registers, A's old handler stops, and the new one runs **after** script B | `out_ex_qjs.json` (shared-counter order a1:0,2,4…; b:1,3,5…; after swap b:20,22…, a2:21,23…) |
| F16 | Call chains: `getaddrinfo → GetAddrInfoW → DnsQueryEx`; `socket → WSASocketW → NtCreateFile("\Device\Afd\Endpoint")`; `CreateThread → kernelbase!CreateRemoteThreadEx → NtCreateThreadEx`; `LoadLibraryW(missing)` → 45 `NtQueryAttributesFile` search-path probes then `LdrLoadDll` → `0xC0000135`; send/recv → AFD IOCTLs (`NtDeviceIoControlFile`, 0x12xxx codes) | same |
| F17 | When the agent loaded, `ntdll!LdrLoadDll` already began with a `jmp` into an Interceptor trampoline slab before BEA attached anything to it. This is attributed to Frida's own module tracking (attribution BELIEVED). BEA's listener coexists with it | `info.presence` (LdrLoadDll `insn0: jmp 0x7ffa14b30208`) |
| F18 | TinyCC compiled a CModule using `g_atomic_pointer_add`, `GUM_IC_GET_INVOCATION_DATA`, `GUM_IC_GET_FUNC_DATA`, `gum_invocation_context_get_nth_argument/get_return_value/get_thread_id`. `Interceptor.attach(t, {onEnter: cm.onEnter, onLeave: cm.onLeave}, ptr(i))` was accepted. Record delivery was not observed, because that run hit F8 | `out_levels_qjs_native.json` (`cmError:null`, `hookErrors:[]`) |
| F19 | **Guard-page + TF watch.** `VirtualProtect(page, PAGE_READWRITE\|PAGE_GUARD)`. In the dispatcher, on `type:'guard-page'` for our page: record `d.address` (the faulting instruction itself) and the value before, set `EFlags \|= 0x100` in `nativeContext+0x44`, remember the page per thread, return `true`. On the next `single-step` for that thread: read the value after, clear TF and Dr6, re-apply `PAGE_GUARD`, return `true`. Over 2×1 s on 2 threads: 810/810 and 772/772 violation/step pairs; exact instructions (`+0x1796` write, `+0x178a` read, worker `+0x1930`); exact deltas (1 and 1000); same-page accesses filtered; zero foreign events or re-arm failures; target healthy after disarm. **DR6 reads 0 on these TF steps**, so routing must use per-thread pending state, not DR6.BS | `out_guard_qjs_tf{,2}.json` |

---

## 2. Build, packaging and loading

### 2.1 Build (`scripts/build-agent.mjs`, run by `npm run build`)

1. **Stage.** Copy `src/agent/**/*.ts` to `build/agent-stage/agent/` and `src/shared/{agentProtocol,agentLimits,apiProfiles,binaryLayouts}.ts` to `build/agent-stage/shared/`. Imports inside the agent use `../shared/agentProtocol.js`.
   - Staging keeps the repo-root `tsconfig.json`, which has Node types, out of the agent compilation. frida.Compiler type-checks with its built-in GumJS typings and needs no tsconfig [ext-frida §1.8].
   - `src/shared/winConstants.ts` is host-only and is **not** staged.
2. **Generate** `build/agent-stage/agent/buildInfo.ts`:
   ```ts
   export const AGENT_VERSION = "<package.json version>";
   export const AGENT_BUILD_ID = "<sha256 of the staged sources, first 16 hex>";
   ```
3. **Compile.**
   ```js
   const compiler = new frida.Compiler();
   compiler.diagnostics.connect(...);
   await compiler.build("build/agent-stage/agent/index.ts", {
     projectRoot: "build/agent-stage",
     bundleFormat: "esm",
     typeCheck: "full",
     sourceMaps: "omitted",
     compression: "none",
   });
   ```
   Any diagnostic fails the build. Diagnostics carry BigInt `line`/`code`, so serialize them with a BigInt replacer [ext-frida §6 #1].
4. **Write.**
   - `dist/agent/bea-agent.js`: the bundle.
   - `dist/agent/bea-agent.meta.json`: `{ protocol:"bea-agent/1", protocol_minor, agent_version, build_id, frida_version:"17.23.2", bundle_sha256, bytes, compiler:{bundleFormat:"esm", typeCheck:"full"} }`.
   - Both are build outputs and never committed.
5. **Fallback.** If frida.Compiler regresses, build the same stage with esbuild (`format:'iife', platform:'neutral', target:'es2022'`), which is VERIFIED to load [ext-frida §1.8]. This is a build-script flag, not a runtime path.
6. **Size budget.** The bundle stays ≤ 512 KiB uncompressed (`terser` is not used, so stack traces stay readable). A CI check enforces this.

### 2.2 Load sequence (host side, summarized for the agent contract)

1. `createScript(bundle, {name: "bea-agent", runtime: "qjs"})`.
2. Set `script.logHandler` immediately [rea-runtime §8.1].
3. Connect `message` **before** `load()`.
4. `load()`. Any `type:'error'` message, or a `{bea:'fatal'}`, fails the load.
5. Wait up to 5 s for `{bea:'ready'}`. Check `protocol`, `protocol_minor ≥ required` and `build_id == meta.build_id`.
6. `hello(config)` (§4.3).
7. On spawn, resume only after `hello` succeeds. Early instrumentation at `RtlUserThreadStart` is VERIFIED [ext-frida §1.4].

The agent must never call `console.*` except in debug builds. `logHandler` is a safety net, not a channel.

### 2.3 Runtime choice

QJS always: cheaper hooks and Stalker callouts, eager GC, and support for bytecode or snapshots [ext-frida §5].
Per-byte work goes into CModule kernels, never into QJS loops (33 MB/s vs 1 GB/s [ext-frida §3.4]). V8 is not used in
v0.1.

---

## 3. Module layout (`src/agent/`, one file per feature area, pre-wired index)

```
src/shared/                         pure TS: no node:*, no zod, no frida imports; staged into the agent build
  agentProtocol.ts                  THE wire contract (§4): encodings, errors, messages, RPC map, params/results, rows
  agentLimits.ts                    AgentLimits defaults + hard caps (§17), shared so host validation == agent clamps
  apiProfiles.ts                    API profile catalog (ApiSpec[]), deny-list, caution-list (§10)
  binaryLayouts.ts                  binary record layouts: hook-native/1, block-span/1, block-count/1, gum-event-x64/1 (§6.4)
  winConstants.ts                   HOST ONLY: NTSTATUS names, PAGE_/MEM_/FILE_/KEY_/REG_/AF_ tables for decoding rows
src/agent/
  index.ts                          pre-wired aggregator: boot order, imports every feature's rpc map, rpc.exports, ready
  buildInfo.ts                      GENERATED at build (AGENT_VERSION, AGENT_BUILD_ID)
  env.ts                            façade over GumJS globals (Process, Memory, Interceptor, …) for unit-test injection
  state.ts                          AgentCore singleton: phase, config, jsTid, registries, fault counter
  rpc.ts                            wrapRpc/wrapAll: admission (phase, gates), AgentResult conversion, timing, slow-RPC log
  coreRpc.ts                        hello, ping, status, flush, shutdown, fingerprint (delegates to fingerprint.ts)
  errors.ts                         AgentError constructors; mapThrown(): Frida error text → tagged AgentError
  encode.ts                         hex/pointer/bits helpers, ScalarInput parsing, ValueCell builders
  native/core.ts                    CModule source + bindings: gseq/clock, rings, native hook listeners, TEB stub,
                                    scan kernels, block-count transform; keep-alive of every CModule/NativeCallback
  win32.ts                          lazily created NativeFunction bindings (kernelbase/ntdll), scheduling flags per fn
  events.ts                         StreamRegistry: JSON/binary batching, flush loop, caps, drop counters, flow control
  instruments.ts                    InstrumentRegistry: ids, lifetimes (duration/max_hits), stop protocol, lifecycle msgs
  jobs.ts                           JobRunner: sliced background jobs (setImmediate), progress, cancel, completion msgs
  ack.ts                            bounded host acknowledgements (Win32 event + cooperative wait), persistent receivers
  exceptions.ts                     THE single exception dispatcher; first-chance rows; crash reports; UEF + exit hooks
  modules.ts                        ModuleIndex: ModuleMap cache, module observer → s:modules, PE header/.pdata/delay
                                    imports/RSDS/TLS parsing from memory, epoch
  threads.ts                        thread enumeration, OpenThread/Suspend/GetThreadContext (exclusive), TEB, observer
  originals.ts                      OriginalBytes registry (bytes under every BEA patch) for disasm and revert checks
  capture.ts                        Win64 argument/return readers (slot→reg/xmm/stack), deref chains, strings, cells
  inspect.ts                        processInfo, listModules/Exports/Imports/Sections/Functions, findFunction,
                                    listRanges (snapshots), listThreads, resolveTargets, describeAddresses
  memory.ts                         safe reads (guard-page aware), typed reads/pointer chains, gated writes, revert
  disasm.ts                         disassembly with original-byte overlay; access-instruction recovery (shared)
  scan.ts                           scan engine: first/next, candidates in native memory, kernels, findPointers, paging
  hooks.ts                          hook engine (JS tier + native tier), install/resolve/forced relocation, detached guard
  profiles.ts                       API profile engine: decoders, handle cache, parent tracking, lazy installs, memmap
  hwbp.ts                           debug-register manager (slots, arm/disarm/verify, trap handling)
  pageguard.ts                      PAGE_GUARD + TF watch manager (arm/re-arm/disarm, trap handling, read coordination)
  watch.ts                          watchInstall façade over hwbp/pageguard; watch rows
  stalker.ts                        trace sessions; StalkerCoordinator (followed threads, invalidate, settle, keep-alive)
  call.ts                           call_function: NativeFunction cache, marshalling, scratch arena, runOnThread,
                                    per-call coverage, time-sliced batches
  override.ts                       override_function: rewrite (args/ret/xmm0) and replace (constant), revert
  dump.ts                           dump jobs: module images, ranges, thread state/TEB/TLS → blob stream + manifest
  fingerprint.ts                    instrumentation fingerprint (run_script interference detection)
```

### 3.1 Feature module contract

Every feature file exports exactly two things.

```ts
// e.g. src/agent/memory.ts
import type { AgentRpcImpl } from "../shared/agentProtocol.js";
export function init(core: AgentCore): void { /* allocate state, register streams/hooks if needed */ }
export const rpc = {
  readMemory(p) { /* … */ },
  readTyped(p) { /* … */ },
  writeMemory(p) { /* … */ },
  revertWrite(p) { /* … */ },
} satisfies Partial<AgentRpcImpl>;
```

Dependency rule (lint-checked with an import-graph test over `src/agent`):
- Features import only core services: `state, env, encode, errors, events, instruments, jobs, ack, native/core,
  win32, modules, threads, originals, capture, disasm, stalker` (only the `StalkerCoordinator` export).
- Features never import other features. The single exception is `watch.ts`, which imports `hwbp.ts` and `pageguard.ts`.
- `coreRpc.ts` may read every registry and imports `fingerprint.ts`.
- The dispatcher in `exceptions.ts` calls `hwbp`/`pageguard` through handler-registration hooks
  (`registerTrapRouter`), so there is no cycle.

### 3.2 `index.ts` (pre-wired; implementers never edit it to add a method)

```ts
import { AGENT_PROTOCOL, AGENT_PROTOCOL_MINOR, type AgentRpcImpl, type AgentRpcMethods } from "../shared/agentProtocol.js";
import { AGENT_VERSION, AGENT_BUILD_ID } from "./buildInfo.js";
import { createCore } from "./state.js";
import * as nativeCore from "./native/core.js";
import * as exceptions from "./exceptions.js";
import * as events from "./events.js";
import * as modules from "./modules.js";
import * as threads from "./threads.js";
import * as core from "./coreRpc.js";        // hello, ping, status, flush, shutdown, fingerprint (fingerprint.ts)
import * as inspect from "./inspect.js";
import * as memory from "./memory.js";
import * as disasm from "./disasm.js";
import * as scan from "./scan.js";
import * as jobs from "./jobs.js";
import * as hooks from "./hooks.js";
import * as profiles from "./profiles.js";
import * as watch from "./watch.js";
import * as stalker from "./stalker.js";
import * as call from "./call.js";
import * as override from "./override.js";
import * as dump from "./dump.js";
import * as instruments from "./instruments.js";
import { wrapAll } from "./rpc.js";

const c = createCore();                                  // captures jsTid, t0; phase = "loaded"
try {
  nativeCore.init(c);                                    // 1. CModule core (gseq, clock, rings, kernels): fatal on failure
  exceptions.installDispatcher(c);                       // 2. Process.setExceptionHandler — FIRST, once (A5)
  exceptions.installCoreHooks(c);                        // 3. RtlExitUserProcess + UnhandledExceptionFilter hooks
  events.init(c);                                        // 4. flush loop, flow + ack receivers
  modules.init(c); threads.init(c);                      // 5. module observer (s:modules), thread observer (lazy)
  for (const f of [inspect, memory, disasm, scan, jobs, hooks, profiles, watch, stalker, call, override, dump, instruments, core])
    f.init(c);                                           // 6. features (order irrelevant: no feature→feature deps)
  const impl = { ...core.rpc, ...inspect.rpc, ...memory.rpc, ...disasm.rpc, ...scan.rpc, ...jobs.rpc, ...hooks.rpc,
                 ...profiles.rpc, ...watch.rpc, ...stalker.rpc, ...call.rpc, ...override.rpc, ...dump.rpc,
                 ...instruments.rpc } satisfies AgentRpcImpl;
  type _Extra = Exclude<keyof typeof impl, keyof AgentRpcMethods>;
  const _noExtra: [_Extra] extends [never] ? true : never = true; void _noExtra;   // compile-time: no stray methods
  rpc.exports = wrapAll(c, impl);                        // 7.
  send({ bea: "ready", protocol: AGENT_PROTOCOL, protocol_minor: AGENT_PROTOCOL_MINOR, agent_version: AGENT_VERSION,
         build_id: AGENT_BUILD_ID, frida_version: Frida.version, runtime: Script.runtime as "QJS" | "V8",
         pid: Process.id, arch: Process.arch, platform: Process.platform, js_thread_id: c.jsTid,
         t0_wall_ms: c.t0Wall, features: c.features, early: c.early });                // 8.
} catch (e) {
  send({ bea: "fatal", stage: c.bootStage, error: mapThrown(e, "boot") });
}
```

- `satisfies AgentRpcImpl` makes a **missing** method a compile error. The `_noExtra` line makes an **extra** method a
  compile error.
- On a non-x64 or non-Windows process, `createCore` sets `bootStage = "platform"` and throws
  `Unsupported{feature:"target", reason:"x64 Windows only in v0.1"}`. The host refuses WoW64 earlier anyway
  (orchestrator decision).
- On Linux, a later build enables a feature subset (§20, A-17).

---

## 4. The wire contract: `src/shared/agentProtocol.ts` (exact)

Rules that bind every type below:
- **JSON-safe only.** Values are numbers within ±2^53, strings, booleans, null, arrays and plain objects. There is
  **no BigInt**, because the host throws on BigInt arguments and the agent's `JSON` cannot serialize them
  [ext-frida §1.7]. There is no `NativePointer`, `Buffer` or `Int64`.
- **64-bit values are `Hex`**: lowercase, `0x` prefix, no leading zeros, and `"0x0"` for zero. Addresses, u64/i64
  bit patterns, handles, NTSTATUS values and float bit patterns all use this form.
- **Floats cross the boundary as exact bits.** `{bits}` is accepted as input everywhere, and every float output carries
  `bits`. This matches bea-emu/0.1 [ext-backends §9.3], so `diff_function` compares bits directly.
- **Calling convention.** Each RPC takes exactly one `params` object and returns `AgentResult<T>`. Methods marked
  `binary: true` return `[AgentResult<T>, ArrayBuffer]` on success and a bare `AgentResult<never>` on failure; the host
  handles both shapes (F1).
- **Message envelope.** Agent→host messages are `send(header, data?)` with a header discriminated by `bea`.
  Host→agent posts are `script.post({type, …})`, which the agent receives with `recv(type)`.

```ts
// =================================================================================================
// src/shared/agentProtocol.ts — BEA host <-> in-target agent wire contract.  Protocol "bea-agent/1".
// Pure types + constants. Imported by the host (tsc) and staged into the agent (frida.Compiler).
// Additive changes bump AGENT_PROTOCOL_MINOR; incompatible changes bump the major ("bea-agent/2").
// =================================================================================================

export const AGENT_PROTOCOL = "bea-agent/1" as const;
export const AGENT_PROTOCOL_MINOR = 0 as const;
export type AgentProtocol = typeof AGENT_PROTOCOL;

/* ------------------------------------------------------------------------------------------------
 * 4.1 Scalar encodings and ids
 * ---------------------------------------------------------------------------------------------- */
/** Lowercase hex, "0x" prefix, no leading zeros ("0x0" for zero). */
export type Hex = `0x${string}`;
/** Even-length lowercase hex byte string without prefix or spaces ("" for zero bytes). */
export type HexBytes = string;
/** Agent-global event sequence: 1-based, strictly increasing over ALL rows of ALL streams (JS and native). */
export type Gseq = number;
/** Agent monotonic microseconds since agent load (native g_get_monotonic_time() minus t0). */
export type TimeUs = number;
export type ThreadId = number;
export type InstrumentId = string; // "h<n>" hook | "p<n>" profile set | "w<n>" watch | "t<n>" trace | "o<n>" override
export type StreamId = string;     // "s<n>" | "s:exceptions" | "s:modules" | "s:threads" | "s:memmap"
export type JobId = string;        // "j<n>"
export type ScanId = string;       // "sc<n>"
export type BlobId = string;       // "b<n>"
export type SnapshotId = string;   // "ss<n>"
export type WriteId = string;      // "wr<n>"
export type AckToken = string;     // "crash-<n>" | "exit-<n>"

export type ValueType =
  | "i8" | "u8" | "i16" | "u16" | "i32" | "u32" | "i64" | "u64" | "ptr"
  | "bool8" | "bool32" | "f32" | "f64" | "utf8" | "utf16" | "ansi" | "bytes";

/** Scalar input: integer JS number (|v| ≤ 2^53-1), decimal or Hex string (exact 64-bit), boolean, or exact float bits. */
export type ScalarInput = number | string | boolean | { bits: Hex };

/** One captured value in a JSON row. Its meaning comes from the capture spec that produced it. */
export type ValueCell =
  | null                                   // not captured (e.g. leave-only capture on an enter-only row)
  | number                                 // i8..i32, u8..u32, bool8/bool32 (0|1)
  | Hex                                    // i64/u64/ptr two's-complement bits; f32 bits (≤8 digits); f64 bits (≤16)
  | { s: string; trunc?: true }            // utf8 / utf16 / ansi text
  | { x: HexBytes; trunc?: true }          // bytes
  | { e: CaptureErr; a?: Hex }             // capture failed at address a
  | ValueCell[];                           // count > 1
export type CaptureErr = "av" | "guard" | "null" | "too_deep" | "unsupported";

/** Typed output used by results (not rows). Floats always carry exact bits. */
export interface TypedOut {
  type: ValueType;
  value: number | string | boolean | null; // f32/f64: number or "NaN"|"Infinity"|"-Infinity"; 64-bit ints: decimal string
  bits?: Hex;                              // f32/f64 (and i64/u64 raw bits)
  hex?: HexBytes;                          // bytes, or raw bytes of strings
  trunc?: boolean;
}

export interface Paged<T> { total: number; offset: number; items: T[]; next_offset: number | null }
export interface Lifetime { duration_ms: number; max_hits: number }

/* ------------------------------------------------------------------------------------------------
 * 4.2 Results and errors (plain data, tagged)
 * ---------------------------------------------------------------------------------------------- */
export type AgentResult<T> = { ok: true; value: T } | { ok: false; error: AgentError };

export type GateName = "write_memory" | "override_function" | "call_function";
export type AgentResource =
  | "agent_memory" | "instruments" | "streams" | "native_hooks" | "rows" | "scan_candidates" | "scan_snapshot"
  | "scans" | "jobs" | "stalker_threads" | "page_guard_pages" | "call_vectors" | "scratch" | "blob_bytes" | "snapshots";

interface E<T extends string> { _tag: T; message: string }
export type AgentError =
  | (E<"BadParams"> & { issues: { path: string; problem: string }[] })
  | E<"NotReady">
  | (E<"ProtocolMismatch"> & { expected: string; got: string; agent_minor: number })
  | E<"ShuttingDown">
  | (E<"GateClosed"> & { gate: GateName })
  | (E<"AccessViolation"> & { address: Hex; operation: "read" | "write" | "execute" | null; partial_bytes?: number })
  | (E<"GuardPage"> & { address: Hex; owner: "bea" | "target" })
  | (E<"ModuleNotFound"> & { module: string })
  | (E<"ExportNotFound"> & { module: string; export: string })
  | (E<"NoFunctionRange"> & { address: Hex })
  | (E<"NotExecutable"> & { address: Hex; protection: string | null })
  | (E<"HookDenied"> & { address: Hex; api: string; reason: "deadlock-risk" | "agent-critical" | "caution-requires-force"; alternatives: string[] })
  | (E<"HookInstallFailed"> & { address: Hex; attempts: ("default" | "forced")[]; frida_message: string; alternatives: string[] })
  | (E<"HookConflict"> & { address: Hex; existing: InstrumentId; kind: "replace" | "override" })
  | (E<"NoFreeDebugRegister"> & { in_use: { slot: number; owner: InstrumentId | "quarantined"; kind: "watch" | "exec" }[] })
  | (E<"WatchInvalid"> & { reason: "slot" | "size" | "alignment" | "access" | "range" | "stack-page" | "module-code" | "agent-page" })
  | (E<"StalkerBusy"> & { thread_id: ThreadId; owner: InstrumentId | "call"; retry_after_ms: number })
  | (E<"NotFound"> & { what: "instrument" | "scan" | "job" | "snapshot" | "write" | "thread" | "blob"; id: string })
  | (E<"WriteConflict"> & { write_id: WriteId; address: Hex; expected: HexBytes; actual: HexBytes })
  | (E<"Timeout"> & { timeout_ms: number; phase: string })
  | (E<"Cancelled"> & { phase: string })
  | (E<"ResourceLimit"> & { resource: AgentResource; limit: number; observed?: number })
  | (E<"Unsupported"> & { feature: string; reason: string })
  | (E<"Internal"> & { where: string; frida_message?: string });
export type AgentErrorTag = AgentError["_tag"];

/* ------------------------------------------------------------------------------------------------
 * 4.3 Handshake and session configuration
 * ---------------------------------------------------------------------------------------------- */
export type AgentFeature =
  | "hooks.js" | "hooks.native" | "hooks.native.xmm" | "profiles" | "watch.debug-register" | "watch.page-guard"
  | "stalker" | "call" | "override" | "scan" | "dump" | "crash.first-chance" | "crash.last-chance" | "exit-flush";

export interface ReadyMessage {
  bea: "ready";
  protocol: AgentProtocol; protocol_minor: number;
  agent_version: string; build_id: string;
  frida_version: string; runtime: "QJS" | "V8";
  pid: number; arch: string; platform: string;
  js_thread_id: ThreadId; t0_wall_ms: number;
  features: AgentFeature[];
  early: { exception_handler: true; exit_hook: boolean; last_chance_hook: boolean; module_observer: boolean };
}
export interface FatalMessage {
  bea: "fatal";
  stage: "platform" | "cmodule" | "exception-handler" | "core-hooks" | "events" | "modules" | "features" | "rpc";
  error: AgentError;
}

export type ExceptionType =
  | "abort" | "access-violation" | "guard-page" | "illegal-instruction" | "stack-overflow"
  | "arithmetic" | "breakpoint" | "single-step" | "system";

export interface CrashPolicy {
  first_chance_rows: boolean;                 // record non-BEA exceptions on s:exceptions (default true)
  first_chance_blocking: boolean;             // blocking report for crash_class at first chance (default true)
  crash_class: ExceptionType[];               // default ["access-violation","illegal-instruction","stack-overflow","arithmetic","abort","system"]
  ack_timeout_ms: number;                     // first-chance blocking report wait (default 1000, max 5000)
  last_chance_ack_timeout_ms: number;         // UEF + exit + self-terminate (default 2000, max 5000)
  max_blocking_per_10s: number;               // rate limit for first-chance blocking reports (default 8, max 64)
  rows_per_sec: number;                       // first-chance row cap; excess folded into repeat counts (default 1000)
  stack_bytes: number;                        // stack window in reports (default 256, max 4096)
  backtrace_depth: number;                    // ACCURATE backtrace frames (default 32, max 64)
  include_xmm: boolean;                       // xmm0..15 bits in reports (default false)
}

export interface HelloParams {
  protocol: AgentProtocol;
  min_minor: number;
  host: { name: "bea"; version: string };
  session: { session_id: string; instance_id: string; owned: boolean };
  gates: Record<GateName, boolean>;           // host-computed effective gates (call_function: owned || opt-in)
  limits?: Partial<AgentLimits>;              // clamped by the agent to AGENT_LIMIT_HARD
  crash: CrashPolicy;
  streams: { flush_ms: number; exceptions: boolean; threads: boolean };   // s:modules is always on (address reconstruction)
  flow: { high_water_bytes: number; low_water_bytes: number };
}
export interface HelloResult {
  protocol: AgentProtocol; protocol_minor: number; agent_version: string; build_id: string;
  frida_version: string; runtime: "QJS" | "V8";
  process: ProcessInfo;
  limits: AgentLimits;                        // effective (after clamping)
  features: AgentFeature[];
  deny_list: { api: string; va: Hex; reason: "deadlock-risk" | "agent-critical" }[];
  caution_list: { api: string; va: Hex }[];
  system_streams: { exceptions: StreamId | null; modules: StreamId; threads: StreamId | null };
  module_map_epoch: number;
  boot: { t_us: number; early_rows: number };  // rows recorded before hello (e.g. module loads, early exceptions)
}

/* ------------------------------------------------------------------------------------------------
 * 4.4 Limits (values in agentLimits.ts, §17)
 * ---------------------------------------------------------------------------------------------- */
export interface AgentLimits {
  rpc_slice_ms: number; job_slice_ms: number;
  flush_ms: number; batch_max_rows: number; batch_max_bin_bytes: number;
  stream_max_pending_rows: number; stream_max_pending_bytes: number; max_streams: number;
  flow_high_water_bytes: number; flow_low_water_bytes: number;
  max_instruments: number; max_js_hooks: number; max_native_hooks: number; native_ring_records: number;
  max_profile_api_hooks: number; profile_events_per_api: number; handle_cache_entries: number;
  max_capture_args: number; max_deref_depth: number; max_string_chars: number; max_capture_bytes: number;
  max_backtrace_depth: number; backtrace_per_sec: number;
  max_duration_ms: number; max_hits_cap: number;
  page_guard_max_pages: number; hwbp_verify_threads: number;
  stalker_max_threads: number; stalker_queue_capacity: number; stalker_drain_ms: number;
  stalker_max_blocks: number; stalker_settle_ms: number;
  scan_max_concurrent: number; scan_max_candidates: number; scan_snapshot_bytes: number; scan_page_rows: number;
  call_max_vectors: number; call_max_wall_ms: number; call_scratch_bytes: number; call_buffer_bytes: number;
  call_coverage_blocks: number; run_on_thread_timeout_ms: number;
  read_max_bytes: number; typed_max_reads: number; write_max_bytes: number;
  disasm_max_insns: number; disasm_max_bytes: number;
  dump_chunk_bytes: number; dump_max_bytes: number; dump_max_concurrent: number;
  list_page_max: number; snapshot_ttl_ms: number; max_snapshots: number;
  max_jobs: number; agent_heap_soft_bytes: number;
}

/* ------------------------------------------------------------------------------------------------
 * 4.5 Shared descriptive types
 * ---------------------------------------------------------------------------------------------- */
export type TargetRef =
  | { va: Hex }
  | { module: string; rva: Hex }
  | { module: string; export: string };

export interface FunctionRange { base: Hex; size: number; source: "pdata" }
export interface ResolvedTarget {
  va: Hex; module: string | null; module_base: Hex | null; rva: Hex | null;
  export: string | null; function: FunctionRange | null; protection: string | null;
}
export interface PeFacts {
  machine: number; time_date_stamp: number; size_of_image: number; checksum: number;
  entry_rva: Hex; subsystem: number; dll_characteristics: number;
  mapped_image_base: Hex;                     // in-memory OptionalHeader.ImageBase (loader rewrites it = base) [ext-frida §3.14]
  section_count: number;
  codeview: { guid: string; age: number; pdb: string } | null;   // RSDS from the in-memory debug directory
  tls_callbacks: Hex[];                       // VAs from IMAGE_TLS_DIRECTORY64.AddressOfCallBacks
  pdata_entries: number;
}
export interface ModuleInfo { name: string; path: string; base: Hex; size: number; pe: PeFacts | null }
export interface ProcessInfo {
  pid: number; arch: "x64"; platform: "windows"; page_size: number; pointer_size: 8;
  main_module: ModuleInfo; peb: Hex | null; current_dir: string; debugger_present: boolean;
  code_signing_policy: string; frida_heap_bytes: number; js_thread_id: ThreadId; module_map_epoch: number;
}
export interface EffectHint {
  kind: "hook-installed" | "profile-installed" | "watchpoint-set" | "breakpoint-set" | "guard-page-set"
      | "stalker-followed" | "memory-written" | "override-installed" | "function-called";
  reversible: boolean;
  targets: { address: Hex | null; size: number | null }[];
  thread_ids: ThreadId[] | null;
  before: { address: Hex; hex: HexBytes }[];  // original bytes for patches/writes (≤ 64 B each, ≤ 64 entries)
}

export type DropReason =
  | "buffer_full" | "flow_control" | "rate_limit" | "instrument_cap" | "agent_memory" | "ring_overrun"
  | "torn_record" | "decode_error" | "stopped" | "per_api_cap";
export type DropCounters = Partial<Record<DropReason, number>>;
export type EndReason =
  | "requested" | "duration" | "max_hits" | "max_events" | "error" | "process-exit" | "module-unloaded"
  | "shutdown" | "thread-exit";

/* ------------------------------------------------------------------------------------------------
 * 4.6 Event rows (JSON tuples) and binary layouts
 * ---------------------------------------------------------------------------------------------- */
export type RowKind =
  | "hook/1" | "api/1" | "watch/1" | "exception/1" | "module/1" | "thread/1" | "override/1" | "memmap/1"   // JSON
  | "hook-native/1" | "block-span/1" | "block-count/1" | "call-site-count/1" | "gum-event-x64/1";             // binary
export type LayoutId = "hook-native/1" | "block-span/1" | "block-count/1" | "call-site-count/1" | "gum-event-x64/1";
/** Backtrace frame as emitted in rows: "<module>+0x<rva>" when inside a module (ModuleMap at capture time), else the bare VA "0x…". */
export type FrameRef = string;

/** JS-tier hook call. phase: 1 = emitted at enter (emit:"enter"); 2 = full call emitted at leave (args + ret). Calls whose leave is never
 *  seen (longjmp/unwind past the frame) produce no row when emit:"leave"; they are counted in InstrumentCounters.unreturned. */
export type HookRow = [
  g: Gseq, t: TimeUs, tid: ThreadId, phase: 1 | 2, depth: number, caller: Hex,
  args: ValueCell[], ret: ValueCell | null, bt: FrameRef[] | null, regs: Record<string, Hex> | null,
];
/** API profile call (one row per completed call; noreturn APIs emit at enter). args keyed by ApiArgSpec.name. */
export type ApiRow = [
  g: Gseq, t: TimeUs, tid: ThreadId, depth: number, parent: Gseq /* 0 = none */, api: number /* ApiSpec.id */,
  args: Record<string, ValueCell>, ret: ValueCell, caller: Hex,
];
/** Watch hit. insn = the accessing instruction; insn_conf says how it was obtained. */
export type WatchRow = [
  g: Gseq, t: TimeUs, tid: ThreadId, watch: InstrumentId, access: "r" | "w" | "x",
  insn: Hex | null, insn_conf: "exact" | "swept" | "heuristic" | "unknown", pc_after: Hex | null, text: string | null,
  addr: Hex | null, before: HexBytes | null, after: HexBytes | null,
  regs: Record<string, Hex> | null, bt: FrameRef[] | null,
];
export type ExceptionRow = [
  g: Gseq, t: TimeUs, tid: ThreadId, type: ExceptionType, address: Hex,
  mem_op: "read" | "write" | "execute" | null, mem_addr: Hex | null,
  disposition: "passed" | "reported", repeat: number,
];
export type ModuleRow = [g: Gseq, t: TimeUs, ev: "L" | "U", name: string, path: string, base: Hex, size: number, epoch: number];
export type ThreadRow = [g: Gseq, t: TimeUs, ev: "S" | "E", tid: ThreadId, entry: Hex | null];
export type OverrideRow = [g: Gseq, t: TimeUs, tid: ThreadId, override: InstrumentId, applied: "args" | "ret" | "replace", detail: ValueCell[]];
export type MemmapRow = [g: Gseq, t: TimeUs, ev: "new-exec" | "new-rwx" | "gone" | "prot-change", base: Hex, size: number, protection: string, module: string | null];

export interface BinaryField { name: string; offset: number; type: "u8" | "u16" | "u32" | "i32" | "u64"; }
export interface BinaryLayout { id: LayoutId; rec_bytes: number; endian: "le"; fields: BinaryField[]; notes: string }

/* ------------------------------------------------------------------------------------------------
 * 4.7 Agent -> host messages
 * ---------------------------------------------------------------------------------------------- */
interface BatchBase {
  bea: "batch"; stream: StreamId; instrument: InstrumentId | null; bseq: number; kind: RowKind;
  n: number; g0: Gseq; g1: Gseq; t0: TimeUs; t1: TimeUs;
  dropped: DropCounters;                      // delta since the previous batch of this stream
  final: boolean;                             // last batch of a stopped stream
}
export interface JsonBatchMessage extends BatchBase { enc: "json"; rows: unknown[] }        // rows: RowOf<kind>[]
export interface BinBatchMessage extends BatchBase { enc: "bin"; layout: LayoutId; rec_bytes: number } // + data = n*rec_bytes
export type BatchMessage = JsonBatchMessage | BinBatchMessage;

export interface BlobMessage {                // + data (≤ dump_chunk_bytes)
  bea: "blob"; blob: BlobId; job: JobId | null; part: number; offset: number; bytes: number;
  last: boolean; total: number | null; sha256?: Hex;   // sha256 advisory, on the last part only (host recomputes)
}
export type JobKind = "scan-first" | "scan-next" | "dump";
export interface Progress { done: number; total: number | null; unit: "bytes" | "items" }
export interface JobMessage {
  bea: "job"; job: JobId; kind: JobKind; state: "done" | "failed" | "cancelled";
  progress: Progress; result?: ScanStatus | DumpManifest; error?: AgentError;
}
export interface InstrumentMessage {
  bea: "instrument"; id: InstrumentId;
  event: "ended" | "degraded" | "lazy-installed";
  detail: InstrumentSummary | { apis: string[] } | { reason: string };
}
export interface CrashReport {
  report_id: string;
  phase: "first-chance" | "last-chance";
  g: Gseq; t: TimeUs; tid: ThreadId;
  type: ExceptionType;
  code: Hex | null;                           // NTSTATUS: last-chance only (first-chance details carry no code) [ext-frida §3.11]
  address: Hex;                               // faulting instruction (ExceptionAddress / details.address)
  memory: { operation: "read" | "write" | "execute"; address: Hex } | null;
  exception_information: Hex[];               // last-chance EXCEPTION_RECORD.ExceptionInformation[0..n)
  registers: Record<"rax"|"rbx"|"rcx"|"rdx"|"rsi"|"rdi"|"rbp"|"rsp"|"r8"|"r9"|"r10"|"r11"|"r12"|"r13"|"r14"|"r15"|"rip", Hex>;
  eflags: Hex | null; mxcsr: Hex | null; fpcw: Hex | null;
  xmm: Hex[] | null;                          // 16 × 128-bit as 32-hex-digit Hex, when policy.include_xmm
  instruction: { address: Hex; bytes: HexBytes; text: string } | null;
  backtrace: { va: Hex; module: string | null; rva: Hex | null }[];   // [faulting pc, ...ACCURATE return addresses]
  backtrace_source: "exception-context" | "first-chance-cache" | "uef-context";
  stack: { address: Hex; hex: HexBytes } | null;
  module_map_epoch: number;
  flushed: { streams: number; rows: number };
}
export interface CrashMessage { bea: "crash"; ack: AckToken; report: CrashReport }
export interface ExitMessage {
  bea: "exit"; ack: AckToken; via: "RtlExitUserProcess" | "NtTerminateProcess(self)";
  exit_code: number; tid: ThreadId; g: Gseq; t: TimeUs; flushed: { streams: number; rows: number };
}
export interface FaultMessage { bea: "fault"; where: string; error: AgentError; count: number }   // rate-limited internal faults
export interface NoticeMessage {
  bea: "notice";
  code: "flow-shedding-on" | "flow-shedding-off" | "instrument-interference" | "hwbp-unreverted" | "heap-soft-limit";
  detail: Record<string, unknown>;
}
export type AgentMessage =
  | ReadyMessage | FatalMessage | BatchMessage | BlobMessage | JobMessage | InstrumentMessage
  | CrashMessage | ExitMessage | FaultMessage | NoticeMessage;

/* ------------------------------------------------------------------------------------------------
 * 4.8 Host -> agent posts (script.post)
 * ---------------------------------------------------------------------------------------------- */
export type HostPost =
  | { type: "ack"; token: AckToken }              // releases a crash/exit waiter
  | { type: "flow"; received_bytes: number };     // cumulative payload bytes durably received by the host

/* ------------------------------------------------------------------------------------------------
 * 4.9 RPC params / results by area
 * ---------------------------------------------------------------------------------------------- */
// ---- core
export interface PingResult { t: TimeUs; g: Gseq; phase: "loaded" | "ready" | "shutting-down" }
export interface StatusParams { detail: "summary" | "full" }
export interface StreamInfo {
  id: StreamId; instrument: InstrumentId | null; kind: RowKind; enc: "json" | "bin";
  state: "open" | "closing" | "closed"; recorded: number; sent_rows: number; batches: number;
  pending_rows: number; dropped: DropCounters;
}
export interface InstrumentCounters {
  hits: number; recorded: number; sampled_out: number; filtered: number; agent_calls_suppressed: number;
  unreturned: number; errors: number; dropped: DropCounters;
}
export interface InstrumentInfo {
  id: InstrumentId; kind: "hook" | "profile" | "watch" | "trace" | "override"; label: string | null;
  state: "active" | "stopping" | "ended"; stream: StreamId | null; created_t: TimeUs;
  deadline_t: TimeUs | null; max_hits: number; counters: InstrumentCounters; targets: Hex[];
}
export interface InstrumentSummary extends InstrumentInfo {
  end_reason: EndReason | null; ended_t: TimeUs | null; reverted: boolean;
  verification: { kind: "bytes" | "dr7" | "protection"; ok: boolean; detail: string } | null;
}
export interface AgentStatus {
  phase: "loaded" | "ready" | "shutting-down"; t: TimeUs; g: Gseq; module_map_epoch: number;
  instruments: InstrumentInfo[]; streams: StreamInfo[]; jobs: JobInfo[]; scans: ScanStatus[];
  flow: { sent_bytes: number; received_bytes: number; inflight: number; shedding: boolean; shed_rows: number };
  exceptions: { by_type: Partial<Record<ExceptionType, number>>; blocking_reports: number; last_chance: number; bea_traps: number };
  memory: { frida_heap_bytes: number; native_bytes: number; scan_bytes: number; ring_bytes: number };
  rpc: { calls: number; slow: { method: string; us: number }[] };   // slow = slices over rpc_slice_ms (last 16)
  faults: number;
  debug_registers: { slot: number; owner: InstrumentId | "quarantined" | null }[];
}
export interface FlushParams { streams?: StreamId[] }
export interface FlushResult { batches: number; rows: number }
export interface ShutdownParams { revert: boolean; timeout_ms: number }
export interface ShutdownResult {
  stopped: InstrumentSummary[]; unreverted: { id: InstrumentId; detail: string }[];
  scans_freed: number; jobs_cancelled: number; final_batches: number;
}
export interface Fingerprint {
  t: TimeUs;
  patches: { owner: string; address: Hex; expected_head: HexBytes; actual_head: HexBytes; ok: boolean }[];
  debug_registers: { tid: ThreadId; dr7: Hex; ok: boolean }[];   // sampled ≤ hwbp_verify_threads
  guard_pages: { page: Hex; guarded: boolean; ok: boolean }[];
  stalker_threads: ThreadId[];
}

// ---- inspection
export interface ListModulesParams { name_glob?: string; with_pe: boolean }
export interface ListModulesResult { module_map_epoch: number; modules: ModuleInfo[] }
export interface ListExportsParams { module: string; name_glob?: string; kind?: "function" | "variable"; offset: number; limit: number }
export interface ExportRow { name: string; kind: "function" | "variable"; va: Hex; rva: Hex }
export interface ListImportsParams { module: string; name_glob?: string; offset: number; limit: number }
export interface ImportRow {
  name: string | null; ordinal: number | null; from_module: string | null; kind: "function" | "variable" | null;
  slot: Hex | null; resolved: Hex | null; delay: boolean;
}
export interface ListSectionsParams { module: string }
export interface SectionRow { raw_name: string; va: Hex; rva: Hex; virtual_size: number; characteristics: number; protection: string | null }
export interface ListFunctionsParams { module: string; rva_min?: Hex; rva_max?: Hex; offset: number; limit: number }
export interface FunctionRow { begin_rva: Hex; end_rva: Hex; unwind_rva: Hex; chained: boolean }
export interface FindFunctionParams { address: Hex }
export interface ListRangesParams {
  protection: string; coalesce: boolean; module?: string; kind: "all" | "module" | "private" | "malloc";
  offset: number; limit: number; snapshot?: SnapshotId;
}
export interface RangeRow { base: Hex; size: number; protection: string; module: string | null; kind: "module" | "private" | "malloc" }
export type ListRangesResult = Paged<RangeRow> & { snapshot: SnapshotId; taken_t: TimeUs };
export interface ListThreadsParams { registers: "none" | "gpr" | "all"; teb: boolean; names: boolean }
export interface ThreadInfo {
  id: ThreadId; state: string /* unreliable [ext-frida §3.13] */; entry: Hex | null; teb: Hex | null;
  stack: { base: Hex; limit: Hex } | null; name: string | null; regs: Record<string, Hex> | null; bea_role: "agent" | null;
}
export interface ListThreadsResult { threads: ThreadInfo[] }
export interface ResolveTargetsParams { targets: TargetRef[] }
export interface ResolveTargetsResult { results: ({ ok: true; target: ResolvedTarget } | { ok: false; error: AgentError })[] }
export interface DescribeAddressesParams { addresses: Hex[] }
export interface AddressDescription {
  va: Hex; module: string | null; rva: Hex | null; function: FunctionRange | null;
  range: { base: Hex; size: number; protection: string } | null;
  export_hint: { name: string; va: Hex; distance: number } | null;   // nearest preceding export — a HINT only
  bea_patched: boolean; bea_guarded: boolean;
}
export interface DescribeAddressesResult { results: AddressDescription[] }

// ---- memory
export interface ReadMemoryParams { address: Hex; size: number }
export interface ReadMemoryMeta {
  address: Hex; requested: number; returned: number; complete: boolean;
  stop: null | { reason: "unmapped" | "protection" | "guard-page" | "access-violation"; at: Hex };
  bea_guard_suspended: Hex[];                  // BEA guard pages temporarily unguarded for this read
}
export interface TypedRead { address: Hex; type: ValueType; count?: number; chain?: number[]; max_len?: number }
export interface ReadTypedParams { reads: TypedRead[] }
export interface ReadTypedResult {
  results: ({ ok: true; final_address: Hex; path: Hex[]; value: TypedOut | TypedOut[] }
          | { ok: false; error: AgentError; path: Hex[] })[];
}
export interface WriteMemoryParams {
  address: Hex; mode: "data" | "code";
  bytes?: HexBytes; typed?: { type: ValueType; values: ScalarInput[] };
  expect_before?: HexBytes; allow_protect_change: boolean;
}
export interface WriteResult {
  write_id: WriteId; address: Hex; size: number; before: HexBytes; after: HexBytes; verified: boolean;
  method: "direct" | "protect-and-restore" | "patchCode"; protection_before: string | null; protection_after: string | null;
  effect: EffectHint;
}
export interface RevertWriteParams { write_id: WriteId; force: boolean }
export interface RevertWriteResult { write_id: WriteId; reverted: boolean; current_before_revert: HexBytes; after: HexBytes }

// ---- disassembly
export interface DisassembleParams {
  address: Hex; mode: "count" | "function" | "range"; count?: number; size?: number;
  original_bytes: boolean; operands: boolean; cfg: boolean;
}
export interface InsnRow {
  address: Hex; size: number; bytes: HexBytes; mnemonic: string; op_str: string; groups: string[];
  branch_target: Hex | null; mem_targets: Hex[]; overlay: boolean;
  regs_read?: string[]; regs_written?: string[];
}
export interface CfgBlock { start: Hex; end: Hex; successors: Hex[] }
export interface DisassembleResult {
  start: Hex; function: FunctionRange | null; instructions: InsnRow[]; truncated: boolean;
  overlay_used: boolean; stop: null | { reason: "decode-error" | "access-violation" | "limit"; at: Hex };
  blocks: CfgBlock[] | null;
}

// ---- scans
export type ScanValueType = "i8" | "u8" | "i16" | "u16" | "i32" | "u32" | "i64" | "u64" | "f32" | "f64" | "ptr" | "bytes" | "utf8" | "utf16";
export interface RegionFilter {
  protection: string;                          // Frida protection filter, e.g. "rw-"
  modules?: string[]; exclude_modules?: string[]; private_only?: boolean;
  min?: Hex; max?: Hex; max_region_bytes?: number;
}
export interface ScanStartParams {
  kind: "value" | "pattern" | "unknown" | "pointers-to";
  value_type?: ScanValueType;
  compare?: { op: "eq" | "approx" | "range" | "gt" | "lt"; value?: ScalarInput; min?: ScalarInput; max?: ScalarInput; eps?: number; text?: string; bytes?: HexBytes };
  pattern?: string;                            // kind "pattern": exact, "??", nibble "4?", ": mask" forms; "/regex/" refused
  targets?: Hex[];                             // kind "pointers-to" (≤ 16)
  regions: RegionFilter;
  align?: 1 | 2 | 4 | 8;
  max_candidates?: number;
  label?: string;
}
export type ScanNextOp =
  | "eq" | "ne" | "approx" | "gt" | "lt" | "range" | "changed" | "unchanged"
  | "increased" | "decreased" | "increased_by" | "decreased_by" | "same_as_first";
export interface ScanNextParams { scan_id: ScanId; op: ScanNextOp; value?: ScalarInput; min?: ScalarInput; max?: ScalarInput; eps?: number }
export interface ScanStartResult { scan_id: ScanId; job_id: JobId }
export interface ScanNextResult { scan_id: ScanId; job_id: JobId }
export interface ScanStatus {
  scan_id: ScanId; label: string | null; state: "running" | "ready" | "failed" | "closed";
  mode: "explicit" | "snapshot"; value_type: ScanValueType; count: number;
  ops: { op: string; count_after: number; t: TimeUs }[];
  bytes_scanned: number; regions: number; unreadable_regions: number; faulted_candidates_dropped: number;
  job: JobId | null; memory_bytes: number; error: AgentError | null;
}
export interface ScanResultsParams { scan_id: ScanId; offset: number; limit: number; read_current: boolean }
export interface ScanHit { address: Hex; stored: TypedOut; current?: TypedOut | { error: AgentError } }
export interface ScanCloseParams { scan_id: ScanId }

// ---- jobs
export interface JobInfo {
  job_id: JobId; kind: JobKind; state: "queued" | "running" | "done" | "failed" | "cancelled";
  progress: Progress; started_t: TimeUs; ended_t: TimeUs | null; error: AgentError | null;
}
export interface JobStatusParams { job_id: JobId }
export interface JobCancelParams { job_id: JobId }

// ---- hooks
export interface ArgCapture {
  name?: string;                               // ≤ 32 chars
  slot: number;                                // Win64 positional parameter index 0..15 (after hidden_ret_ptr shift)
  class: "int" | "float";                      // slots 0..3: int → rcx/rdx/r8/r9, float → xmm0..3; ≥4: stack
  type: ValueType;                             // slot value type, or the final type after deref
  deref?: number[];                            // pointer chain offsets (≤ max_deref_depth); last = field offset
  count?: number;                              // array length at the final address (≤ 64)
  max_len?: number;                            // strings (chars) / bytes
  at?: "enter" | "leave";                      // default "enter"; "leave" reads out-params after the call
}
export interface RetCapture { type: ValueType; deref?: number[]; count?: number; max_len?: number }
export interface HookInstallParams {
  target: TargetRef;
  engine: "js" | "native";
  relocation: "auto" | "forced";
  capture: {
    args: ArgCapture[];
    ret: RetCapture | null;
    backtrace: { depth: number; max_per_sec: number } | null;   // js engine only; frames as FrameRef ("mod+0xrva")
    registers: "none" | "gpr";                                   // js engine only
  };
  emit: "enter" | "leave";
  hidden_ret_ptr: boolean;
  filter?: { thread_ids?: ThreadId[]; caller_modules?: string[] };
  sample?: { every_n?: number; max_per_sec?: number };
  lifetime: Lifetime;
  observe_agent_calls: boolean;
  force_caution: boolean;
  label?: string;
}
export interface HookInstallResult {
  instrument_id: InstrumentId; stream_id: StreamId; row_kind: "hook/1" | "hook-native/1"; layout: BinaryLayout | null;
  resolved: ResolvedTarget; thunk: { kind: "jmp-rip" | "jmp-rel"; to: Hex } | null; patched_at: Hex[];
  relocation: "default" | "forced"; stalker_invalidated: ThreadId[]; arg_map: { slot: number; source: string }[];
  effect: EffectHint;
}

// ---- API profiles (catalog in apiProfiles.ts)
export type ApiProfileName = "file" | "registry" | "network" | "process" | "module" | "memory";
export interface ProfileOptions {
  thread_ids?: ThreadId[];
  per_api_max_events?: number;                 // default limits.profile_events_per_api
  dedupe_window_ms?: number;                   // 0 = off; identical (api, args, ret) within the window → repeat count
  file?: { io: boolean; capture_bytes: number; track_handles: boolean };
  registry?: { capture_value_bytes: number; query_key: boolean; enumerate: boolean };
  network?: { capture_payload_bytes: number; http: boolean; dns: boolean };
  process?: { cross_process_memory: boolean; apc_and_context: boolean };
  module?: { resolve_procedures: boolean };
  memory?: { frees: boolean; sections: boolean; exec_region_scan_ms: number };
}
export interface ProfileInstallParams { profiles: ApiProfileName[]; options: ProfileOptions; lifetime: Lifetime; label?: string }
export interface ProfileInstallResult {
  instrument_id: InstrumentId; stream_id: StreamId; row_kind: "api/1"; catalog_minor: number;
  installed: { api_id: number; api: string; va: Hex }[];
  pending: { api: string; module: string }[];                   // module not loaded yet; installed on load
  denied: { api: string; reason: string }[];
  failed: { api: string; error: AgentError }[];
  memmap_stream: StreamId | null;
  effect: EffectHint;
}

// ---- watches
export interface WatchInstallParams {
  method: "debug-register" | "page-guard";
  address: Hex;
  size: number;                                // debug-register: 1|2|4|8 (aligned); page-guard: 1..65536
  access: "write" | "read-write" | "execute";  // DR "r" ≡ "rw" in hardware [ext-frida §3.9]: no read-only option
  slot?: 0 | 1 | 2 | 3;
  threads: "all" | ThreadId[];
  capture: { registers: "none" | "gpr"; backtrace: number; values: boolean };
  engine?: "trap-flag" | "access-monitor";      // page-guard only: default trap-flag (§11.3); access-monitor = MemoryAccessMonitor fallback (§11.3.1)
  lifetime: Lifetime;
  label?: string;
}
export interface WatchInstallResult {
  instrument_id: InstrumentId; stream_id: StreamId; method: "debug-register" | "page-guard";
  slot: number | null; pages: Hex[] | null; armed_threads: number; arm_errors: { tid: ThreadId; message: string }[];
  verified: { threads_checked: number; ok: number } | null; initial_value: HexBytes | null; effect: EffectHint;
}
export interface DebugRegisterStateParams { thread_ids?: ThreadId[] }
export interface DebugRegisterStateResult {
  threads: { tid: ThreadId; dr: [Hex, Hex, Hex, Hex]; dr7: Hex; error: string | null }[];
  slots: { slot: number; owner: InstrumentId | "quarantined" | null; kind: "watch" | "exec" | null; address: Hex | null }[];
}

// ---- Stalker
export interface TraceStartParams {
  threads: ThreadId[];                          // 1..stalker_max_threads; never the agent thread
  mode: "coverage" | "block_counts" | "call_summary" | "call_events";
  modules: string[];                            // blocks recorded/counted only inside these (default: [main module])
  exclude_modules: string[];                    // Stalker.exclude for speed
  lifetime: Lifetime;                           // max_hits = max rows/events
  queue?: { capacity: number; drain_ms: number };
  label?: string;
}
export interface TraceStartResult {
  instrument_id: InstrumentId; stream_id: StreamId;
  row_kind: "block-span/1" | "block-count/1" | "call-site-count/1" | "gum-event-x64/1";
  layout: BinaryLayout; threads: ThreadId[]; queue: { capacity: number; drain_ms: number };
  excluded: { module: string; base: Hex; size: number }[]; effect: EffectHint;
}

// ---- overrides
export interface OverrideInstallParams {
  target: TargetRef;
  relocation: "auto" | "forced";
  mode: "rewrite" | "replace";
  rewrite?: {
    args?: { slot: number; class: "int" | "float"; type: ValueType; value: ScalarInput }[];
    ret?: { type: ValueType; value: ScalarInput };
  };
  replace?: { ret_type: ValueType | "void"; arg_types: ValueType[]; returns: ScalarInput | null };
  when?: { thread_ids?: ThreadId[]; every_n?: number };
  lifetime: Lifetime;
  record: boolean;                              // emit override/1 rows
  label?: string;
}
export interface OverrideInstallResult {
  instrument_id: InstrumentId; stream_id: StreamId | null; resolved: ResolvedTarget; mode: "rewrite" | "replace";
  relocation: "default" | "forced"; stalker_invalidated: ThreadId[]; effect: EffectHint;
}

// ---- instruments (generic stop/list)
export interface InstrumentStopParams { id: InstrumentId | "all"; final_flush: boolean }
export interface InstrumentStopResult { stopped: InstrumentSummary[]; not_found: string[]; unreverted: { id: InstrumentId; detail: string }[] }
export interface InstrumentListResult { instruments: InstrumentInfo[] }

// ---- calls
export type CallType = ValueType | "void";
export interface BufferSpec {
  name: string; size: number; align?: number;
  init: { kind: "zero" } | { kind: "hex"; hex: HexBytes } | { kind: "copy"; from: Hex; size?: number };
  read_back: boolean;
}
export type CallArgValue =
  | number | string | boolean | { bits: Hex } | { ptr: Hex } | { buf: string; offset?: number }
  | { utf8: string } | { utf16: string } | null;
export interface CallFunctionParams {
  target: TargetRef;
  signature: { ret: CallType; args: CallType[] };
  vectors: CallArgValue[][];                    // 1..call_max_vectors
  start_index: number;                          // continuation (0 first)
  thread: { kind: "agent" } | { kind: "thread"; tid: ThreadId; timeout_ms: number };
  scheduling: "cooperative" | "exclusive";
  buffers: BufferSpec[];
  reset_buffers: "per-vector" | "never";
  coverage: { mode: "none" | "blocks"; modules: string[]; max_blocks: number };
  max_wall_ms: number;
  hooks: "suppress" | "observe";                // BEA hook/profile rows caused by this call
  overrides: "apply" | "bypass";
}
export interface FaultInfo {
  type: ExceptionType; address: Hex; memory: { operation: "read" | "write" | "execute"; address: Hex } | null;
  registers: Record<string, Hex>;
}
export interface CallVectorResult {
  index: number; status: "returned" | "fault"; ret: TypedOut | null; fault: FaultInfo | null;
  buffers: Record<string, HexBytes> | null; wall_us: number;
  coverage: { blocks: [Hex, number][]; truncated: boolean } | null;   // [start, size]
}
export interface CallFunctionResult {
  completed: number; next_index: number | null; thread_id: ThreadId; results: CallVectorResult[];
  resolved: ResolvedTarget;
  perturbation: { target_instruments: InstrumentId[]; overrides_bypassed: boolean; hooks_suppressed: number };
  effect: EffectHint;
}

// ---- dumps
export type DumpItem =
  | { kind: "module"; module: string }
  | { kind: "range"; base: Hex; size: number }
  | { kind: "ranges"; filter: RegionFilter; max_total_bytes: number }
  | { kind: "thread"; tid: ThreadId; stack_bytes: number; teb: boolean; tls: boolean; xmm: boolean };
export interface DumpStartParams { items: DumpItem[]; suspend: "none" | "all"; chunk_bytes?: number; max_total_bytes: number }
export interface DumpStartResult { job_id: JobId; planned_bytes: number; planned_blobs: number }
export interface DumpRegion {
  blob: BlobId; kind: "module" | "range" | "stack" | "teb" | "peb" | "tls";
  base: Hex; size: number; protection: string; module: string | null;
  holes: { offset: number; size: number; reason: "unreadable" | "guard-page" }[];
  sha256: Hex | null;
}
export interface ThreadState {
  tid: ThreadId; registers: Record<string, Hex>; eflags: Hex; mxcsr: Hex; fpcw: Hex; xmm: Hex[] | null;
  teb: Hex | null; peb: Hex | null; stack: { base: Hex; limit: Hex } | null;
  tls: { static_tls_array: Hex | null; tls_slots: Hex[] } | null;
}
export interface DumpManifest {
  format: "bea-dump/1"; pid: number; taken: { t0: TimeUs; t1: TimeUs; suspended: boolean };
  modules: { name: string; path: string; base: Hex; size: number; blob: BlobId | null }[];
  regions: DumpRegion[]; threads: ThreadState[]; module_map_epoch: number; truncated: boolean;
}
export interface CaptureThreadStateParams { tid: ThreadId; xmm: boolean; teb: boolean; tls: boolean }

/* ------------------------------------------------------------------------------------------------
 * 4.10 The RPC method map (single source of truth for both sides)
 * ---------------------------------------------------------------------------------------------- */
type NoParams = Record<string, never>;
export interface AgentRpcMethods {
  // core
  hello: { params: HelloParams; result: HelloResult };
  ping: { params: NoParams; result: PingResult };
  status: { params: StatusParams; result: AgentStatus };
  flush: { params: FlushParams; result: FlushResult };
  shutdown: { params: ShutdownParams; result: ShutdownResult };
  fingerprint: { params: NoParams; result: Fingerprint };
  // inspection
  processInfo: { params: NoParams; result: ProcessInfo };
  listModules: { params: ListModulesParams; result: ListModulesResult };
  listExports: { params: ListExportsParams; result: Paged<ExportRow> };
  listImports: { params: ListImportsParams; result: Paged<ImportRow> };
  listSections: { params: ListSectionsParams; result: { sections: SectionRow[] } };
  listFunctions: { params: ListFunctionsParams; result: Paged<FunctionRow> };
  findFunction: { params: FindFunctionParams; result: FunctionRange | null };
  listRanges: { params: ListRangesParams; result: ListRangesResult };
  listThreads: { params: ListThreadsParams; result: ListThreadsResult };
  resolveTargets: { params: ResolveTargetsParams; result: ResolveTargetsResult };
  describeAddresses: { params: DescribeAddressesParams; result: DescribeAddressesResult };
  // memory + code
  readMemory: { params: ReadMemoryParams; result: ReadMemoryMeta; binary: true };
  readTyped: { params: ReadTypedParams; result: ReadTypedResult };
  writeMemory: { params: WriteMemoryParams; result: WriteResult };            // gate write_memory
  revertWrite: { params: RevertWriteParams; result: RevertWriteResult };
  disassemble: { params: DisassembleParams; result: DisassembleResult };
  // scans + jobs
  scanStart: { params: ScanStartParams; result: ScanStartResult };
  scanNext: { params: ScanNextParams; result: ScanNextResult };
  scanStatus: { params: { scan_id: ScanId }; result: ScanStatus };
  scanResults: { params: ScanResultsParams; result: Paged<ScanHit> };
  scanClose: { params: ScanCloseParams; result: { closed: true; freed_bytes: number } };
  jobStatus: { params: JobStatusParams; result: JobInfo };
  jobCancel: { params: JobCancelParams; result: JobInfo };
  // instruments
  hookInstall: { params: HookInstallParams; result: HookInstallResult };
  profileInstall: { params: ProfileInstallParams; result: ProfileInstallResult };
  watchInstall: { params: WatchInstallParams; result: WatchInstallResult };
  traceStart: { params: TraceStartParams; result: TraceStartResult };
  overrideInstall: { params: OverrideInstallParams; result: OverrideInstallResult }; // gate override_function
  instrumentStop: { params: InstrumentStopParams; result: InstrumentStopResult };
  instrumentList: { params: NoParams; result: InstrumentListResult };
  debugRegisterState: { params: DebugRegisterStateParams; result: DebugRegisterStateResult };
  // execution + capture
  callFunction: { params: CallFunctionParams; result: CallFunctionResult };     // gate call_function
  dumpStart: { params: DumpStartParams; result: DumpStartResult };
  captureThreadState: { params: CaptureThreadStateParams; result: ThreadState };
}
export type AgentMethodName = keyof AgentRpcMethods;
export type AgentParams<K extends AgentMethodName> = AgentRpcMethods[K]["params"];
export type AgentValue<K extends AgentMethodName> = AgentRpcMethods[K]["result"];
export type IsBinary<K extends AgentMethodName> = AgentRpcMethods[K] extends { binary: true } ? true : false;
/** What the agent's rpc.exports[K] returns (sync or Promise). */
export type AgentReply<K extends AgentMethodName> =
  IsBinary<K> extends true ? [AgentResult<AgentValue<K>>, ArrayBuffer] | AgentResult<never> : AgentResult<AgentValue<K>>;
export type AgentRpcImpl = { [K in AgentMethodName]: (p: AgentParams<K>) => AgentReply<K> | Promise<AgentReply<K>> };
export const PRE_HELLO_METHODS: readonly AgentMethodName[] = ["hello", "ping", "processInfo"] as const;
export const GATED_METHODS: Readonly<Partial<Record<AgentMethodName, GateName>>> = {
  writeMemory: "write_memory", revertWrite: "write_memory", overrideInstall: "override_function", callFunction: "call_function",
};
```

**Count.** 39 RPC methods and 10 message kinds. Each MCP tool maps onto one or more methods; for example,
`watch_memory` maps to `watchInstall` + `instrumentStop` + the stream.

### 4.11 Agent error → host wire code (`src/frida/agentErrorMap.ts`, exhaustive with `satisfies`)

| AgentError `_tag` | Host code | Retryable | Recovery / remediation hint |
|---|---|---|---|
| BadParams | invalid_request | no | inspect_input_contract (host-side validation should have caught it, so this is a contract bug) |
| NotReady | execution_failure | yes | reattach (the host must send `hello` first) |
| ProtocolMismatch | capability_unavailable | no | rebuild or reinstall BEA (agent/host skew) |
| ShuttingDown | capability_unavailable | no | the session is closing |
| GateClosed | capability_unavailable | no | names the gate and its config switch |
| AccessViolation, GuardPage | memory_access_failed | no | `details.partial_bytes` when present |
| ModuleNotFound | address_unmapped | after refresh | refresh_module_map |
| ExportNotFound, NoFunctionRange, NotExecutable, WatchInvalid | invalid_request | no | inspect_input_contract |
| HookDenied, HookInstallFailed, HookConflict, NoFreeDebugRegister | instrumentation_failed | no | `alternatives[]` carried in `details` |
| StalkerBusy | resource_constraint | yes | `retry_after_ms` |
| NotFound | invalid_request (`session_not_found` when `what` is an instrument of a closed session) | no | — |
| WriteConflict | effect_unreverted | yes | revert_effects |
| Timeout | provider_timeout | yes | inspect_timeout_state |
| Cancelled | cancelled | yes | — |
| ResourceLimit | resource_constraint | capacity: yes | `details.resource`, `limit` |
| Unsupported | unsupported_target | no | — |
| Internal | execution_failure | no | `details.where` (never raw Frida text in `message` [rea-evidence §2.4]) |

Transport errors on the host side:
- `"Script is destroyed"` maps to `target_exited` if the session detached with `process-terminated`, and to
  `capability_unavailable` otherwise.
- `"unable to find method"` maps to `capability_unavailable` (protocol skew).
- `"Operation was cancelled"` maps to `cancelled`.
- A deadline with no reply maps to `provider_timeout`. The host then marks the session `agent_unresponsive` (§13.6).

---

## 5. Core runtime

### 5.1 `state.ts`: the AgentCore singleton (internal, not wire)

```ts
export type Phase = "loaded" | "ready" | "shutting-down";
export interface AgentCore {
  readonly t0Wall: number;                  // Date.now() at load
  readonly jsTid: ThreadId;                 // Process.getCurrentThreadId() at top level (cloaked, F2)
  phase: Phase;
  bootStage: FatalMessage["stage"];
  features: AgentFeature[];
  early: ReadyMessage["early"];
  config: EffectiveConfig;                  // defaults until hello; then hello params clamped to AGENT_LIMIT_HARD
  native: NativeCore;                       // §5.4
  win: Win32;                               // §5.5
  streams: StreamRegistry;                  // §6
  instruments: InstrumentRegistry;          // §5.7
  jobs: JobRunner;                          // §5.8
  modules: ModuleIndex;                     // §8.1
  threads: ThreadService;                   // §5.6
  originals: OriginalBytes;                 // §8.4
  stalkerCo: StalkerCoordinator;            // §12.1
  keep: KeepAlive;                          // pins CModules/NativeCallbacks; delayed release (§12.4)
  counters: { exceptions: Partial<Record<ExceptionType, number>>; beaTraps: number; faults: number; rpcCalls: number };
  agentCallTids: Map<ThreadId, number>;     // threads currently running a BEA-initiated call (depth), §13.4
  fault(where: string, e: unknown): void;   // rate-limited FaultMessage (≤ 10/s, coalesced counts)
}
export interface EffectiveConfig {
  session: HelloParams["session"] | null; gates: Record<GateName, boolean>; limits: AgentLimits;
  crash: CrashPolicy; streams: HelloParams["streams"]; flow: HelloParams["flow"];
}
```

### 5.2 `rpc.ts`: the wrapper that every method passes through

```ts
export function wrapAll(c: AgentCore, impl: AgentRpcImpl): Record<string, (p: unknown) => unknown> {
  const out: Record<string, (p: unknown) => unknown> = {};
  for (const name of Object.keys(impl) as AgentMethodName[]) out[name] = wrapOne(c, name, impl[name] as any);
  return out;
}
function wrapOne(c: AgentCore, name: AgentMethodName, fn: (p: any) => any) {
  const gate = GATED_METHODS[name];
  return (params: unknown) => {
    c.counters.rpcCalls++;
    if (c.phase === "shutting-down" && name !== "status" && name !== "ping")
      return err({ _tag: "ShuttingDown", message: "agent is shutting down" });
    if (c.phase === "loaded" && !PRE_HELLO_METHODS.includes(name))
      return err({ _tag: "NotReady", message: "hello() must be called first" });
    if (gate && !c.config.gates[gate])
      return err({ _tag: "GateClosed", gate, message: `gate ${gate} is closed for this session` });
    const t0 = c.native.nowUs();
    try {
      const r = fn(params ?? {});
      if (r instanceof Promise)
        return r.catch((e) => err(mapThrown(e, name))).finally(() => noteTiming(c, name, t0));
      noteTiming(c, name, t0);
      return r;                                        // AgentResult | [AgentResult, ArrayBuffer]
    } catch (e) {
      noteTiming(c, name, t0);
      return err(mapThrown(e, name));
    }
  };
}
```

- **Params validation.** The host validates with zod, so the agent does structural checks only: required fields,
  numeric bounds against `limits`, enum membership. A failure is `BadParams{issues}`. The agent clamps to
  `AGENT_LIMIT_HARD` itself, so a host bug cannot drive it past a hard cap.
- **`mapThrown(e, where)`** (`errors.ts`). Frida error text maps to tags, matching on case-insensitive regexes:

| Pattern | Tag | Source |
|---|---|---|
| `/access violation accessing (0x[0-9a-f]+)/` | `AccessViolation{address}` | [ext-frida §3.3] |
| `/unable to intercept function/` | `HookInstallFailed` | [ext-frida §3.6] |
| `/already replaced this function/` | `HookConflict` | [ext-frida §3.6] |
| `/unable to find module '(.+)'/` | `ModuleNotFound` | [ext-frida §3.1] |
| `/unable to find (?:global )?export '(.+)'/` | `ExportNotFound` | [ext-frida §3.1] |
| `/invalid match pattern/` | `BadParams` | [ext-frida §3.4] |
| a stolen NativeFunction exception (`e.type` present) | `AccessViolation` / … | [ext-frida §3.7] |
| anything else | `Internal{where, frida_message}` | — |

  For `Internal`, `frida_message` is truncated to 512 chars. The **host** never puts it in the curated `message`
  [rea-evidence §2.4].

### 5.3 `encode.ts`

```ts
export const hex = (p: NativePointer | UInt64 | Int64 | number): Hex;        // canonical lowercase "0x…" (two's complement for negatives)
export const hexBytes = (ab: ArrayBuffer, off?: number, len?: number): HexBytes;
export const f32Bits = (ab16: ArrayBuffer): Hex;   // new Uint32Array(ab16, 0, 1)[0] → Hex (exact; from xmmN)
export const f64Bits = (ab16: ArrayBuffer): Hex;   // two u32 lanes → 16-digit Hex (exact)
export function scalarToNative(v: ScalarInput, t: ValueType): number | Int64 | UInt64 | NativePointer | boolean;
export function floatOut(t: "f32" | "f64", bits: Hex): TypedOut; // value: number | "NaN" | "Infinity" | "-Infinity"
```

Float rules:
- Floats read from `xmmN` are captured as **bits straight from the 16-byte ArrayBuffer** and never round-tripped
  through a JS number. That makes them exact, including NaN payloads.
- Floats passed **into** `NativeFunction` go through a JS number, so NaN payload bits may be canonicalized
  (assumption A-9, §20). Every other float value is exact.

### 5.4 `native/core.ts`: the core CModule (one per agent, pinned forever)

JS allocates the externs (`Memory.alloc`) and passes them in the CModule's second argument [ext-frida §3.15]. The core
CModule provides the following. The C below is a specification and the implementer types it in verbatim.

```c
#include <gum/guminterceptor.h>
#include <gum/gumstalker.h>
#include <glib.h>
#include <string.h>

typedef gboolean (*BeaQpc) (gint64 *);              /* kernelbase!QueryPerformanceCounter, passed as extern pointer */
extern BeaQpc bea_qpc;  extern gint64 bea_qpc0;  extern double bea_us_per_tick;
extern volatile gint64 bea_gseq;                     /* global event sequence, shared by JS and native producers */

double bea_next_g (void)  { return (double) (g_atomic_pointer_add (&bea_gseq, 1) + 1); }
double bea_now_us (void)  { gint64 t; bea_qpc (&t); return (double) (t - bea_qpc0) * bea_us_per_tick; }

/* ---- native hook tier: one BeaNativeHook per native hook; record layout hook-native/1 (160 B) ---- */
typedef struct {
  guint32 hook_index; guint32 flags;                 /* flags bit0: emit at enter */
  volatile gint64 * head; guint8 * ring; guint64 mask;
  volatile gint64 hits; gint64 max_hits; guint32 every_n;
  volatile gint32 active; guint32 nthreads; guint32 threads[16];
} BeaNativeHook;
typedef struct { guint64 g, t, w[4], x[4], s[4], ret; guint32 depth; } BeaInv;
void bea_hn_enter (GumInvocationContext * ic);       /* captures rcx,rdx,r8,r9, xmm0..3 low 8 B (if available), */
void bea_hn_leave (GumInvocationContext * ic);       /* nth_argument(4..7), return address, depth; leave adds rax, xmm0 */
guint64 bea_ring_collect (BeaNativeHook * h, gint64 * tail, guint8 * out, guint64 max_records,
                          volatile gint64 * overrun, volatile gint64 * torn);
                                                     /* copies committed records [tail, head) into out, zeroes their
                                                        commit words, advances *tail; counts overrun/torn */
/* ---- scan kernels (§9.4); all called via NativeFunction(…, {exceptions:'steal', scheduling:'exclusive'}) ---- */
guint64 bea_scan_cmp (const guint8 * p, guint64 len, guint32 vt, guint32 align, guint32 op, guint64 a, guint64 b,
                      double eps, guint64 * out_off, guint64 out_cap, volatile guint64 * progress);
guint64 bea_scan_next (guint64 * addrs, guint8 * vals, const guint8 * firsts, guint64 n, guint32 vt, guint32 op,
                       guint64 a, guint64 b, double eps, volatile guint64 * progress, volatile guint64 * kept);
guint64 bea_scan_snap (const guint8 * va, const guint8 * snap, guint64 len, guint32 vt, guint32 align, guint32 op,
                       guint64 a, guint64 b, double eps, guint64 * out_addrs, guint8 * out_vals, guint64 cap,
                       volatile guint64 * progress);
/* ---- Stalker block_counts / call_summary transforms (§12.3) ---- */
void bea_bc_transform (GumStalkerIterator * it, GumStalkerOutput * out, gpointer user_data);
void bea_cs_transform (GumStalkerIterator * it, GumStalkerOutput * out, gpointer user_data);
```

Notes:
- **Multi-producer rings.** The ring index comes from `g_atomic_pointer_add` on the head, and each record's commit
  word is written last. x86-64 store ordering (TSO) makes the commit word a valid publication flag. Atomics, invocation
  data and function data compiled and attached [S4-lab F18]. Delivery under contention is assumption A-6.
- **Clock.** QPC is reached through an extern function pointer, so the CModule does not depend on GLib time symbols
  being exported to TinyCC (A-7). `bea_now_us` uses the same clock as the host-side `t` decode.
- **JS access.** JS reaches `bea_next_g` and `bea_now_us` through `NativeFunction(…, 'double', [], {scheduling:'exclusive'})`.
  Exclusive scheduling skips the lock release, and a `double` return avoids `Int64` objects. Expected cost is about
  0.2–0.5 µs per call (A-8). JS rows call both once per row.
- **Feature probe.** A second, tiny CModule probe at boot compiles `offsetof(GumCpuContext, xmm)`. Success enables the
  feature `hooks.native.xmm`. Without it, native hooks refuse float-class captures with
  `Unsupported{feature:"native-xmm"}` and the JS tier is the alternative.
- **TEB stub.** `Memory.alloc(Process.pageSize, {protection:'rwx'})` (VERIFIED [ext-frida §3.5]) holds the bytes
  `65 48 8B 04 25 30 00 00 00 C3` (`mov rax, gs:[0x30]; ret`). `NativeFunction(stub, 'pointer', [], {scheduling:'exclusive'})`
  returns the **current thread's** TEB, which is used in hooks and `runOnThread`. `TEB+0x60` is the PEB.
- **Lifetime.** Every CModule, `NativeCallback` and extern cell is pushed onto `core.keep` and released only after its
  last user is gone (Stalker rule §12.4). The core CModule itself is never released [ext-frida §3.8 lifetime crash].

### 5.5 `win32.ts`: native bindings (created lazily, cached, explicit scheduling)

| Binding | Module!export | Signature | Scheduling | Used by |
|---|---|---|---|---|
| CreateEventW / SetEvent / CloseHandle | kernelbase | `pointer(pointer,int,int,pointer)` / `int(pointer)` / `int(pointer)` | exclusive | ack |
| WaitForSingleObject | kernelbase | `uint32(pointer,uint32)` | **cooperative** (must release the JS lock; F12) | ack |
| OpenThread | kernelbase | `pointer(uint32,int,uint32)` | exclusive | threads, hwbp |
| SuspendThread / ResumeThread | kernelbase | `uint32(pointer)` | **exclusive** [ext-frida §3.7, a6e] | threads, hwbp verify, dump |
| GetThreadContext | kernelbase | `int(pointer,pointer)` | exclusive | hwbp verify, captureThreadState |
| NtQueryInformationThread | ntdll | `uint32(pointer,uint32,pointer,uint32,pointer)` | exclusive | TEB lookup (class 0) |
| GetThreadDescription | kernelbase | `int32(pointer,pointer)` (HRESULT, out PWSTR; free with LocalFree) | exclusive | thread names (optional) |
| VirtualQuery | kernelbase | `size_t(pointer,pointer,size_t)` | exclusive | guard-page-aware reads |
| VirtualProtect | kernelbase | `int(pointer,size_t,uint32,pointer)` | exclusive | page-guard arm/re-arm/disarm, writes |
| NtQueryKey | ntdll | `uint32(pointer,uint32,pointer,uint32,pointer)` | exclusive | registry root names (F10) |
| QueryPerformanceCounter / Frequency | kernelbase | pointers passed to the CModule | — | clock |

All handles opened here are closed in `finally` blocks. OpenThread access masks:
- verify: `THREAD_GET_CONTEXT 0x8 | THREAD_SUSPEND_RESUME 0x2 | THREAD_QUERY_LIMITED_INFORMATION 0x800`;
- TEB: `0x800` only.

### 5.6 `threads.ts`

- `enumerate()` wraps `Process.enumerateThreads()`. Frida's own threads are cloaked [ext-frida §3.13]. The agent JS
  thread is cloaked too (F2) and never armed, followed or reported.
- `teb(tid)` calls `NtQueryInformationThread(h, ThreadBasicInformation=0, buf, 0x30, NULL)` and reads
  `TebBaseAddress` at `+0x8` (A-10). `stack(tid)` reads `NT_TIB.StackBase` (`TEB+0x8`) and `StackLimit` (`TEB+0x10`).
- `context(tid, flags)`: OpenThread → SuspendThread → `ContextFlags = flags` at `+0x30` in a 16-byte-aligned
  `Memory.alloc(0x500)` → GetThreadContext → ResumeThread. All exclusive. This is VERIFIED for the debug registers
  [ext-frida §3.9 a6e]. Flags: `CONTEXT_AMD64 0x100000 | CONTROL 1 | INTEGER 2 | SEGMENTS 4 | FLOATING_POINT 8 | DEBUG_REGISTERS 0x10`.
- **CONTEXT x64 offsets.**
  - VERIFIED: `ContextFlags +0x30`, `MxCsr +0x34`, `EFlags +0x44`, `Dr0..3 +0x48..+0x60`, `Dr6 +0x68`, `Dr7 +0x70`,
    `Rax +0x78`, `Rsp +0x98`, `Rip +0xF8`, `FltSave.ControlWord +0x100` [ext-frida §3.9; S4-lab F13].
  - BELIEVED (winnt.h; A-11): `Rcx +0x80, Rdx +0x88, Rbx +0x90, Rbp +0xA0, Rsi +0xA8, Rdi +0xB0, R8..R15 +0xB8..+0xF0, FltSave.MxCsr +0x118, Xmm0..15 +0x1A0 (16 B each)`.
- Thread observer: `Process.attachThreadObserver` is attached lazily. It is needed when the `s:threads` stream is
  enabled or any debug-register slot is armed. `onAdded` runs **on the new thread** and also fires for existing threads
  at attach [ext-frida §3.9, §3.13]. It emits `thread/1` rows and calls `hwbp.onThreadAdded(t)`; `onRemoved` emits
  exit rows.

### 5.7 `instruments.ts`: registry, lifetimes, stop protocol

- Ids are `h|p|w|t|o` plus a counter that is never reused within an agent's lifetime.
- `duration_ms` is clamped to `limits.max_duration_ms` (1 h) and `max_hits` to `limits.max_hits_cap`.
- The host always sends explicit lifetimes (the BRIEF rule "every instrument bounded"). The agent applies its own
  defaults only when a field is 0: 30 s, and 10,000 hits (hooks) / 1,000 (watches).
- **Deadline.** `setTimeout(() => stop(id, "duration"), duration_ms)`.
- **max_hits.**
  - JS tier: the listener increments `hits`. When it exceeds the limit, the listener sets `state='stopping'`
    synchronously (the detached guard) and schedules `stop(id,"max_hits")` with `setImmediate`. Listeners are never
    detached from inside their own callback.
  - Native tier: the C listener clears `active`, and the next drain stops the instrument.
- **`stop(id, reason)`**, in this order:
  1. Set `state='stopping'`. From here every callback returns at its first line (late callbacks happen [ext-frida §3.6]).
  2. Kind-specific revert:
     - hook / profile / override: `listener.detach()` for each, or `Interceptor.revert` for replace mode.
     - watch: hwbp disarm protocol (§11.2) or page-guard disarm (§11.3).
     - trace: unfollow protocol (§12.4).
  3. `Interceptor.flush()`.
  4. `stalkerCo.invalidateAll(addresses)` (§12.1).
  5. Verify the revert. Patches: the bytes at each patch site equal `originals`. DR7: §11.2. Guard: `VirtualQuery`
     shows no `PAGE_GUARD`.
  6. Wait one `setImmediate` tick, then emit the final batch (`final:true`) and `{bea:"instrument", event:"ended", detail:summary}`.
  7. Drop the instrument's native memory after `keep` settles.

  A failed verification sets `summary.reverted=false` and `verification.ok=false`. The host maps that to
  `effect_unreverted`. The instrument stays listed until shutdown.
- **Module unload.** `modules` `onRemoved` stops every instrument whose patch site lies inside the unloaded module,
  with `reason:"module-unloaded"`. The detach is wrapped in try/catch, and a failure is recorded as `reverted:false`
  with detail `"code unmapped"` (A-12).

### 5.8 `jobs.ts`: sliced background work

```ts
interface Job {
  id: JobId; kind: JobKind; state: JobInfo["state"]; progress: Progress;
  step(budgetMs: number): "more" | "done";     // does ≤ budget of work, updates progress
  cancel: boolean; result?: ScanStatus | DumpManifest; error?: AgentError; startedT: TimeUs; endedT: TimeUs | null;
}
```

- The runner keeps at most `limits.max_jobs` (8) jobs and runs one slice at a time. Slices go round-robin across
  running jobs, each with a budget of `limits.job_slice_ms` (8 ms; QJS `Date.now()` granularity is 1 ms). After every
  slice the runner yields with `setImmediate`, so queued RPCs and the flush timer run between slices.
- Cancellation is checked before each slice.
- Completion sends `{bea:"job", …}` exactly once.
- `jobStatus` and `jobCancel` are the RPCs.
- **Why.** One JS thread serves every script and RPC in the target. A 400 ms handler delayed every other script by
  400 ms [ext-frida §1.7]. With 8 ms slices, the worst-case RPC latency while a scan runs is about 8 ms plus RPC
  overhead.

---

## 6. Event pipeline (`events.ts`)

### 6.1 Streams

```ts
interface Stream {
  id: StreamId; instrument: InstrumentId | null; kind: RowKind; enc: "json" | "bin";
  layout: BinaryLayout | null;
  rows: unknown[]; rowBytes: number;                 // JSON rows pending + byte estimate
  ring: NativeRingRef | null;                        // native producers (hook-native/1), drained at flush
  bin: { buf: ArrayBuffer; used: number } | null;    // JS-assembled binary (block-span/1, block-count/1, gum-event)
  bseq: number; recorded: number; sentRows: number; batches: number;
  dropped: Required<DropCounters>; droppedAtLastBatch: Required<DropCounters>;
  g0: Gseq; g1: Gseq; t0: TimeUs; t1: TimeUs;
  state: "open" | "closing" | "closed"; system: boolean;
}
```

- **System streams** are `s:exceptions`, `s:modules`, `s:threads` and `s:memmap`. They are created at boot when
  enabled, so pre-`hello` events, such as early module loads, are kept and flushed after `hello`. Before `hello` the
  flush loop sends nothing but keeps up to `stream_max_pending_rows`.
- Every other stream belongs to one instrument and closes with it.
- At most `limits.max_streams` (64) streams exist. A new instrument that would exceed this fails with
  `ResourceLimit{resource:"streams"}`.

### 6.2 Admission and buffering (per row; JS producers)

```ts
function emit(s: Stream, row: unknown[], estBytes: number): void {
  if (s.state !== "open") { s.dropped.stopped++; return; }
  if (flow.shedding && !s.system) { s.dropped.flow_control++; flow.shedRows++; return; }
  if (s.rows.length >= L.stream_max_pending_rows || s.rowBytes >= L.stream_max_pending_bytes) { s.dropped.buffer_full++; return; }
  s.rows.push(row); s.rowBytes += estBytes; s.recorded++;
  if (s.rows.length >= L.batch_max_rows || s.rowBytes >= 256 * 1024) flushStream(s, false);   // immediate, from the producer thread
}
```

- `estBytes` is a cheap estimate: 12 per number, 2 + length per string, 20 per Hex, summed while building the row.
  It feeds flow control only.
- `send()` from a hook callback on a target thread is VERIFIED to work [ext-frida §1.9, a10 binary-batch variant].

### 6.3 Flushing

- **Timer.** A `setInterval(flushAll, config.streams.flush_ms)` timer runs, default 50 ms (VERIFIED batching interval
  [ext-frida §1.9]).
- **`flushAll`.**
  1. For every stream, drain its native ring if it has one: `bea_ring_collect` → staging buffer → `readByteArray` →
     binary batch.
  2. Then send JSON or binary batches when rows are pending.
  3. Sends are not throttled per stream. Flow control (§6.5) is the throttle.
- **JSON batch.** `send(JsonBatchMessage)`, where `rows` is the array itself and `dropped` is the delta since the
  previous batch. `bseq` increments per stream, so the host detects gaps; with Frida's ordered transport a gap means a
  bug.
- **Binary batch.** `send(BinBatchMessage, data)`, where `data` is exactly `n * rec_bytes` bytes.
- **Sizes.**
  - JSON: ≤ `batch_max_rows` (2000, VERIFIED size [ext-frida §1.9]) or ≈256 KiB.
  - Binary: ≤ `batch_max_bin_bytes` (1 MiB per message; the VERIFIED throughput used 64 KiB to 4 MiB messages
    [ext-frida §1.9, §3.4]).
- **Final flush** (`flushAll({final:true})`) is used by the exit hook, crash reports, `instrumentStop` and `shutdown`.
  It drains everything synchronously on the calling thread and sets `final:true` on the last batch of stopped streams.

### 6.4 Binary layouts (`src/shared/binaryLayouts.ts`; all little-endian)

**`hook-native/1`**: `rec_bytes` 160. The producer is the native hook tier.

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | g | u64 | global sequence |
| 8 | t | u64 | µs since agent load (cast from double) |
| 16 | tid | u32 | |
| 20 | hook_index | u16 | maps to instrument via the install result |
| 22 | phase | u8 | 1 enter-only, 2 call |
| 23 | depth | u8 | interceptor depth |
| 24 | ret_addr | u64 | caller |
| 32/40/48/56 | rcx, rdx, r8, r9 | u64 | at entry |
| 64/72/80/88 | xmm0..xmm3 | u64 | low 8 bytes at entry (0 if feature absent) |
| 96/104/112/120 | s4..s7 | u64 | `nth_argument(4..7)` raw words |
| 128 | rax | u64 | at leave (0 for phase 1) |
| 136 | xmm0_ret | u64 | low 8 bytes at leave |
| 144 | reserved | u64 | 0 |
| 152 | commit | u64 | `0xbea0bea0bea0bea0` while published; the host ignores it |

The host decodes typed values from the hook spec:
- int-class slot k<4 → `w[k]`;
- float slot k<4 → `x[k]` (f32 = low 4 bytes, f64 = 8);
- slot ≥ 4 → `s[k-4]`;
- ret f32/f64 → `xmm0_ret`, else `rax`.

**`block-span/1`**: `rec_bytes` 16 (`start u64`, `end u64`). Coverage mode: unique compiled blocks, deduped in the agent.

**`block-count/1`**: `rec_bytes` 24 (`start u64`, `end u64`, `count u64`). Block-count snapshots. Blocks that were
recompiled appear more than once; the host sums counts by `start`.

**`call-site-count/1`**: `rec_bytes` 24 (`site u64`, `target u64` (0 for indirect calls), `count u64`). Call-summary
snapshots, one record per compiled `call` instruction. The host aggregates by target, and resolves the top indirect
sites by disassembling them (§12.3).

**`gum-event-x64/1`**: `rec_bytes` 32. Raw `GumEvent` passthrough for `call_events` mode:
`type u32 @0` (1 call, 2 ret, 4 exec, 8 block, 16 compile), `a u64 @8` (location/start), `b u64 @16` (target/end),
`depth i32 @24`. The 32-byte size is VERIFIED [ext-frida §3.8]; the field layout is BELIEVED (A-13). The agent
self-checks it at the first batch against `Stalker.parse` and falls back to agent-side parsing into `block-span/1` if
they disagree.

### 6.5 Flow control (bounds target memory even if the host stalls)

- The agent counts `sent_bytes`: the sum of JSON `estBytes` plus binary and blob payload bytes.
- The host posts `{type:"flow", received_bytes}` after every 1 MiB received or every 100 ms, whichever comes first.
  `received_bytes` is cumulative, after the chunk write call has returned. No fsync is needed (orchestrator decision).
- `inflight = sent_bytes − received_bytes`.
  - Above `flow_high_water_bytes` (default 32 MiB): `shedding = true`. Non-system rows are dropped with
    `flow_control`, and a `NoticeMessage{flow-shedding-on}` is sent.
  - Below `flow_low_water_bytes` (default 8 MiB): `shedding` is cleared and a `flow-shedding-off` notice is sent.
- Messages that are not batches (`crash`, `exit`, `instrument`, `job`, `notice`, `fault`) are never shed. They are
  small and bounded.
- **Why this is needed.** `send()` has no backpressure, and per-call sends grew a target to 21 GB [ext-frida §1.9].
  Batching cuts the message rate, but only flow control bounds memory when the *host* is slow: a blocked event loop,
  slow disk, or a suspended MCP server.

### 6.6 The persistent receivers (`ack.ts`)

```ts
const ackWaiters = new Map<AckToken, NativePointer /* event HANDLE */>();
function armAck(): void { recv("ack", (m: { token: AckToken }) => { const h = ackWaiters.get(m.token); if (h) win.SetEvent(h); armAck(); }); }
function armFlow(): void { recv("flow", (m: { received_bytes: number }) => { flow.onReceived(m.received_bytes); armFlow(); }); }

/** Send a message that requires a host ack and wait for it, bounded. Safe on any thread except the JS thread, where it degrades to a timeout. */
export function sendAndAwaitAck(msg: CrashMessage | ExitMessage, timeoutMs: number): { acked: boolean; waited_ms: number } {
  const h = win.CreateEventW(NULL, 1, 0, NULL);          // manual-reset, non-signaled
  ackWaiters.set(msg.ack, h);
  const t0 = Date.now();
  try {
    send(msg);
    const r = win.WaitForSingleObject(h, timeoutMs);      // cooperative: the JS thread can run armAck's callback (F12)
    return { acked: r === 0, waited_ms: Date.now() - t0 };
  } finally { ackWaiters.delete(msg.ack); win.CloseHandle(h); }
}
```

- `recv` is one-shot, so each receiver re-arms itself.
- One persistent `ack` receiver serves many concurrent waiters, for example two crashing threads, matched by token.
  A per-waiter `recv` would consume another waiter's ack.

---

## 7. The single exception dispatcher (`exceptions.ts`)

### 7.1 Registration

`installDispatcher(c)` runs at boot step 2 and calls `Process.setExceptionHandler(dispatch)` **exactly once**. It is
never called again, because a second call in the same script replaces the first (F15).

Scripts registered later, such as `run_script` user scripts, run **after** BEA in the chain (F15). BEA therefore sees
every exception first and returns `true` only for traps it owns.

### 7.2 Routing

```ts
function dispatch(d: ExceptionDetails): boolean {
  const tid = Process.getCurrentThreadId();
  try {
    c.counters.exceptions[d.type] = (c.counters.exceptions[d.type] ?? 0) + 1;
    if (d.type === "single-step") {
      let ours = false;
      if (pageGuard.hasPendingStep(tid)) ours = pageGuard.onStep(d, tid) || ours;   // TF re-arm (F19): per-thread state
      if (hwbp.ownsTrap(d)) ours = hwbp.onTrap(d, tid) || ours;                    // DR6 B0..B3 ∩ owned slots
      if (ours) { c.counters.beaTraps++; return true; }
    } else if (d.type === "guard-page") {
      if (d.memory !== null && pageGuard.ownsPage(d.memory.address)) { c.counters.beaTraps++; return pageGuard.onGuard(d, tid); }
    }
    if (Cloak.hasCurrentThread()) return false;          // agent/Frida-internal faults: counted, never reported
    firstChance(d, tid);                                 // §7.3: row on s:exceptions (non-blocking)
    if (c.config.crash.first_chance_blocking && c.config.crash.crash_class.includes(d.type) && crashLimiter.allow())
      reportCrash(d, tid, "first-chance");               // §7.4: flush + CrashMessage + bounded ack
    return false;                                        // never swallow what BEA did not cause
  } catch (e) {
    c.fault("exception-dispatcher", e);                  // never throw out of the handler
    return false;
  }
}
```

- **Both trap sources on one step.** A single `single-step` can carry both a TF step owed to page-guard and a DR hit,
  for example when the re-executed instruction also hits a data watch. Both handlers run.
- **DR6 does not identify TF steps.** It read 0 on TF steps (F19). TF steps are recognized by per-thread pending state
  only. DR hits are recognized by DR6 B-bits, which are VERIFIED to identify slots on DR traps [ext-frida §3.9].
- **Other single-steps.** A `single-step` that is neither BEA's TF nor a BEA slot (the app's own TF trick or its own
  debug registers) is recorded and passed.
- **`breakpoint` (int3).** BEA never uses int3: Interceptor patches with `jmp`, and execute breakpoints use DRs.
  int3 exceptions are therefore always the target's own and are passed.

### 7.3 First-chance rows (`s:exceptions`, `exception/1`)

- **Row.** `[g, t, tid, type, address, mem_op, mem_addr, "passed"|"reported", repeat]`, with `memory` from
  `d.memory` [ext-frida §3.11].
- **Rate limit.** `rows_per_sec` (default 1000). Above the cap, a `(type, address)` key that already has a row within
  the current second increments that row's `repeat` field. This works because the row is still in the pending buffer
  or is tracked in a small LRU of 256 keys. Keys with no pending row are dropped with `rate_limit`.
- **Handled exceptions.** First-chance AVs that the app handles, such as `IsBadReadPtr` or .NET/Mono null checks, are
  normal [ext-frida §3.11]. They are rows, not crashes.

### 7.4 Crash reports

**First chance.** `reportCrash(d, tid, "first-chance")`:
1. Build the `CrashReport`:
   - registers from `d.context` (explicit name list; QJS context objects have no own keys [ext-frida §3.6]);
   - `eflags` from `nativeContext+0x44`, `mxcsr` from `+0x34`, `fpcw` from `+0x100` (F13);
   - instruction bytes and text at `d.address` through the overlay-aware decoder (§8.4);
   - `backtrace = [d.address, ...Thread.backtrace(d.context, Backtracer.ACCURATE).slice(0, depth)]`
     [ext-frida §3.11, §3.13], each frame as `{va, module, rva}` through `map.find`;
   - a stack window from `d.context.sp`, read guard-aware (§8.2).
2. `flushAll({final:false})`, so every pending row reaches the host before a possible death.
3. `sendAndAwaitAck({bea:"crash", ack:"crash-<n>", report}, crash.ack_timeout_ms)`.
4. Return `false`. The app's SEH runs next; if nothing handles the exception, the last-chance path follows.

The blocking report is rate-limited (`max_blocking_per_10s`, default 8). Above that limit the dispatcher only records
the row. With the default policy, the worst-case cost of first-chance AV storms is about 8 acks per 10 s, each about
1 ms locally [ext-frida §3.11].

**Last chance.** `installCoreHooks` attaches a JS listener to `kernelbase!UnhandledExceptionFilter` (VERIFIED, F13).
`onEnter(args)`:
- `ep = args[0]`; `er = ep.readPointer()`; `cr = ep.add(8).readPointer()`;
- `code = er.readU32()`; `address = er.add(0x10).readPointer()`; `n = er.add(0x18).readU32()`;
  `info[i] = er.add(0x20 + 8*i).readU64()` (i < min(n, 15));
- for an AV, `memory = {operation: info[0]==0 ? "read" : info[0]==1 ? "write" : info[0]==8 ? "execute" : null, address: info[1]}`;
- registers from the CONTEXT at `cr` (offsets §5.6);
- backtrace, preferring the exact one:
  1. The dispatcher keeps a per-thread cache `{address, backtrace, g}` of the last crash-class first-chance exception
     (≤ 64 threads, LRU). If `tid` and `address` match, use that backtrace. It was taken from the faulting `d.context`
     and is VERIFIED-quality [ext-frida §3.11].
  2. Otherwise use `[address, ...Thread.backtrace(this.context, ACCURATE)]`, taken from inside the UEF call. This
     relies on the unwinder walking back through `KiUserExceptionDispatcher` into the faulting frames (A-14), so it is
     marked `backtrace_source:"uef-context"`.
- then `flushAll(final)` → `sendAndAwaitAck(…, last_chance_ack_timeout_ms)` with `phase:"last-chance"`, then return
  normally so the original filter (WER, the app's own UEF or crash reporter, the job's die-on-unhandled) proceeds.

The host derives "crashed" from three signals: (a) a last-chance report, (b) jobhost's NTSTATUS exit code, and
(c) `detached('process-terminated')`. A first-chance report alone is "crash-candidate".

**Exit.** A listener on `ntdll!RtlExitUserProcess` (VERIFIED, F11/F12) runs `onEnter(args)`:
1. `exit_code = args[0].toUInt32()`;
2. every instrument is marked `process-exit` (state `stopping`; no reverts);
3. `flushAll({final:true})`;
4. `sendAndAwaitAck({bea:"exit", via:"RtlExitUserProcess", …}, last_chance_ack_timeout_ms)`.

A second listener on `ntdll!NtTerminateProcess` acts only when `args[0]` is `-1` (`0xffffffffffffffff`, the current
process). It does the same with `via:"NtTerminateProcess(self)"`, which covers `TerminateProcess(GetCurrentProcess())`
calls that skip `RtlExitUserProcess` (A-15). `RtlExitUserProcess`'s own internal `NtTerminateProcess(NULL)` (kill other
threads) is ignored because its handle is 0. A process-wide flag makes the exit report happen at most once.

**Not catchable.**
- `__fastfail` / `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409) and similar fail-fast terminations bypass every user-mode
  handler. Only jobhost's exit code reveals them.
- External `TerminateProcess` from another process.
- Kernel-forced termination.

The host reports these as "terminated without agent report" with the NTSTATUS.

---

## 8. Inspection, memory and code

### 8.1 `modules.ts`: ModuleIndex and PE facts from memory

**State.** The index holds:
- `map: ModuleMap`, the snapshot used by every hot path. `find(addr)` does not take the loader lock (A-16). The lab
  used `ModuleMap.find` inside hooks with no stall [S4-lab levels runs].
- `byName: Map<lowercase name, Module>` and `epoch: number`.
- A per-module lazy cache of exports (sorted by VA, for `export_hint`), `.pdata` and PE facts.

**Observer.** `Process.attachModuleObserver({onAdded, onRemoved})` is installed at boot. Its `onAdded` fires
synchronously for existing modules and then for each load [ext-frida §3.13]. The rule is to do nothing heavy on the
loader thread:
- `onAdded` and `onRemoved` only queue `{ev, module}` and emit a `module/1` row (cheap).
- A `setImmediate` on the JS thread then bumps `epoch`, rebuilds `map` (`new ModuleMap()`), notifies `profiles`
  (lazy installs) and `instruments` (unload stops).
- No `Interceptor.attach` runs inside the loader callback (A-16).

**PE facts from memory** (`pe(m)`). The loader rewrites only `ImageBase` [ext-frida §3.14]; every other header field
below is file-identical.

| Item | Location (all reads bounded and try/catch) |
|---|---|
| NT headers | `nt = base + u32[base+0x3C]`, signature `"PE\0\0"`, `Machine u16 nt+4`, `NumberOfSections u16 nt+6`, `TimeDateStamp u32 nt+8`, `SizeOfOptionalHeader u16 nt+0x14` |
| Optional header (`opt = nt+0x18`) | `Magic` 0x20B required, else `Unsupported`. `AddressOfEntryPoint opt+0x10`, `ImageBase opt+0x18` (in-memory = actual base), `SizeOfImage opt+0x38`, `CheckSum opt+0x40`, `Subsystem opt+0x44`, `DllCharacteristics opt+0x46`, `NumberOfRvaAndSizes opt+0x6C`, `DataDirectory[i] opt+0x70+8*i` |
| Section table | at `opt + SizeOfOptionalHeader`, 40 B each: `Name[8]` (raw; gcc `/4`-style long names stay unresolved, and the host resolves them from the COFF string table on disk [ext-frida §3.1]), `VirtualSize +8`, `VirtualAddress +0xC`, `Characteristics +0x24` |
| `.pdata` | `DataDirectory[3]`: RUNTIME_FUNCTION[] of 12 B: `Begin u32, End u32, UnwindInfo u32`. `UnwindInfo` byte 0 `>> 3 & 4` = UNW_FLAG_CHAININFO (row `chained:true`) |
| Debug / CodeView | `DataDirectory[6]` → IMAGE_DEBUG_DIRECTORY[] of 28 B. `Type u32 +0xC == 2` (CODEVIEW), `AddressOfRawData u32 +0x14` → `"RSDS"`, GUID 16 B, `Age u32`, PDB path (≤ 260 chars) |
| TLS | `DataDirectory[9]` → IMAGE_TLS_DIRECTORY64, `AddressOfCallBacks +0x18` (VA of a null-terminated array, ≤ 64 entries read) |
| Delay imports | `DataDirectory[13]` → ImgDelayDescr[] of 32 B (RVAs: `DllNameRVA +4`, `ModuleHandleRVA +8`, `ImportAddressTableRVA +0xC`, `ImportNameTableRVA +0x10`) → `ImportRow{delay:true}` |

- Exports and imports come from Frida's `module.enumerateExports/Imports()` (VERIFIED; the import `slot` is the IAT
  entry [ext-frida §3.1]), plus delay imports from the table above.
- Function lists come from `.pdata`.
- `findFunction` is `Process.findFunctionRange` (exact `.pdata` ranges [ext-frida §3.12]).
- `DebugSymbol` is **never** used for names (wrong without a PDB [ext-frida §3.12]). `export_hint` is the nearest
  preceding export, labeled as a hint.
- **Host side, never in the agent:** on-disk preferred ImageBase, file sha256, long section names, and on-disk bytes
  for `map_address` verification [ext-frida §3.14]. The agent's figures are in-memory facts only.

### 8.2 `memory.ts`: reads

**`readMemory`** (binary RPC): `{address, size ≤ read_max_bytes (1 MiB)}` → `[ok(meta), ArrayBuffer]`.
1. **Guard check.** Use `VirtualQuery` on each page run (cached per allocation region) and stop at:
   - `MEM_FREE` or `MEM_RESERVE` → `unmapped`;
   - `PAGE_NOACCESS`, or no read right → `protection`;
   - `PAGE_GUARD (0x100)` on a page that is **not** BEA's → `guard-page`.

   Reading a target guard page would consume it: the OS clears the guard on access, which breaks the app's mechanism
   (A-18). BEA's own guard pages (§11.3) are read under a suspension window: clear the guard, read, re-guard. These
   pages are reported in `bea_guard_suspended`.
2. **Read.** `ptr(address).readByteArray(n)` for the readable prefix. A bad address throws a plain JS Error, and the
   process survives [ext-frida §3.3]. If an AV still happens (a TOCTOU unmap), fall back to page-wise reads and stop at
   the first faulting page (`access-violation`, `at`).
3. **Result.** `complete = returned === requested`. Zero readable bytes gives `AccessViolation{partial_bytes:0}` and no
   tuple. The host splits reads above 1 MiB and puts large data into blobs.

**`readTyped`**: up to `typed_max_reads` (256) reads per call.
- **Pointer chains.** For each `TypedRead`: `p = address`, `path = [p]`; for each offset `o` in `chain`:
  `p = (p + o).readPointer()`, push `p` (null → `{e:'null'}`-style error `AccessViolation{address:0x0}`). The final
  read is at `p` with `type` and `count` (≤ 256), strings via `max_len`. Each step is guard-checked like `readMemory`.
- **Floats.** f32/f64 are read as bits (`readU32`/`readU64`) and returned through `floatOut` with exact bits, so no
  float-to-JS-to-float conversion takes place.
- **Strings.** `utf8` → `readUtf8String(max)`, `utf16` → `readUtf16String(max)`, `ansi` → `readAnsiString(max)`.
  `trunc` is reported when the string reaches `max` without a terminator, detected by reading `max+1`.

This serves the Cheat-Engine pointer-chain validation step and the struct-field reads the user wants
("live variables/structs").

### 8.3 `memory.ts`: writes (gate `write_memory`) and revert

`writeMemory({address, mode, bytes|typed, expect_before?, allow_protect_change})`:
1. Validate size (≤ `write_max_bytes`, 64 KiB). Refuse if the range overlaps a BEA patch (`originals`) or a BEA guard
   page (`WatchInvalid{agent-page}`-style `BadParams`).
2. Read `before`. If `expect_before` is given and differs, return `WriteConflict` (a compare-and-swap write).
3. Choose the mode:
   - **data**: if `Memory.queryProtection` includes `w`, use a direct `writeByteArray`. Otherwise, if
     `allow_protect_change`, do `Memory.protect(pageRange, 'rw-')`, then write, then restore the original protection
     (`protect-and-restore`). Otherwise fail with `AccessViolation{operation:"write"}`. Writing code without protect
     faults [ext-frida §3.5].
   - **code**: `Memory.patchCode(address, n, code => code.writeByteArray(bytes))`. Protection stays `r-x`
     [ext-frida §3.5]. Then call `stalkerCo.invalidateAll([address])` (§12.1).
4. Read back `after` and set `verified = after == bytes`. Register `wr<n>` in `originals` (kind `write`, `before`
   bytes) and return `effect{kind:"memory-written", reversible:true, before:[…]}`.

`revertWrite({write_id, force})`:
- If current memory ≠ the written bytes and not `force`, return `WriteConflict` (someone else changed it).
- Otherwise write `before` back the same way, verify, and drop the record.

### 8.4 `originals.ts` and `disasm.ts`: code views that tell the truth

**OriginalBytes registry.**
- Before any BEA patch (Interceptor attach, replace, override, `patchCode` write) the agent saves
  `min(32, bytes to the end of readable memory)` bytes at **each address that will be patched**. That includes the
  thunk target when the requested address is a `jmp [rip+x]` stub, because Interceptor instruments the target (F5).
- Records are refcounted per address: several listeners on one function share one patch.
- `isPatched(range)` and `overlay(buf, base)` are used by disassembly, by the writer-instruction recovery and by
  `fingerprint`.
- **Why.** `Instruction.parse` at a hooked address returns the hook's `jmp` [ext-frida §3.6]. The lab saw kernelbase
  functions already showing trampolines before inspection (F17).

**`disassemble`.**
1. Determine the range:
   - `count`: ≤ `disasm_max_insns` (2048);
   - `function`: `Process.findFunctionRange` (exact [ext-frida §3.12]), else `NoFunctionRange`;
   - `range`: ≤ `disasm_max_bytes` (64 KiB).
2. Read the bytes guard-aware (§8.2).
3. **Fast path.** If `original_bytes` is false or nothing in the range is patched, decode in place with
   `Instruction.parse(addr)`.
4. **Overlay path.** Copy the bytes into a scratch buffer `S` (one reusable 64 KiB `rw-` allocation), overlay the
   originals, and decode at `S+off`. Then fix up each instruction:
   - `address = A+off`, `next = address + size`.
   - **Relative branches/calls** (groups `call`, `jump` or `branch_relative` with an `imm` operand): Capstone computes
     the target from the scratch address, so `target = imm − S + A`. Rebuild `op_str` as
     `` `${mnemonic} 0x${target}` ``. Immediates are decimal strings [ext-frida §3.12].
   - **RIP-relative memory operands**: `abs = next + disp` (disp is relative to `next` [ext-frida §3.12]). Since `next`
     is already the real address, no correction is needed. Each absolute address goes into `mem_targets`.
   - Rows decoded with overlaid bytes carry `overlay:true`.
5. `cfg:true` adds `new ControlFlowGraph(fnBase)` blocks (VERIFIED to match objdump [ext-frida §3.12]). This uses
   live bytes, so with patches present it is marked best-effort. It is capped at 4096 blocks.

**Access-instruction recovery** (`findAccessInsn(pcAfter)`, used by debug-register watches):
1. Look up `fr = Process.findFunctionRange(pcAfter)`. If found: sweep from `fr.base`, `p = fr.base`; while
   `p < pcAfter`: `insn = decodeAt(p)` (overlay-aware); if `insn.next == pcAfter` return `{insn, conf:"swept"}`;
   `p = insn.next`. Cap 4096 instructions. VERIFIED to find the writer [ext-frida §3.9].
2. Otherwise (leaf code without `.pdata`, JIT code): back-scan `k = 1..15`, decode at `pcAfter − k`, and accept the
   candidates where `size == k`. Exactly one candidate gives `conf:"heuristic"`; zero or several give
   `conf:"unknown"`, with the `pc_after` row field still filled.
3. Results are cached in `Map<pcAfter, {address, size, text, conf}>` (≤ 4096 entries, LRU). This matters because
   watch traps repeat at the same pc.

### 8.5 `inspect.ts`: ranges, threads, resolution

**`listRanges`.**
- It takes a **snapshot**: `Process.enumerateRanges({protection, coalesce})`, or `Process.enumerateMallocRanges()`
  for `kind:"malloc"` (5663 blocks in 2 ms [ext-frida §3.2]). Rows are attributed through `map.find` (there is no
  `file` field on Windows [ext-frida §3.2]) and filtered by module or kind.
- The snapshot is stored as `ss<n>` (TTL `snapshot_ttl_ms` 30 s, at most `max_snapshots` 4, LRU) and paged
  (`list_page_max` 5000).
- Paging with `snapshot` reuses it. An expired snapshot returns `NotFound{what:"snapshot"}` and the host retries
  without one.

**`listThreads`.**
- `Process.enumerateThreads()` plus the following:
  - `entry = entrypoint.routine`;
  - `regs` from `t.context` with an explicit name list (QJS context objects have no keys [ext-frida §3.6]);
  - `teb` / `stack` via §5.6 when requested;
  - `name` via `GetThreadDescription` when requested.
- `state` is passed through verbatim and documented as unreliable (`running` for sleeping threads [ext-frida §3.13]).
- The agent JS thread never appears, because it is cloaked.

**`resolveTargets`.** Up to 1024 `TargetRef` entries.
- `{module, export}` → `Process.findModuleByName` (case-insensitive [ext-frida §3.1]) → `module.findExportByName`.
- `{module, rva}` → `base + rva`, checked against `size`.
- `{va}` → `map.find`.
- Each result is a `ResolvedTarget` with `function` (pdata range) and `protection` (`findRangeByAddress`).
- Static↔runtime rebasing (`runtime = base + (staticVA − preferredBase)` [ext-frida §3.14]) is **host-side**, because
  the preferred base comes from the PE on disk. The host then calls `resolveTargets({va})` to validate the result, and
  `readMemory` to compare it with the file bytes.

**`describeAddresses`.** Up to 1024 addresses. Each result is `module`/`rva` via `map.find`, `function`, `range`,
`export_hint` (the nearest preceding export from the cached sorted export table) and the `bea_patched` /
`bea_guarded` flags.

---

## 9. Scans (`scan.ts`): Cheat-Engine semantics, agent-side state, sliced jobs

### 9.1 Model

```ts
interface ScanState {
  id: ScanId; label: string | null; vt: ScanValueType; elem: number;      // element size; bytes/strings: pattern length
  align: 1 | 2 | 4 | 8; regions: RegionFilter;
  mode: "explicit" | "snapshot";
  // explicit: parallel native arrays (Memory.alloc), capacity = max_candidates
  addrs: NativePointer | null;       // u64[cap]
  vals: NativePointer | null;        // u8[cap * elem]  (last observed value; "changed/unchanged/increased" compare to it)
  firsts: NativePointer | null;      // u8[cap * elem]  (value at first scan; for same_as_first) — allocated lazily
  count: number; cap: number;
  // snapshot: unknown-initial mode
  snaps: { base: NativePointer; size: number; copy: NativePointer }[] | null;   // ≤ scan_snapshot_bytes total
  history: { op: string; count_after: number; t: TimeUs }[];
  bytes_scanned: number; unreadable_regions: number; faulted_dropped: number;
  state: "running" | "ready" | "failed" | "closed"; job: JobId | null; error: AgentError | null;
}
```

- **Limits.** At most `scan_max_concurrent` (8) scans. Candidates are capped at `scan_max_candidates` (default 4M,
  hard 16M), which costs `(8 + elem)` bytes each in target memory. Snapshots are capped at `scan_snapshot_bytes`
  (default 256 MiB, hard 1 GiB). Hitting a cap mid-scan stops with
  `ResourceLimit{resource:"scan_candidates"|"scan_snapshot", limit, observed}`; the scan keeps what it had, with
  `state:"failed"`, and can be narrowed or closed.
- **Region list.** Computed once per first scan: `Process.enumerateRanges({protection, coalesce:false})`, filtered by
  modules, address window, `private_only` (`map.find == null`) and `max_region_bytes`, then sorted. Frida's own
  allocations are absent from range enumeration (`findRangeByAddress` is null for a `Memory.alloc` block
  [ext-frida §3.2]). Scans therefore do not see the agent's own buffers (A-19).
- **Guard pages.** Excluded: `VirtualQuery` with `PAGE_GUARD` is skipped and counted as unreadable (A-18).
- **Persistence.** None. Scan state lives in target memory and dies with the process. "Named persistent scans" across
  sessions are a host feature (export the candidate list). Not in v0.1.

### 9.2 First scan (job `scan-first`, sliced at 8 ms)

| Kind | Mechanism (per slice ≤ 8 MiB of region) | Source |
|---|---|---|
| `value` + `eq`, integers, `ptr`, exact floats, `bytes`, strings | Build a match pattern from the little-endian bytes (utf16 = UTF-16LE). `Memory.scanSync(base, n, pattern)` in try/catch: an unreadable range is counted. Hits failing the `align` check are discarded. Consecutive slices overlap by `elem − 1` bytes and hits are deduplicated by address. The stored value is the pattern bytes | VERIFIED 1.8 GB/s [ext-frida §3.4] |
| `pattern` (AOB with `??`, nibble or `: mask`) | `Memory.scanSync`. `elem` = pattern length; values are read at hit time. `/regex/` is refused (`BadParams`; its match length varies) | [ext-frida §3.4] |
| `value` + `approx`/`range`/`gt`/`lt` (any numeric) | `bea_scan_cmp` CModule kernel via a `NativeFunction` with `exceptions:'steal'`. The kernel writes offsets into a 64K-entry staging array; JS appends `(base+off, value)`. A stolen AV skips the rest of the region (`unreadable_regions++`) | CModule float scan 1.0 GB/s VERIFIED [ext-frida §3.4] |
| `unknown` | Copy each region into the snapshot (`Memory.copy`, try/catch) up to `scan_snapshot_bytes`. `count = Σ floor(size/align)` virtual candidates, `mode:"snapshot"` | [proposal]; `Memory.copy` VERIFIED [ext-frida §3.5] |
| `pointers-to` | `Memory.findPointers(rangeSlice, targets)` per ≤ 256 MiB slice. Stored as explicit `ptr` candidates (value = the matched target) | VERIFIED ~30 GB/s [ext-frida §3.4] |

QJS JS loops are **never** used over memory (33 MB/s [ext-frida §3.4]).

**Value encoding.** Comparands come from `ScalarInput`. For floats, `eq` compares bits only when the input is
`{bits}`; otherwise it is IEEE `==` (NaN never equal). `approx` means `|x − v| ≤ eps`. `range` is inclusive.

### 9.3 Next scan (job `scan-next`)

- **Explicit mode.** `bea_scan_next(addrs, vals, firsts, n, vt, op, a, b, eps, progress, kept)` runs over chunks of
  ≤ 1M candidates per slice and compacts in place. It re-reads each candidate's current value; the comparison against
  the stored `vals`/`firsts` is in C.
- **Candidates that fault.** A page freed since the last scan causes a stolen AV (VERIFIED stealing
  [ext-frida §3.7]). JS reads `progress` (the faulting index) and `kept`, drops every candidate in that 4 KiB page
  (`faulted_dropped++`) and resumes at `progress + 1`.
- **Snapshot mode.** `bea_scan_snap(regionVA, copy, size, …)` produces explicit candidates (with current values) for
  elements that satisfy the op against the snapshot. When the total fits in `cap`, the scan switches to
  `mode:"explicit"` and frees the snapshot. Otherwise it fails with `ResourceLimit{scan_candidates}` and suggests
  narrowing the regions or the type.
- **Ops.** `eq ne approx gt lt range changed unchanged increased decreased increased_by decreased_by same_as_first`
  (the CE set [ext-landscape §7.2]). `same_as_first` needs `firsts`. These are captured at the first scan for explicit
  kinds; snapshot mode uses the snapshot.

### 9.4 Kernel contract (C, in the core CModule)

- **`vt` codes:** 0 i8, 1 u8, 2 i16, 3 u16, 4 i32, 5 u32, 6 i64, 7 u64, 8 f32, 9 f64, 10 ptr (= u64). `bytes` and
  strings only support `eq`/`ne`, via `memcmp`.
- **Operand bits:** `a`/`b` are passed as raw 64-bit bits. Floats are reinterpreted in C (`memcpy` into
  `float`/`double`).
- **Reads:** every target read is a plain C dereference. The caller guarantees the NativeFunction steals AVs, and the
  kernel publishes its index in `*progress` **before** each read, so JS can resume precisely.
- **Throughput target:** ≥ 0.5 GB/s per slice, which matches the 1.0 GB/s VERIFIED kernel [ext-frida §3.4].
- **Unit tests:** C kernels are tested on the host by compiling the same C with gcc against a tiny shim (§19).

### 9.5 Results

`scanResults({scan_id, offset, limit ≤ scan_page_rows (4096), read_current})`:
- Rows come from the native arrays: `stored` is decoded from `vals`; `current` is re-read with the guard-aware reader
  when `read_current`.
- In snapshot mode, results are refused (`BadParams`: "narrow the snapshot with scanNext first").
- `total = count`. Like a CE first scan, the RPC returns only `{scan_id, job_id}` and the job result returns
  `{count}`, so a 40k-hit scan costs a few tokens [ext-landscape §7.3].

`scanClose` frees the native arrays immediately. Nothing is held by Stalker or Interceptor, so no keep delay is needed.

---

## 10. Hooks and API behavior profiles (`hooks.ts`, `capture.ts`, `profiles.ts`, `src/shared/apiProfiles.ts`)

### 10.1 Which level fires for which operation (VERIFIED level map, [S4-lab F5, F6, F16])

| Operation (fixture marker) | kernel32 | kernelbase | ntdll | other |
|---|---|---|---|---|
| `CreateFileW` write (1) | CreateFileW d0 *(same code as kernelbase)* | CreateFileW d0 | NtCreateFile d1, `\??\C:\…`, disp 5, Information 2 | — |
| `CreateFileA` read (2) | CreateFileA d0 *(same)* | CreateFileA d0 | NtCreateFile d1, disp 1 | — |
| msvcrt `fopen` (3) | **CreateFileA d0** (msvcrt→kernelbase) | CreateFileA d0 | NtCreateFile d1 | — |
| `GetFileAttributesW` missing (4) | — | — | NtQueryAttributesFile d0 → 0xC000003A | — |
| `MoveFileExW` (5) | — | — | NtOpenFile + NtSetInformationFile class 10 | — |
| `DeleteFileW` (6) | — | — | NtOpenFile + NtSetInformationFile class **64** (not NtDeleteFile) | — |
| `FindFirstFileW` (7) | — | — | NtOpenFile + NtQueryDirectoryFileEx ×2, pattern `"<.c"`, then 0x80000006 | — |
| `RegOpenKeyExW(HKLM)` + `RegQueryValueExW` (8) | — | RegOpenKeyExW d0 *(advapi32 stub → same)* | NtOpenKeyEx d1 (root 0x14c = `\REGISTRY\MACHINE`), NtQueryValueKey class 2 | — |
| `RegOpenKeyExW(HKCU, missing)` (9) | — | RegOpenKeyExW d0 | NtOpenKey d1 `\REGISTRY\USER\<SID>`, NtOpenKeyEx d1 → 0xC0000034 | — |
| `RegGetValueW` (10) | — | **not via RegOpenKeyExW** | NtOpenKeyEx d0, NtQueryValueKey d0 | — |
| `LoadLibraryW` + `GetProcAddress` (11) | LoadLibraryW d0 *(stub)*; **GetProcAddress d0 (real fn)** | LoadLibraryW d0, LoadLibraryExW d1 | LdrLoadDll d2, NtQueryAttributesFile/NtOpenFile/NtProtectVirtualMemory d3, **LdrGetProcedureAddressForCaller d1** | observer: `version.dll` |
| `LoadLibraryW` missing (12) | — | LoadLibraryExW d1 | LdrLoadDll d2 → 0xC0000135, 45× NtQueryAttributesFile d3 | — |
| `VirtualAlloc/Protect/Free` (14) | VirtualProtect *(stub)* | VirtualProtect d0, VirtualFree d0 | NtProtectVirtualMemory d1 (0x4→0x20), NtFreeVirtualMemory d1 | (`VirtualAlloc` not hookable: F8) |
| `getaddrinfo` (15) | — | — | (Winsock catalog registry reads, AFD `NtCreateFile`) | ws2_32 getaddrinfo d0 → GetAddrInfoW d1 → dnsapi DnsQueryEx d2 |
| TCP/UDP loopback (16) | — | — | NtCreateFile `\Device\Afd\Endpoint` under WSASocketW; AFD IOCTLs | socket d0 → WSASocketW d1; bind/listen/connect/accept/send/recv/WSASend/sendto/recvfrom/closesocket d0 |
| `CreateProcessW` missing image (17) | CreateProcessW d0 (real fn) | CreateProcessW d1 → **CreateProcessInternalW d2** | NtQueryAttributesFile only; **no NtCreateUserProcess** | — |
| `OpenProcess(self)` (18) | — | — | NtOpenProcess, ClientId.pid = own pid | — |
| `CreateThread` (19) | — | CreateRemoteThreadEx d0 | NtCreateThreadEx d1, start = `bt_fixture.exe+0x17a2` | — |

**Level-selection rules** for profiles, and the guidance `hook_function` gives callers:

1. **Hook the convergence point.** For kernel-object operations (files, keys, processes, threads, virtual memory,
   the loader) that is the ntdll `Nt*`/`Ldr*` stub. Every Win32, CRT and framework path ends there: `fopen` →
   kernelbase → NtCreateFile, and `RegGetValueW` skips `RegOpenKeyExW` entirely.
2. **Not when the convergence point is an undocumented protocol.** Network I/O converges on AFD IOCTLs
   (`NtDeviceIoControlFile`, `\Device\Afd\Endpoint`). So network is hooked at the documented ws2_32/dnsapi layer.
3. **Never kernel32.**
   - Thunk exports (16-byte `jmp [rip+x]`) are followed by Interceptor to the kernelbase body. Hooking both kernel32
     and kernelbase only duplicates listeners on one function.
   - Real kernel32 wrappers bypass kernelbase's same-named export: `kernel32!GetProcAddress →
     LdrGetProcedureAddressForCaller`.
   - Profile specs name `ntdll.dll`, `kernelbase.dll`, `ws2_32.dll`, `dnsapi.dll`, `winhttp.dll` or `wininet.dll`.
4. **kernelbase only where the NT level is missing or forbidden.**
   - `CreateProcessInternalW` sees attempts on a missing image and the full command line (NtCreateUserProcess was
     never reached).
   - `VirtualAllocEx` and `VirtualAlloc2` stand in because `NtAllocateVirtualMemory`/`VirtualAlloc` are denied (F8).
5. **One level per API family.** Nested activity (the 45 DLL-search probes, AFD opens under `WSASocketW`) is
   attributed through **parent tracking** (§10.6), not through a second hook level.

### 10.2 Install algorithm (`hookInstall`, also used by profiles and overrides)

```
install(target, purpose, opts):
 1. A = resolveTargets(target).va. Require executable protection (findRangeByAddress(A).protection has "x"); else NotExecutable.
 2. Thunk resolution, for the deny check and for reporting:
      insn = Instruction.parse(A)                                   // live bytes; overlay if BEA already patched A
      jmp qword ptr [rip+d]  → T = readPointer(insn.next + d)        thunk {kind:"jmp-rip", to:T}
      jmp rel32 outside fn   → T = imm                               thunk {kind:"jmp-rel", to:T}   (A-20)
    effectiveSites = thunk ? [T] : [A]       // Interceptor patches the thunk TARGET (F5)
 3. Deny/caution check on A and effectiveSites against the resolved deny list (§10.8):
      deny → HookDenied{reason:"deadlock-risk", alternatives:[…]};
      caution and !force_caution → HookDenied{reason:"caution-requires-force"}.
 4. Conflict check: a BEA override in replace mode already on an effective site → HookConflict{kind:"replace"}.
    (Listeners can stack: double attach is VERIFIED [ext-frida §3.6].)
 5. originals.save(site, 32) for each effective site (refcounted).
 6. listener = Interceptor.attach(A, callbacks[, data])
    on Error /unable to intercept function/ and relocation == "auto":
        listener = Interceptor.attach({ target: A, relocation: "forced" }, callbacks[, data])   // VERIFIED for 4-byte fns
        relocation = "forced"
    on failure: originals.release(…); HookInstallFailed{attempts, frida_message,
        alternatives:["watch_memory {method:'debug-register', access:'execute'} at the entry",
                      "trace_execution coverage", "hook the call sites (disassemble callers)"]}
 7. Interceptor.flush()                                       // commit now; otherwise pending until the JS turn ends
 8. stalkerCo.invalidateAll(effectiveSites)                    // threads already followed see the hook [ext-frida §3.8]
 9. patched_at = effectiveSites; verify each site now begins with a jmp (diagnostic only; recorded, not fatal)
10. register instrument + stream; return HookInstallResult with effect{kind:"hook-installed", reversible:true, before:[originals]}
```

Every callback's first statement is the **detached guard**: `if (inst.state !== "active") return;`
([ext-frida §3.6]: one `onEnter` arrived after `detachAll` + `flush`).

### 10.3 Win64 capture (`capture.ts`, JS tier)

**Slot → source.** With `p = slot + (hidden_ret_ptr ? 1 : 0)`:

| Class | p < 4 | p ≥ 4 |
|---|---|---|
| int | `args[p]` (rcx, rdx, r8, r9) | `args[p]`. Frida maps it to `[rsp+0x28+8*(p−4)]` (VERIFIED for p=4 [ext-frida §3.6]) |
| float | **bits** from `this.context["xmm"+p]` (16-byte ArrayBuffer): f32 = `Uint32Array(ab)[0]`, f64 = two lanes | bits read at `this.context.rsp.add(8 + 8*p)` (`readU32`/`readU64`). At entry, `rsp+0x28` = slot 4 and `rsp+0x30` = slot 5, VERIFIED with `mix_args` [ext-frida §3.6] |

- Win64 assigns registers **by position**. The 2nd parameter, if it is a float, is in `xmm1`, and `args[1]` is
  garbage (VERIFIED [ext-frida §3.6]).
- Structs passed by value with size 1/2/4/8 occupy an int slot. Larger structs are passed by pointer, so use `deref`.
- A C++ `this` is slot 0. `hidden_ret_ptr` covers functions returning large structs: the callee receives the result
  pointer in rcx and the real arguments shift by one.

**Deref chains.**
- With `deref = [o1, …, on]`: `v = slotValueAsPointer`; for `i < n−1`, `v = v.add(o_i).readPointer()`; the final
  read is at `v.add(o_n)` with `type`, `count` and `max_len`.
- Failure cells: a null pointer gives `{e:"null", a}`; an AV gives `{e:"av", a}`; a non-BEA guard page gives
  `{e:"guard", a}`, checked through a per-page VirtualQuery cache with a 1 s TTL.
- Strings and bytes are capped by `max_len` (default 256 chars / 64 B, hard `max_string_chars` 1024 /
  `max_capture_bytes` 4096). `at:"leave"` reads after the call (out-params); the slot value saved at enter is the base.

**Return.** `f32`/`f64` take bits from `this.context.xmm0` in `onLeave`; anything else uses `retval` (rax), with
optional `deref`. Both are VERIFIED [ext-frida §3.6]. With `hidden_ret_ptr`, the return value is read from the saved
rcx pointer.

**Backtrace.**
- `Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, depth)`: return addresses, VERIFIED accurate where
  FUZZY gives false positives [ext-frida §3.13].
- It is rate-limited per hook by a token bucket of `max_per_sec` (default 100, hard `backtrace_per_sec` 1000), because
  it is the most expensive part of a hit.
- Frames are emitted as `FrameRef` strings: `"fixture_gcc.exe+0x13ba"` inside a module (via `map.find` at capture
  time), else a bare VA. The `caller` field stays a VA.
- The host can still reconstruct exact module+RVA for any VA field from `s:modules` (`module/1` rows are ordered by
  `g`), so `s:modules` is always on.

**Filters and sampling**, in order, and cheap:
1. detached guard;
2. `Cloak.hasCurrentThread()` → return. This skips agent and Frida threads (F2), including oracle calls made on the
   JS thread (§13.4), unless `observe_agent_calls`;
3. `core.agentCallTids.has(tid)` → `agent_calls_suppressed++` and return (calls made through `runOnThread`, §13.4);
4. thread filter (`Set`);
5. caller-module filter: `map.find(this.returnAddress)` name ∈ set;
6. `hits++` against `max_hits`;
7. `every_n`;
8. `max_per_sec` token bucket.

**Row.** `g = core.nextG()` and `t = core.nowUs()` are taken at enter.
- `emit:"leave"` (the default when `ret` is captured): the enter data is held in `this.bea` and one row with
  `phase:2` is emitted in `onLeave`.
- `emit:"enter"`: emit `phase:1` immediately.
- `unreturned = enters − leaves` is reported at stop (longjmp or exception unwinding past the frame).
- Rows still pending at stop are **not** synthesized: their data lived in invocation-local `this`.

**Cost.** Empty QJS `onEnter` is 0.44 µs [ext-frida §3.6], plus about 1 µs for stamping and 1–5 µs for captures.
Expect 100–300k rows/s per process, against JSON batch delivery measured at 1.0M items/s [ext-frida §1.9]. Hotter
functions use the native tier.

### 10.4 Native tier (`engine:"native"`)

**Install.** Validation:
- every capture is a bare slot 0..7 (no `deref`, strings, `count` or `at:"leave"`);
- `ret` is optional and of a scalar type;
- float slots need the feature `hooks.native.xmm`;
- `backtrace` and `registers` are refused.

Then:
1. Allocate `BeaNativeHook` plus a ring of `native_ring_records` (default 32,768 × 160 B = 5 MiB; power of two).
2. `Interceptor.attach(A, {onEnter: core.bea_hn_enter, onLeave: core.bea_hn_leave}, hookStruct)`. The third argument
   is delivered to C as `GUM_IC_GET_FUNC_DATA` (compiles and attaches, F18; delivery is A-6).
3. Pin everything in `keep`.

At most `max_native_hooks` (32) native hooks exist.

**Runtime.**
- C performs the thread filter (≤ 16 tids), `hits` (atomic), `max_hits`, `every_n` and `active`. When `max_hits` is
  exceeded, C clears `active` and the next flush stops the instrument.
- No JS runs per call. The cost is about 0.19 µs per hit for a CModule `onEnter` writing a ring [ext-frida §1.9].
- The flush loop drains the ring with `bea_ring_collect` into `hook-native/1` binary batches.
- `ring_overrun` and `torn_record` drops are counted in C and reported.

**When to choose it.** The host picks native when the caller asks for `engine:"native"`, or for `hot:true`
tool-level hints. Typical hot targets are per-frame physics helpers called 10^5–10^6 times per second.

### 10.5 API profile catalog (`src/shared/apiProfiles.ts`)

```ts
export const API_CATALOG_MINOR = 0;
export type ApiModule = "ntdll.dll" | "kernelbase.dll" | "ws2_32.dll" | "dnsapi.dll" | "winhttp.dll" | "wininet.dll";
export type HandleKind = "file" | "key" | "socket" | "process" | "thread" | "section" | "inet";
export type ArgDecoder =
  | { k: "u32" } | { k: "i32" } | { k: "u64" } | { k: "ptr" } | { k: "bool" } | { k: "skip" }
  | { k: "handle"; kind: HandleKind }                       // value + cached name annotation (`<name>_name`)
  | { k: "out_handle"; kind: HandleKind }                   // PHANDLE read at leave (success); cache insert
  | { k: "wstr"; max: number } | { k: "astr"; max: number }
  | { k: "ustr"; max: number } | { k: "anstr"; max: number } // PUNICODE_STRING / PANSI_STRING (nullable)
  | { k: "oa"; kind: "file" | "key" }                       // POBJECT_ATTRIBUTES → {root, root_name, name, path, attributes}
  | { k: "iosb" }                                           // PIO_STATUS_BLOCK → Information (u64) at leave
  | { k: "inout_ptr" } | { k: "inout_size" }                // PVOID* / PSIZE_T: values at enter and at leave
  | { k: "out_u32" } | { k: "out_ptr" } | { k: "i64ptr" }    // PULONG/PVOID* at leave; PLARGE_INTEGER at enter
  | { k: "client_id" }                                      // PCLIENT_ID → {pid, tid}
  | { k: "proc_params" }                                    // PRTL_USER_PROCESS_PARAMETERS → {image, command_line, cwd}
  | { k: "proc_info_out" }                                  // LPPROCESS_INFORMATION at leave → {pid, tid}
  | { k: "loadpath" }                                       // LdrLoadDll arg0: (v & 1) ? {flags:v} : {path: wstr}
  | { k: "procname" }                                       // PANSI_STRING name, or null → ordinal from arg 2
  | { k: "sockaddr"; len_arg: number } | { k: "out_sockaddr" }
  | { k: "wsabufs"; count_arg: number; when: "enter" | "leave" }
  | { k: "buf"; len_arg: number; when: "enter" | "leave"; len_from: "arg" | "ret" | "iosb" | "out_arg"; out_arg?: number }
  | { k: "fileinfo"; class_arg: number; len_arg: number }   // NtSetInformationFile payload by class
  | { k: "regdata"; type_arg: number; size_arg: number }    // NtSetValueKey data
  | { k: "kvinfo"; class_arg: number }                      // NtQueryValueKey output at leave (classes 1, 2)
  | { k: "addrinfo_out"; ex: boolean }                      // PADDRINFOW* / PADDRINFOEXW* at leave → ≤ 8 addresses
  | { k: "dnsreq" };                                        // PDNS_QUERY_REQUEST → {name, type}
export interface ApiArgSpec { name: string; d: ArgDecoder }
export interface ApiSpec {
  id: number; profile: ApiProfileName; sub: "core" | "io" | "track_handles" | "enumerate" | "query_key"
    | "resolve_procedures" | "frees" | "sections" | "dns" | "http" | "cross_process_memory" | "apc_and_context";
  module: ApiModule; export: string; args: readonly ApiArgSpec[];
  ret: "ntstatus" | "bool32" | "handle" | "ptr" | "i32" | "u32" | "socket" | "void";
  volume: "low" | "medium" | "high"; default_on: boolean;
  emit_when?: { arg: string; op: "eq" | "ne"; value: Hex };   // e.g. NtTerminateProcess ProcessHandle
  noreturn_when?: { arg: string; op: "eq"; value: Hex };      // self-terminate: emit at enter
  rows: boolean;                                               // false = cache maintenance only (NtClose)
  lazy_module: boolean;
  verified: "hooked+decoded" | "hooked" | "believed";
}
export const HOOK_DENY_LIST = [
  { module: "ntdll.dll", export: "NtAllocateVirtualMemory", reason: "deadlock-risk" },   // F8 (JS 3/3, CModule 1/1)
  { module: "kernelbase.dll", export: "VirtualAlloc", reason: "deadlock-risk" },        // F8 (2/2); kernel32 stub resolves here
] as const;
export const HOOK_CAUTION_LIST = [ /* §10.8 */ ] as const;
```

Name conventions:
- `handle` decoders add a sibling annotation key `<arg>_name`, the cached path or name.
- `oa` produces an object cell with `{root, root_name, name, path}`, where `path = root_name ? root_name + "\\" + name : name`.
- Flags and statuses stay raw numbers, decoded by the host (A15).

**The v0.1 catalog.** Positions are 0-based Win64 slots. "verified" refers to [S4-lab]:
- **H+D**: hooked and the listed args decoded on real calls;
- **H**: hooked safely, args not exercised;
- **B**: believed only, lab check A-21.

| id | Profile/sub | DLL!export | Args (slot:name:decoder) | Ret | Vol | Default | Verified |
|---|---|---|---|---|---|---|---|
| 1 | file/core | ntdll!NtCreateFile | 0 FileHandle out_handle(file), 1 DesiredAccess u32, 2 ObjectAttributes oa(file), 3 IoStatusBlock iosb, 4 skip, 5 FileAttributes u32, 6 ShareAccess u32, 7 CreateDisposition u32, 8 CreateOptions u32, 9 skip, 10 EaLength u32 | ntstatus | med | on | H+D (0,1,2,3,7,8) |
| 2 | file/core | ntdll!NtOpenFile | 0 out_handle(file), 1 DesiredAccess u32, 2 oa(file), 3 iosb, 4 ShareAccess u32, 5 OpenOptions u32 | ntstatus | med | on | H+D (0,1,2,5) |
| 3 | file/core | ntdll!NtQueryAttributesFile | 0 oa(file), 1 skip | ntstatus | med | on | H+D |
| 4 | file/core | ntdll!NtQueryFullAttributesFile | 0 oa(file), 1 skip | ntstatus | med | on | H |
| 5 | file/core | ntdll!NtSetInformationFile | 0 FileHandle handle(file), 1 skip, 2 FileInformation fileinfo(class 4, len 3), 3 Length u32, 4 FileInformationClass u32 | ntstatus | med | on | H+D (0,3,4); payload B |
| 6 | file/core | ntdll!NtQueryDirectoryFileEx | 0 handle(file), 1–5 skip, 6 Length u32, 7 FileInformationClass u32, 8 QueryFlags u32, 9 FileName ustr | ntstatus | med | on | H+D |
| 7 | file/core | ntdll!NtQueryDirectoryFile | 0 handle(file), 1–5 skip, 6 Length u32, 7 Class u32, 8 ReturnSingleEntry bool, 9 FileName ustr, 10 RestartScan bool | ntstatus | med | on | H |
| 8 | file/core | ntdll!NtDeleteFile | 0 oa(file) | ntstatus | low | on | B |
| 9 | file/io | ntdll!NtReadFile | 0 handle(file), 1–3 skip, 4 iosb, 5 Buffer buf(len 6, leave, from iosb), 6 Length u32, 7 ByteOffset i64ptr, 8 skip | ntstatus | high | off | H+D (0,6) |
| 10 | file/io | ntdll!NtWriteFile | 0 handle(file), 1–3 skip, 4 iosb, 5 Buffer buf(len 6, enter, from arg), 6 Length u32, 7 ByteOffset i64ptr, 8 skip | ntstatus | high | off | H+D (0,6) |
| 11 | file+registry/track_handles | ntdll!NtClose | 0 Handle ptr; `rows:false` (evicts the handle cache) | ntstatus | high | on | H |
| 20 | registry/core | ntdll!NtOpenKey | 0 out_handle(key), 1 DesiredAccess u32, 2 oa(key) | ntstatus | med | on | H+D |
| 21 | registry/core | ntdll!NtOpenKeyEx | 0 out_handle(key), 1 DesiredAccess u32, 2 oa(key), 3 OpenOptions u32 | ntstatus | med | on | H+D |
| 22 | registry/core | ntdll!NtCreateKey | 0 out_handle(key), 1 DesiredAccess u32, 2 oa(key), 3 TitleIndex u32, 4 Class ustr, 5 CreateOptions u32, 6 Disposition out_u32 | ntstatus | low | on | H (2) |
| 23 | registry/core | ntdll!NtQueryValueKey | 0 handle(key), 1 ValueName ustr, 2 KeyValueInformationClass u32, 3 KeyValueInformation kvinfo(class 2), 4 Length u32, 5 ResultLength out_u32 | ntstatus | med | on | H+D (0,1,2) |
| 24 | registry/core | ntdll!NtSetValueKey | 0 handle(key), 1 ValueName ustr, 2 TitleIndex u32, 3 Type u32, 4 Data regdata(type 3, size 5), 5 DataSize u32 | ntstatus | low | on | B |
| 25 | registry/core | ntdll!NtDeleteKey | 0 handle(key) | ntstatus | low | on | B |
| 26 | registry/core | ntdll!NtDeleteValueKey | 0 handle(key), 1 ValueName ustr | ntstatus | low | on | B |
| 27 | registry/core | ntdll!NtRenameKey | 0 handle(key), 1 NewName ustr | ntstatus | low | on | B |
| 28 | registry/enumerate | ntdll!NtEnumerateKey | 0 handle(key), 1 Index u32, 2 KeyInformationClass u32, 3 skip, 4 Length u32, 5 skip | ntstatus | med | off | B |
| 29 | registry/enumerate | ntdll!NtEnumerateValueKey | 0 handle(key), 1 Index u32, 2 Class u32, 3 skip, 4 Length u32, 5 skip | ntstatus | med | off | B |
| 30 | registry/query_key | ntdll!NtQueryKey | 0 handle(key), 1 KeyInformationClass u32, 2 skip, 3 Length u32, 4 skip | ntstatus | high | off | H+D |
| 40 | module/core | ntdll!LdrLoadDll | 0 DllPath loadpath, 1 skip, 2 DllName ustr, 3 DllHandle out_ptr | ntstatus | low | on | H+D |
| 41 | module/core | ntdll!LdrUnloadDll | 0 DllHandle ptr | ntstatus | low | on | B |
| 42 | module/resolve_procedures | ntdll!LdrGetProcedureAddressForCaller | 0 DllHandle ptr, 1 ProcedureName procname, 2 ProcedureNumber u32, 3 ProcedureAddress out_ptr, 4 Flags u32, 5 CallerAddress ptr | ntstatus | med | on | H+D (0,1,2) |
| 50 | memory/core | ntdll!NtProtectVirtualMemory | 0 ProcessHandle handle(process), 1 BaseAddress inout_ptr, 2 RegionSize inout_size, 3 NewProtect u32, 4 OldProtect out_u32 | ntstatus | med | on | H+D |
| 51 | memory/core | ntdll!NtAllocateVirtualMemoryEx | 0 handle(process), 1 inout_ptr, 2 inout_size, 3 AllocationType u32, 4 PageProtection u32, 5 skip, 6 ParamCount u32 | ntstatus | med | on | H |
| 52 | memory/core | kernelbase!VirtualAllocEx | 0 hProcess handle(process), 1 lpAddress ptr, 2 dwSize u64, 3 flAllocationType u32, 4 flProtect u32 | ptr | med | on | H |
| 53 | memory/core | kernelbase!VirtualAlloc2 | 0 Process handle(process), 1 BaseAddress ptr, 2 Size u64, 3 AllocationType u32, 4 PageProtection u32, 5 skip, 6 ParamCount u32 | ptr | med | on | H |
| 54 | memory/frees | ntdll!NtFreeVirtualMemory | 0 handle(process), 1 inout_ptr, 2 inout_size, 3 FreeType u32 | ntstatus | high | off | H+D |
| 55 | memory/sections | ntdll!NtMapViewOfSection | 0 SectionHandle handle(section), 1 ProcessHandle handle(process), 2 BaseAddress inout_ptr, 3 skip, 4 CommitSize u64, 5 SectionOffset i64ptr, 6 ViewSize inout_size, 7 InheritDisposition u32, 8 AllocationType u32, 9 Win32Protect u32 | ntstatus | med | off | B (hook safety untested: A-22) |
| 56 | memory/sections | ntdll!NtUnmapViewOfSection | 0 handle(process), 1 BaseAddress ptr | ntstatus | med | off | B |
| 60 | network/core | ws2_32!WSASocketW | 0 af i32, 1 type i32, 2 protocol i32, 3 skip, 4 g u32, 5 dwFlags u32 | socket | low | on | H+D (covers `socket()`) |
| 61 | network/core | ws2_32!WSASocketA | same as 60 | socket | low | on | B |
| 62 | network/core | ws2_32!bind | 0 s handle(socket), 1 name sockaddr(len 2), 2 namelen i32 | i32 | low | on | H+D |
| 63 | network/core | ws2_32!listen | 0 s handle(socket), 1 backlog i32 | i32 | low | on | H+D |
| 64 | network/core | ws2_32!connect | 0 s handle(socket), 1 name sockaddr(len 2), 2 namelen i32 | i32 | low | on | H+D |
| 65 | network/core | ws2_32!WSAConnect | 0 s, 1 name sockaddr(len 2), 2 namelen i32, 3–6 skip | i32 | low | on | H |
| 66 | network/core | ws2_32!accept | 0 s handle(socket), 1 addr out_sockaddr, 2 skip | socket | low | on | H+D |
| 67 | network/core | ws2_32!WSAAccept | 0 s, 1 addr out_sockaddr, 2–4 skip | socket | low | on | B |
| 68 | network/core | ws2_32!send | 0 s handle(socket), 1 buf buf(len 2, enter, arg), 2 len i32, 3 flags i32 | i32 | med | on | H+D |
| 69 | network/core | ws2_32!WSASend | 0 s, 1 lpBuffers wsabufs(count 2, enter), 2 dwBufferCount u32, 3 sent out_u32, 4 dwFlags u32, 5 lpOverlapped ptr, 6 skip | i32 | med | on | H+D (0,1,2) |
| 70 | network/core | ws2_32!sendto | 0 s, 1 buf buf(len 2, enter, arg), 2 len i32, 3 flags i32, 4 to sockaddr(len 5), 5 tolen i32 | i32 | med | on | H+D |
| 71 | network/core | ws2_32!WSASendTo | 0 s, 1 wsabufs(count 2, enter), 2 count u32, 3 sent out_u32, 4 flags u32, 5 lpTo sockaddr(len 6), 6 iTolen i32, 7 lpOverlapped ptr, 8 skip | i32 | med | on | H |
| 72 | network/core | ws2_32!recv | 0 s, 1 buf buf(len 2, leave, ret), 2 len i32, 3 flags i32 | i32 | med | on | H+D |
| 73 | network/core | ws2_32!WSARecv | 0 s, 1 wsabufs(count 2, leave), 2 count u32, 3 recvd out_u32, 4 skip, 5 lpOverlapped ptr, 6 skip | i32 | med | on | H |
| 74 | network/core | ws2_32!recvfrom | 0 s, 1 buf buf(len 2, leave, ret), 2 len i32, 3 flags i32, 4 from out_sockaddr, 5 skip | i32 | med | on | H+D |
| 75 | network/core | ws2_32!WSARecvFrom | 0 s, 1 wsabufs(count 2, leave), 2 count u32, 3 recvd out_u32, 4 skip, 5 lpFrom out_sockaddr, 6 skip, 7 lpOverlapped ptr, 8 skip | i32 | med | on | B |
| 76 | network/core | ws2_32!closesocket | 0 s handle(socket) | i32 | low | on | H+D |
| 77 | network/dns | ws2_32!GetAddrInfoW | 0 pNodeName wstr, 1 pServiceName wstr, 2 skip, 3 ppResult addrinfo_out(ex:false) | i32 | low | on | H+D (covers `getaddrinfo`) |
| 78 | network/dns | ws2_32!GetAddrInfoExW | 0 pName wstr, 1 pServiceName wstr, 2 dwNameSpace u32, 3 skip, 4 skip, 5 ppResult addrinfo_out(ex:true), 6 skip, 7 lpOverlapped ptr, 8–9 skip | i32 | low | on | H |
| 79 | network/dns | ws2_32!gethostbyname | 0 name astr | ptr | low | on | B |
| 80 | network/dns | dnsapi!DnsQueryEx | 0 pQueryRequest dnsreq, 1–2 skip | i32 | low | on | H (struct B) |
| 81 | network/dns | dnsapi!DnsQuery_W | 0 pszName wstr, 1 wType u32, 2 Options u32, 3–5 skip | i32 | low | on | H |
| 82 | network/http | winhttp!WinHttpConnect | 0 hSession handle(inet), 1 pswzServerName wstr, 2 nServerPort u32, 3 skip | handle | low | off | B (lazy) |
| 83 | network/http | winhttp!WinHttpOpenRequest | 0 hConnect handle(inet), 1 pwszVerb wstr, 2 pwszObjectName wstr, 3 pwszVersion wstr, 4–5 skip, 6 dwFlags u32 | handle | low | off | B (lazy) |
| 84 | network/http | winhttp!WinHttpSendRequest | 0 hRequest handle(inet), 1 lpszHeaders wstr, 2 dwHeadersLength u32, 3 lpOptional buf(len 4, enter, arg), 4 dwOptionalLength u32, 5 dwTotalLength u32, 6 skip | bool32 | low | off | B (lazy) |
| 85 | network/http | wininet!InternetConnectW | 0 hInternet handle(inet), 1 lpszServerName wstr, 2 nServerPort u32, 3 skip, **4 password skip (never captured)**, 5 dwService u32, 6 dwFlags u32, 7 skip | handle | low | off | B (lazy) |
| 86 | network/http | wininet!HttpOpenRequestW | 0 hConnect handle(inet), 1 lpszVerb wstr, 2 lpszObjectName wstr, 3 lpszVersion wstr, 4–5 skip, 6 dwFlags u32, 7 skip | handle | low | off | B (lazy) |
| 87 | network/http | wininet!InternetOpenUrlW | 0 hInternet handle(inet), 1 lpszUrl wstr, 2 skip, 3 dwHeadersLength u32, 4 dwFlags u32, 5 skip | handle | low | off | B (lazy) |
| 100 | process/core | kernelbase!CreateProcessInternalW | 0 skip, 1 lpApplicationName wstr, 2 lpCommandLine wstr(max 4096), 3–4 skip, 5 bInheritHandles bool, 6 dwCreationFlags u32, 7 skip, 8 lpCurrentDirectory wstr, 9 skip, 10 lpProcessInformation proc_info_out, 11 skip | bool32 | low | on | H+D (1,2,6) |
| 101 | process/core | ntdll!NtCreateUserProcess | 0 out_handle(process), 1 out_handle(thread), 2 ProcessDesiredAccess u32, 3 ThreadDesiredAccess u32, 4–5 skip, 6 ProcessFlags u32, 7 ThreadFlags u32, 8 ProcessParameters proc_params, 9–10 skip | ntstatus | low | on | H (decode B) |
| 102 | process/core | ntdll!NtOpenProcess | 0 out_handle(process), 1 DesiredAccess u32, 2 skip, 3 ClientId client_id | ntstatus | low | on | H+D |
| 103 | process/core | ntdll!NtTerminateProcess | 0 ProcessHandle handle(process), 1 ExitStatus u32; `emit_when` ProcessHandle ne 0x0; `noreturn_when` eq 0xffffffffffffffff | ntstatus | low | on | B |
| 104 | process/core | ntdll!NtCreateThreadEx | 0 out_handle(thread), 1 DesiredAccess u32, 2 skip, 3 ProcessHandle handle(process), 4 StartRoutine ptr, 5 Argument ptr, 6 CreateFlags u32, 7 skip, 8 StackSize u64, 9 MaxStackSize u64, 10 skip | ntstatus | low | on | H+D (3,4) |
| 105 | process/cross_process_memory | ntdll!NtWriteVirtualMemory | 0 handle(process), 1 BaseAddress ptr, 2 skip, 3 NumberOfBytesToWrite u64, 4 skip; `emit_when` ProcessHandle ne 0xffffffffffffffff | ntstatus | med | off | B |
| 106 | process/cross_process_memory | ntdll!NtReadVirtualMemory | same as 105 | ntstatus | med | off | B |
| 107 | process/apc_and_context | ntdll!NtQueueApcThread | 0 handle(thread), 1 ApcRoutine ptr, 2–4 Arg ptr | ntstatus | low | off | B |
| 108 | process/apc_and_context | ntdll!NtSetContextThread | 0 handle(thread), 1 skip | ntstatus | low | off | B |

**Decoder layouts.** Offsets are VERIFIED (F9) unless marked B.
- `oa`: `RootDirectory +0x8`, `ObjectName (PUNICODE_STRING) +0x10`, `Attributes +0x18`.
- `ustr`/`anstr`: `Length u16 +0`, `Buffer +8`. Characters read = `Length/2` for UNICODE and `Length` for ANSI,
  capped by `max`.
- `iosb`: `Information u64 +8` at leave.
- `client_id`: `UniqueProcess +0`, `UniqueThread +8`.
- `sockaddr`: `family u16 +0`. AF_INET (2): `port` big-endian u16 at `+2`, IPv4 at `+4`. AF_INET6 (23, B): port `+2`,
  address 16 B at `+8`, `scope_id +24`. Other families give `{family}`.
- `wsabufs`: WSABUF `{len u32 +0, buf ptr +8}`, 16 B per entry. Total length plus `capture_payload_bytes` from the
  first buffers.
- `addrinfo_out` (B):
  - ADDRINFOW: `ai_family +4`, `ai_addr +32`, `ai_next +40`.
  - ADDRINFOEXW: `ai_addr +32`, `ai_next +64`.
  - At most 8 entries; only on rc == 0.
- `dnsreq` (B): DNS_QUERY_REQUEST `{Version u32 +0, QueryName PCWSTR +8, QueryType u16 +16}`.
- `proc_params` (B): RTL_USER_PROCESS_PARAMETERS `CurrentDirectory.DosPath +0x38`, `ImagePathName +0x60`,
  `CommandLine +0x70` (UNICODE_STRINGs; Buffer may be offset-relative when the struct is not normalized: flag at `+8`
  bit 0).
- `proc_info_out` (B): PROCESS_INFORMATION `dwProcessId u32 +0x10`, `dwThreadId u32 +0x14`.
- `kvinfo` (B):
  - class 2 (PARTIAL): `Type u32 +4`, `DataLength u32 +8`, `Data +0xC`;
  - class 1 (FULL): `Type +4`, `DataOffset +8`, `DataLength +0xC`;
  - data capped by `capture_value_bytes`. REG_SZ/EXPAND_SZ are decoded as UTF-16 text, REG_DWORD as u32, REG_QWORD as
    Hex, anything else as bytes.
- `regdata`: the same value rules, taken from the `Type`/`Data`/`DataSize` arguments.
- `fileinfo` (B):
  - classes 10/65 (rename): FILE_RENAME_INFORMATION `Flags u32 +0`, `RootDirectory +8`, `FileNameLength u32 +0x10`,
    `FileName +0x14`;
  - 13 (disposition): `DeleteFile u8 +0`; 64 (disposition ex): `Flags u32 +0` (bit 0 DELETE);
  - 20 (end of file): `EndOfFile i64 +0`;
  - 4 (basic): attributes `u32 +0x20`;
  - any other class: `{class}` only.
- `loadpath`: LdrLoadDll arg 0 was `0x1` in the lab (a flags form, F9). An odd value is reported as `{flags}`;
  otherwise it is a PWSTR search path (B).
- `procname`: a null `ProcedureName` means ordinal = arg 2 (`ProcedureNumber`).

### 10.6 Profile runtime (`profiles.ts`)

**Install.** `profileInstall({profiles, options, lifetime})`:
1. Select catalog entries: `spec.profile ∈ profiles`, and (`spec.sub == "core"` or the sub-option enabled). `NtClose`
   comes in when `file` or `registry` is selected and `track_handles` is not false.
2. Resolve each `module!export`. A missing module is queued in `pending` if `lazy_module`; otherwise the entry is
   `failed`.
3. `install()` each one (§10.2), sharing **one** instrument (`p<n>`) and **one** stream (`api/1`).
4. Return installed, pending, denied and failed.

**Lazy modules** (winhttp, wininet, and dnsapi if absent). On a `module/1` load for one of these, the JS thread (via
`setImmediate`, never inside the loader callback, §8.1) installs the pending entries and sends
`{bea:"instrument", event:"lazy-installed", detail:{apis}}`. ws2_32 and dnsapi are normally already loaded, because
Frida's injection loads WS2_32 and DNSAPI [ext-frida §4].

**Generic listener** (one closure per ApiSpec).

`onEnter(args)`:
1. detached guard → `Cloak.hasCurrentThread()` → `agentCallTids` → thread filter →
   `perApi[id] < per_api_max_events` (else `per_api_cap` drop) → `emit_when`.
2. `this.g = nextG()`; `this.t = nowUs()`; push `this.g` on `tstack[tid]` (parent tracking).
3. Decode the enter-time args into `this.a`.
4. Save the pointers needed at leave (`out_handle`, `inout`, `iosb`, `buf` with `when:"leave"`).
5. If `noreturn_when` matches: emit now (ret `null`) and pop.

`onLeave(retval)`:
1. Decode the leave-time args.
2. `ret` = NTSTATUS as Hex (u32), or BOOL/int/handle/ptr.
3. On success, insert handles into the cache (§ handle cache).
4. Pop `tstack`; `parent` = the new top or 0.
5. Emit `ApiRow`.

**Handle cache** (`Map<HexHandle, {kind, name, g}>`, ≤ `handle_cache_entries` 65,536; on overflow drop the oldest
25%):
- *Inserts*: successful `out_handle` decoders, with the resolved `oa` path or `name`. `WSASocketW` and `accept` insert
  `socket`; `WinHttpConnect` inserts `inet` `"host:port"`.
- *Evicts*: `NtClose` (row-less listener), `closesocket`.
- *Annotations*: `handle(kind)` decoders add `<arg>_name` from the cache, or `null` with `<arg>_src:"unresolved"`.
  Handles opened before the profile was installed are therefore unresolved. The agent never calls `NtQueryObject` on
  files (A-23: name queries on synchronous pipes can hang).
- *Registry roots* are resolved even when missing from the cache: `NtQueryKey(root, KeyNameInformation=3)` is called
  from inside the hook (F10). It is safe from recursion (F3) and the result is cached. Predefined HKEY values never
  reach ntdll (F10).
- *Duplicated and inherited handles* are not tracked (limitation).

**Deduplication** (opt-in `dedupe_window_ms`). A key of `(api, JSON(args), ret, tid)` within the window increments
`repeat` on the pending row instead of emitting. Without it, the 45-probe DLL search (F16) yields 45 rows, all
parented to the `LdrLoadDll` row.

**Volume.**
- Default-on entries are low or medium volume. `io`, `frees`, `query_key` and `enumerate` are opt-in.
- `per_api_max_events` (default 10,000) bounds noisy APIs per instrument, and the instrument's `max_hits` bounds the
  total.
- Drops are counted per reason, so coverage is honest ("not observed" is never "did not happen").

**Payloads.** `capture_payload_bytes` (network), `capture_bytes` (file io) and `capture_value_bytes` (registry) all
default to **0**. Payload capture is opt-in, because it can expose user data. The host's explicit-literal redaction
also applies to rows before storage [rea-evidence §10.10].

### 10.7 Memory-map watcher (`memmap/1` on `s:memmap`)

- **Why.** `NtAllocateVirtualMemory` and `VirtualAlloc` cannot be hooked (F8). A plain
  `VirtualAlloc(PAGE_EXECUTE_READWRITE)` is therefore invisible to hooks.
- **How.** When the memory profile is active and `exec_region_scan_ms > 0` (default 1000), a JS-thread timer runs
  `Process.enumerateRanges('--x')` and diffs it against the previous set by `base`:
  - new executable regions not covered by a module → `new-exec`, or `new-rwx` if writable;
  - vanished regions → `gone`;
  - protection changes on tracked regions → `prot-change`.
- **Cost guard.** If one enumeration takes longer than 20 ms, the interval doubles (up to 10 s). The watcher stops with
  the instrument.
- **Semantics.** This is *sampled* state, not an event log. Short-lived regions can be missed, and the limitation says
  so. `NtProtectVirtualMemory` events (hooked, VERIFIED) catch the common RW→RX flip exactly.

### 10.8 Hook safety policy (applies to `hookInstall`, profiles and overrides)

**Deny list.** Resolved at `hello`, and checked after thunk resolution, so `kernel32!VirtualAlloc` (a stub) is caught
too. Both are VERIFIED (F8):
- `ntdll!NtAllocateVirtualMemory`;
- `kernelbase!VirtualAlloc`.

Each refusal suggests an alternative: `memory` profile (`NtProtectVirtualMemory`, `VirtualAllocEx`/`VirtualAlloc2`,
memmap watcher), or a debug-register execute breakpoint for occasional observation.

**Caution list.** Allowed only with `force_caution:true`, and the result carries a warning limitation. These are
BELIEVED risky because Frida's runtime, the loader or exception dispatch sit on them; none was tested (A-24):
- `ntdll!RtlAllocateHeap`, `RtlFreeHeap`, `RtlReAllocateHeap`, `RtlSizeHeap`;
- `RtlEnterCriticalSection`, `RtlLeaveCriticalSection`, `RtlTryEnterCriticalSection`, `RtlAcquireSRWLockExclusive`,
  `RtlReleaseSRWLockExclusive`, `RtlAcquireSRWLockShared`, `RtlReleaseSRWLockShared`;
- `NtWaitForSingleObject`, `NtWaitForMultipleObjects`, `NtSetEvent`, `NtResetEvent`, `NtReleaseSemaphore`,
  `NtDelayExecution`, `NtYieldExecution`;
- `NtContinue`, `NtRaiseException`, `RtlRaiseException`, `KiUserExceptionDispatcher`, `RtlDispatchException`,
  `RtlUnwindEx`, `RtlVirtualUnwind`, `RtlLookupFunctionEntry`;
- `LdrInitializeThunk`, `RtlUserThreadStart`, `kernelbase!BaseThreadInitThunk`, `RtlExitUserThread`;
- `ntdll!NtQueryVirtualMemory`, `kernelbase!VirtualQuery` (the agent's own guard checks use them; F3 covers recursion
  only within a listener).

**Also safe.** Every API with verified ≥ H in §10.5, plus `NtClose`, `NtDeviceIoControlFile` and
`NtDuplicateObject` (F8). This is a living list: new deadlock findings go into the deny list with a fixture
reproducing them (§19).

---

## 11. Watchpoints (`watch.ts`, `hwbp.ts`, `pageguard.ts`)

### 11.1 Choosing a method

| Need | Method | Why |
|---|---|---|
| "Who writes or reads this 1–8-byte variable", across all threads, with low overhead | `debug-register` | Hardware, per-thread, 4 slots. Trap-after semantics, so the writer is recovered by sweeping. VERIFIED [ext-frida §3.9] |
| A struct or range wider than 8 bytes, more than 4 concurrent watches, the exact instruction without sweeping, or code-page execute tracing | `page-guard` | BEA's PAGE_GUARD + TF re-arm. Lossless in the lab, reports the exact faulting instruction with before/after values, costs two exceptions per access to the page (F19) |
| Execute breakpoint on a function Interceptor cannot patch, without changing code bytes | `debug-register` + `access:"execute"` | RF flag prevents re-trigger. VERIFIED [ext-frida §3.9] |

`MemoryAccessMonitor` is **not** the default:
- it is lossy (≈43 events/s, re-armed through `setImmediate` [ext-frida §3.10]);
- it is a process-wide singleton;
- it gives no before/after values.

It is available as `engine:"access-monitor"` (§11.3.1) for targets where trap-flag steps misbehave (A-26). The two
engines are never armed on the same page.

### 11.2 Debug registers (`hwbp.ts`)

**Slots.** `slots[0..3] = {owner, kind: "watch" | "exec", address, size, rw, state: "free" | "armed" | "disarming" | "quarantined", shadow: ArrayBuffer | null}`.
Breakpoints and watchpoints share the 4 slots [ext-frida §3.9].

**Validation.** Frida validates nothing [ext-frida §3.9]. An invalid input returns `WatchInvalid{reason}`, and a
missing free slot returns `NoFreeDebugRegister{in_use}`.
- `slot ∈ {0,1,2,3}`. A requested slot that is busy is an error; otherwise the lowest free slot is used.
- `size ∈ {1,2,4,8}` and `address % size == 0`. Frida silently aligns down, which mis-attributes neighbours (VERIFIED).
- `access`:
  - `write` → `'w'` (RW=01);
  - `read-write` → `'rw'` (RW=11). `'r'` is never sent; hardware treats it as `rw` (VERIFIED);
  - `execute` → `setHardwareBreakpoint`, with size forced to 1.
- The address must not be in a cloaked range: `Cloak.hasRangeContaining` → `WatchInvalid{agent-page}`.

**DR7 arithmetic** (matches the encodings VERIFIED in a17):

```
enableMask(s) = 0b11 << (2*s)                 // L_s | G_s
ctrlMask(s)   = 0b1111 << (16 + 4*s)          // RW_s | LEN_s
LEN: 1→00, 2→01, 4→11, 8→10                   // a17: 0x90101 = L0 + LE + RW0=01 + LEN0=10 (8-byte write)
```

**Arm.**
1. Allocate the slot. Set `shadow = readByteArray(address, size)`, which supplies "before" for the first hit.
2. For every `t` in `threads.enumerate()` (or the requested tid list): `t.setHardwareWatchpoint(slot, address, size, rw)`
   or `t.setHardwareBreakpoint(slot, address)`. Errors are collected per thread in `arm_errors`, since threads can exit.
3. Ensure the thread observer exists (§5.6). For `threads:"all"`, `onAdded(t)` arms every armed slot on the new thread
   (`onAdded` runs on that thread, VERIFIED [ext-frida §3.9]).
4. Verify: read DR0–3 and DR7 through `threads.context(tid, CONTEXT_DEBUG_REGISTERS)` on up to `hwbp_verify_threads`
   (64) threads. The slot's address and control bits must be present. The result is reported as `verified`.

**Trap handling.** `hwbp.ownsTrap(d)` is `(dr6 & 0xF & armedOrDisarmingMask) != 0` with `dr6 = nativeContext+0x68`
(VERIFIED offset). `onTrap(d, tid)` handles every owned bit `s` set in DR6:
- `exec` slot: `pc = d.address`, which is the breakpoint address (fault before execution).
  - Emit a `WatchRow` with access `x`, `insn = pc`, `conf:"exact"`.
  - If the slot is armed: `EFlags |= 0x10000` (RF) at `nativeContext+0x44`, so the instruction executes once without
    re-trapping. VERIFIED: one trap per call [ext-frida §3.9].
  - If the slot is disarming or `max_hits` was reached: clear `enableMask|ctrlMask` in nc DR7 and zero `DR_s`, instead
    of setting RF (one-shot).
- `watch` slot: `pcAfter = d.context.pc`, the next instruction (trap-after, VERIFIED).
  - `{insn, conf, text} = findAccessInsn(pcAfter)` (§8.4).
  - `after = readByteArray(address, size)`, `before = shadow`, then `shadow = after`. Handlers are serialized by the JS
    lock, so the shadow is consistent across threads.
  - `access` = `w` for a write slot. For an `rw` slot it is `w` if `before != after`, else `r`; a write of the same
    value then reads as `r` (documented limitation).
  - Registers (`gpr`, explicit list) and backtrace (`Thread.backtrace(d.context, ACCURATE)`) are added when requested.
  - Emit a `WatchRow`.
- Always clear the B0–B3 bits in nc DR6 (`+0x68`) after handling (A-27). Return `true`.

**Disarm** (stop or max_hits). This is the VERIFIED reliable protocol, 8/8 against 3–5/8 failures for API-only unset
[ext-frida §3.9 a6d]:
1. `state = "disarming"`. While a slot is disarming, every owned trap on any thread runs the handler-side clear
   (`DR7 &= ~(enableMask|ctrlMask)`, `DR_s = 0`) on the CONTEXT that will be restored.
2. From the JS thread, call `t.unsetHardwareWatchpoint(slot)` or `unsetHardwareBreakpoint(slot)` on every thread. This
   covers threads that are not trapping.
3. Detach the thread observer when no slot remains armed.
4. After 150 ms, verify through `GetThreadContext` (exclusive scheduling) on up to 64 threads.
   - Any thread still showing the slot's bits: retry `unset*`, up to 3 rounds of 150 ms.
   - Still set after that: `state = "quarantined"`. The slot is never reused this session. The handler keeps swallowing
     its traps (clear in handler, return `true`), `summary.verification.ok = false`, and
     `NoticeMessage{hwbp-unreverted}` is sent. The host maps this to `effect_unreverted`.
5. Otherwise `state = "free"`.

**Limits and notes.**
- Per-thread semantics are inherent [ext-frida §3.9]. Threads created by other means and never seen by the observer
  are impossible in-process, because `onAdded` covers every new thread.
- The agent thread is never armed: it is cloaked and filtered out.
- A hit on a Stalker-followed thread reports `pcAfter` inside Stalker's code cache. `findAccessInsn` then fails and
  gives `conf:"unknown"` (limitation). Avoid combining a trace and a watch on the same thread.

### 11.3 Page-guard watches (`pageguard.ts`): PAGE_GUARD + trap flag (F19)

**State.**
```ts
interface GuardPage { base: NativePointer; origProtect: number; watches: Set<InstrumentId>; armed: boolean; rearmFails: number }
pages: Map<string /* page hex */, GuardPage>;
pendingSteps: Map<ThreadId, { pages: string[]; hits: PendingHit[] }>;
interface PendingHit { watch: InstrumentId; insn: NativePointer; op: "read" | "write" | "execute"; addr: NativePointer; before: ArrayBuffer | null }
```

**Arm.** `watchInstall({method:"page-guard", address, size ≤ 65536, access})`:
1. `pagesOf(address, size)` (4 KiB each, at most `page_guard_max_pages` = 64 in total). For each page run
   `VirtualQuery`, then refuse with `WatchInvalid` if:
   - the page is not committed (`range`);
   - it already has `PAGE_GUARD`, i.e. the target's own guard (`range`);
   - it lies inside any thread stack, between TEB `StackLimit` and `StackBase`, for all threads (`stack-page`, A-28);
   - it is cloaked (`agent-page`);
   - it is a module code page and `access` is not `execute` (`module-code`).

   An execute watch on code pages is allowed but expensive.
2. `VirtualProtect(page, 4096, origProtect | PAGE_GUARD 0x100, &old)` through the exclusive `win32` binding. Record
   `origProtect`. `before` values are read before arming.

**`onGuard(d, tid)`** (dispatcher `type:"guard-page"`, `d.memory.address` inside a BEA page):
1. Fetch the page entry and set `entry.armed = false`; the OS cleared the guard bit for this access (F19).
2. For each watch on the page whose `[address, address+size)` contains `d.memory.address` and whose access filter
   matches `d.memory.operation`:
   - push `{watch, insn: d.address, op, addr: d.memory.address, before: read(watch range)}`. The page is unguarded now,
     so the read is safe.
   - `insn` is the **faulting instruction itself**, so no sweep is needed (F19).

   Other accesses to the same page increment the watch's `filtered` counter.
3. `nativeContext.add(0x44)`: `EFlags |= 0x100` (TF). Append `{page, hits}` to `pendingSteps[tid]`; one instruction
   can touch two guarded pages. Return `true`, so the instruction re-executes unguarded.

**`onStep(d, tid)`** (dispatcher `single-step` with `pendingSteps.has(tid)`):
1. Take and delete `pendingSteps[tid]`. For each hit: `after = read(range)`, then emit a `WatchRow`:
   `[g, t, tid, watch, op → "r"/"w"/"x", insn, "exact", null, text = decodeAt(insn).toString(), addr, before, after, regs?, bt?]`.
2. For each page whose watches are still active, re-apply `origProtect | PAGE_GUARD` and set `armed = true`; a failure
   counts `rearmFails`.
3. Clear TF (`EFlags &= ~0x100`) and DR6. Return `true`.

**Verifier.** Every 250 ms while any page is armed, on the JS thread: `VirtualQuery` each armed page. A page that lost
`PAGE_GUARD` while no thread has a pending step for it is re-armed and counts `kernel_access_suspected` (A-29). The
cause is usually a syscall touching the page from kernel mode, which consumes the guard without a user-mode exception.

**Disarm.** Remove the watch from its pages. Pages with no watches left are restored to `origProtect` (if still
guarded) and verified with `VirtualQuery`. A step still pending for a removed page sees the watch inactive and does
not re-arm.

**Coexistence and limits.**
- Agent reads of BEA pages use `pageGuard.suspendFor(range, fn)` (§8.2): unguard, read, re-guard. A target access in
  that window is missed and counted in `suspend_windows`.
- Each access costs two exceptions. The lab saw 810 pairs in 1 s on a 30 fps fixture with the target healthy (F19).
  Hot pages need small `max_hits` and short durations.
- A target's syscalls into a guarded page may fail with a guard-page status (A-29). Prefer debug registers for I/O
  buffers.
- With TF steps pending, a debug-register trap on the same instruction is handled by both handlers (§7.2).

#### 11.3.1 `engine:"access-monitor"` (fallback)

This engine multiplexes `MemoryAccessMonitor`, a process-wide singleton, over the union of all access-monitor watch
pages:
- When the set changes: `disable()`, then `enable(unionRanges, {onAccess})`.
- `onAccess(d)` routes by `d.address` into the watches, using `d.from` as the exact instruction
  [ext-frida §3.10]. It then schedules one coalesced re-arm through `setImmediate` (disable + enable).

Limitations:
- Hits are **sampled**, not complete: about 43/s, once per page per arm. Rows say `insn_conf:"exact"` but the
  stream manifest carries the limitation `sampled-page-guard`.
- No before/after values: the access has already completed when `onAccess` runs, so `before` is null.

Use it only when trap-flag single-steps conflict with the target, for example anti-debug code that inspects TF.

### 11.4 Watch rows and results

- Every hit is one `watch/1` row on the watch's stream.
- `WatchInstallResult` gives `slot` (debug-register) or `pages` (page-guard), `armed_threads`, `verified` and
  `initial_value`.
- `effect.kind` is `watchpoint-set`, `breakpoint-set` or `guard-page-set`, all reversible.
- The host's "walk-back" recipe (watch writes → access instruction → struct base → pointer scan) is skill-level
  guidance [ext-landscape §7.1]. The agent supplies the parts: exact instructions with operands
  (`disassemble {operands:true}` gives `mem` base and displacement), `scanStart {kind:"pointers-to"}`, and
  `readTyped {chain}`.

---

## 12. Stalker (`stalker.ts`)

### 12.1 StalkerCoordinator (core service)

- `followed: Map<ThreadId, {owner: InstrumentId | "call", since: TimeUs}>` and
  `settling: Map<ThreadId, TimeUs /* free after */>`.
- **Queue settings.** Before the **first** follow of the agent's lifetime set `Stalker.queueCapacity` and
  `Stalker.queueDrainInterval`. The defaults are `1 << 21` and `50`, the VERIFIED loss fix: 64,000/64,000 events
  instead of 3–6% loss [ext-frida §3.8]. The values are global, so they are only ever raised, never lowered while
  anything is followed.
- **`invalidateAll(addresses)`.** For every followed tid and every address, `Stalker.invalidate(tid, addr)`. It is
  called after **every** Interceptor attach/detach/replace/revert and every code patch by BEA. VERIFIED: without
  invalidate a new hook is invisible to a followed thread, and detaching a hook while following crashed the target
  1 time in 4; with invalidate, 0 crashes in 4 [ext-frida §3.8].
- **`claim(tid, owner)`** refuses with `StalkerBusy{retry_after_ms}` when the thread is followed or still settling.
  The agent thread is never offered to trace sessions; `call.ts` claims it for per-call coverage only.

### 12.2 Modes

| Mode | Follow options | Agent processing | Rows | Cost (VERIFIED basis) |
|---|---|---|---|---|
| `coverage` | `events:{compile:true}`, `onReceive(raw)` | `Stalker.parse(raw, {annotate:false, stringify:false})` gives `[start, end]` pairs. Keep pairs whose start is inside `modules`. Dedupe with `Set(startHex)`, ≤ `stalker_max_blocks` (1M); beyond that, drop with `instrument_cap`. Append to a JS binary buffer | `block-span/1` | Negligible: 481 blocks in 600 ms, no FPS cost [ext-frida §3.8] |
| `block_counts` | `transform: core.bea_bc_transform`, `data: bcConfig` | None per block. C counts per block (§12.3). At stop, and every 1 s, JS snapshots the used slab | `block-count/1` | CModule callout per block; exact counts VERIFIED [ext-frida §3.8 a5e] |
| `call_summary` | `transform: core.bea_cs_transform`, `data: csConfig` | None per call. C counts per call site (§12.3). At stop, and every 1 s, JS snapshots the used slab | `call-site-count/1` | One callout per executed call (CModule) |
| `call_events` | `events:{call:true}`, `onReceive(raw)` | Raw passthrough. The data `ArrayBuffer` is appended as-is, with no JS parse | `gum-event-x64/1` | **About 90x slowdown** on call-heavy code [ext-frida §3.8]. Duration default 5 s, hard 30 s |

- `exclude_modules` maps to `Stalker.exclude({base, size})` per module (accepted, VERIFIED). Exclusions are
  process-global and cannot be undone in GumJS (A-30). They are tracked and reported in `excluded`, and only module
  ranges the caller named are excluded.
- `onCallSummary` is not used: it came back empty in one VERIFIED run and is best-effort [ext-frida §3.8]. The
  `call_summary` mode replaces it with exact CModule counting.

### 12.3 `bea_bc_transform` (C, in the core CModule)

```c
typedef struct { guint64 start, end; volatile gint64 count; } BeaBlock;           /* 24 B: matches block-count/1 */
typedef struct { BeaBlock * slab; volatile gint64 used; gint64 cap; volatile gint64 overflow;
                 guint32 nmods; guint64 lo[16], hi[16]; } BeaBc;
static void bea_bc_hit (GumCpuContext * cpu, gpointer user_data) { g_atomic_pointer_add (&((BeaBlock *) user_data)->count, 1); }
void bea_bc_transform (GumStalkerIterator * it, GumStalkerOutput * out, gpointer user_data) {
  BeaBc * bc = user_data; cs_insn * insn; gboolean first = TRUE; BeaBlock * cur = NULL; guint64 last = 0;
  while (gum_stalker_iterator_next (it, &insn)) {
    if (first) {
      first = FALSE;
      if (bea_in_mods (bc, insn->address)) {
        gint64 i = g_atomic_pointer_add (&bc->used, 1);
        if (i < bc->cap) { cur = &bc->slab[i]; cur->start = insn->address; cur->count = 0;
                           gum_stalker_iterator_put_callout (it, bea_bc_hit, cur, NULL); }
        else g_atomic_pointer_add (&bc->overflow, 1);
      }
    }
    last = insn->address + insn->size;
    gum_stalker_iterator_keep (it);
  }
  if (cur != NULL) cur->end = last;
}
```

- Stalker blocks are dynamic blocks: they split after `call` and do not split at join points [ext-frida §3.8]. The
  host maps them to static CFG blocks by range overlap.
- A recompiled block, after `invalidate` or GC, gets a new slot. The host sums counts by `start`.
- Passing per-block data to `put_callout` is BELIEVED (A-31). The VERIFIED a5e variant passed `NULL` and keyed on a
  global.

**`bea_cs_transform`** (call summary) has the same structure. For each instruction with `insn->id == X86_INS_CALL`
whose **site** is inside the selected modules, it takes a slot `{site = insn->address, target, count}`:
- `target` is the immediate for `call rel32`, read from `insn->detail->x86.operands[0].imm`;
- `target` is 0 for indirect calls;
- it calls `put_callout(it, bea_cs_hit, slot, NULL)` **before** `keep()`, so the count includes calls that never return.

A slab of 24-byte slots matches `call-site-count/1`. The host sums counts per target, and reports indirect sites by
site. Reading Capstone operand details from TinyCC is BELIEVED (A-43); the fallback is to count every `call` site with
`target = 0` and resolve targets on the host by disassembly.

### 12.4 Start and stop protocol

**Start** (`traceStart`):
1. `claim()` each tid.
2. Set the queue (§12.1).
3. Build the mode's options. For `block_counts`, allocate `BeaBc` with `cap = stalker_max_blocks` (24 MiB at 1M) and
   pin it in `keep`.
4. `Stalker.follow(tid, opts)` for each tid.
5. Register the instrument, its stream and the deadline.

**Stop** (`instrumentStop`, duration, `max_hits` = maximum rows):
1. `Stalker.unfollow(tid)` for each tid, then `Stalker.flush()`.
2. Wait `2 × drain_ms` (`setTimeout`); the last `onReceive` batches arrive asynchronously (the lab waited 100 ms
   [ext-frida §3.7, §7]).
3. `block_counts`: snapshot the slab `[0, min(used, cap))` → `block-count/1` (final), plus
   `overflow → dropped.instrument_cap`.
4. `Stalker.garbageCollect()`. Mark the tids `settling` for `stalker_settle_ms` (300 ms; VERIFIED advice before
   re-following [ext-frida §3.8]).
5. Release the CModule and NativeCallbacks from `keep` only after the settle. VERIFIED: QJS freed an out-of-scope
   CModule while a thread was still in Stalker code and crashed the target 2 times in 2 [ext-frida §3.8].

**Thread exit** while followed: a `thread/1` `E` row removes the tid from `followed`. When no threads remain, the
instrument ends with `reason:"thread-exit"`.

---

## 13. In-process oracle calls (`call.ts`, gate `call_function`)

### 13.1 Signature mapping and the NativeFunction cache

| BEA `CallType` | Frida type | Argument input (`CallArgValue`) | Return output |
|---|---|---|---|
| i8/u8/i16/u16/i32/u32 | int8 … uint32 | number, or decimal/Hex string | `TypedOut{value:number}` |
| i64/u64 | int64/uint64 | Hex or decimal string (exact; built with `int64()`/`uint64()`), or a safe number | `value` as a decimal string, `bits` as Hex |
| bool8/bool32 | bool / int32 (A-37) | boolean or 0/1 | boolean |
| ptr | pointer | `{ptr: Hex}`, Hex, `{buf, offset}`, `{utf8}`, `{utf16}`, null | Hex |
| f32 | float | `{bits}` (exact: DataView f32 → JS number, exactly representable), or a number | `{value, bits}` from a `Float32Array` of the returned number |
| f64 | double | `{bits}` or a number | `{value, bits}` via `Float64Array` |
| utf8/utf16/ansi (ret) | pointer | — | read the string at the returned pointer (`max_len` 1024) |
| void | void | — | null |

- **Options.** `new NativeFunction(va, ret, args, {exceptions: "steal", scheduling, traps: coverage ? "all" : "default"})`.
  The ABI is the platform default (Win64).
- **Cache.** An LRU of 64 keyed by `va|ret|args|scheduling|traps`.
- **Exactness.** Float-by-bits inputs and outputs are exact except for NaN payloads, which may be canonicalized
  crossing a JS number (A-9).
- **VERIFIED exact results.** `physics_step(scratch, 0.5) = 14.905`, `mix_args` = 15.375, `four_floats` = 1234
  [ext-frida §3.7]. The emulator matched in-process calls bit for bit [rea-testing §10].
- **By-value structs.** NativeFunction struct-typed arguments construct but are untested [ext-frida §3.7]. v0.1 refuses
  them with `Unsupported{feature:"struct-by-value"}`; Win64 passes structs larger than 8 bytes by pointer anyway (use a
  buffer).

### 13.2 Buffers and the scratch arena

- `buffers[]` are allocated per RPC from a scratch arena: `Memory.alloc` chunks, at most `call_scratch_bytes` (16 MiB)
  per RPC and `call_buffer_bytes` (1 MiB) per buffer. They are 16-byte aligned by default, or to `align`.
- `init`:
  - `zero`;
  - `hex` (`writeByteArray`);
  - `copy` from a live address: a guard-aware read of `size` bytes, then a write into the buffer. This is the VERIFIED
    "scratch copy of the struct, so game state is not perturbed" pattern [ext-frida §3.7].
- `reset_buffers:"per-vector"` re-initializes every buffer before each vector. That gives each vector isolation, the
  analogue of the bridge's `isolation:"snapshot"` [ext-backends §9.9]. `"never"` chains state across vectors.
- `read_back` buffers are returned per vector as hex, with at most 1 MiB of read-back per RPC. Above that the response
  ends early with `next_index`.
- The arena is freed when the RPC returns. Pointers into it are invalid afterwards; this is documented.

### 13.3 Execution

**`thread:{kind:"agent"}`** (default). The vector loop runs synchronously on the agent JS thread inside the RPC:
```
for i = start_index … vectors.length-1:
  if (now - t0 > max_wall_ms && i > start_index) break         // time slice; return next_index = i
  resetBuffersIfPerVector(); mark agentCallTids; t = nowUs()
  try { ret = fn(...marshal(vectors[i])) ; status = "returned" }
  catch (e) { if (e.type) { status = "fault"; fault = { type: e.type, address: hex(e.address),
                memory: e.memory ? { operation: e.memory.operation, address: hex(e.memory.address) } : null,
                registers: regsFrom(e.context) } } else throw e }      // stolen exception: target survives [ext-frida §3.7]
  finally { unmark agentCallTids }
  results.push({ index: i, status, ret: decodeRet(ret), fault, buffers: readBack(), wall_us: nowUs()-t, coverage })
```
- The host continues with `start_index = next_index` until `next_index == null`.
- A fault is a **result** (`status:"fault"`), not an error (BRIEF D6 outcome rule).
- After a fault the target function may have left locks or globals inconsistent. The effect is irreversible and the
  host adds a perturbation limitation [rea-evidence §10.5].

**`thread:{kind:"thread", tid, timeout_ms}`**.
- `Process.runOnThread(tid, () => loop(...))` runs the same loop on that thread. VERIFIED to run on a game thread with
  about 15 ms latency while it was in `Sleep(16)` [ext-frida §3.7].
- The RPC is async: it races the promise against `timeout_ms` (default 2000, hard 30000).
- On timeout it returns `Timeout{phase:"run-on-thread"}`. The tid is marked `busy` until the late completion arrives
  and is discarded; new calls to a busy tid get `Timeout{phase:"previous run-on-thread still executing"}`.
- A thread blocked in an infinite kernel wait may never run the callback (A-38).

**Scheduling.**
- `cooperative` (default) releases the JS lock during the native call.
- `exclusive` is **required** when the target function calls thread-control APIs (Suspend/GetThreadContext) on
  threads that may run JS. Cooperative scheduling deadlocked V8 in that case [ext-frida §3.7].

### 13.4 BEA's own instruments during a call

- `core.agentCallTids.set(tid, {depth, bypassOverrides: overrides === "bypass", observe: hooks === "observe"})` for
  the executing thread.
- Hook and profile listeners skip recording for marked threads unless `observe` (count `agent_calls_suppressed`).
  Calls on the agent thread are additionally invisible because that thread is cloaked (F2).
- Override listeners skip their rewrite when `bypassOverrides`. Without that, an oracle result is perturbed by BEA's
  own overrides.
- `perturbation.target_instruments` lists every BEA instrument whose patch site is the target function, so a hooked
  target is visible in the result.

### 13.5 Per-call coverage

`coverage:{mode:"blocks", modules, max_blocks}`:
1. The NativeFunction uses `traps:"all"`.
2. `stalkerCo.claim(currentTid, "call")`. Then `Stalker.follow(currentTid, {events:{compile:true}, onReceive})`
   around **that single vector's** call, then `Stalker.unfollow(currentTid)` and `Stalker.flush()`.
3. Await `2 × drain_ms` for the trailing `onReceive`, then parse, filter by module, dedupe and cap. The result is
   `coverage.blocks = [[start, size], …]`.

VERIFIED: this yields the exact block coverage of one call, including callees such as `sin` [ext-frida §3.7, §3.8].
Each vector then costs about 100 ms, so at most 16 vectors per RPC run with coverage, and the RPC is async.

### 13.6 Non-returning functions and an unresponsive agent

A target function that never returns on the agent thread blocks the agent JS thread. Every later RPC times out on the
host (`provider_timeout`), and the host marks the session `agent_unresponsive`.
- Owned targets: `close_session` kills the job tree [rea-process §7].
- Attached targets: detach may fail, and that is reported.

Calls cannot be interrupted safely: the function may hold the heap or loader lock. The skill should tell agents to:
- prefer `thread` mode on attached targets for unknown functions, where only that thread blocks (A-38);
- always use scratch copies.

### 13.7 Effect and gate

- Every executed vector contributes to one `EffectHint{kind:"function-called", reversible:false}` per RPC.
- The gate is computed by the host from ownership and opt-in. It is open by default for owned targets and off for
  attached targets (orchestrator decision). The agent re-checks it.

---

## 14. `override_function` (`override.ts`, gate `override_function`)

| Mode | Mechanism (VERIFIED basis) | Revert |
|---|---|---|
| `rewrite` args | `onEnter`: int slot → `args[slot] = ptr(v)` (slot ≥ 4 works) [ext-frida §3.6]. Float slot < 4 → `this.context["xmm"+slot] = ab16`, where `ab16` is the **current** register copied with only the low lane replaced by the bits, so upper lanes are preserved (xmm writes VERIFIED). Float slot ≥ 4 → `rsp.add(8+8*slot).writeU32/writeU64(bits)` (A-39) | `listener.detach()` + flush + invalidate |
| `rewrite` ret | `onLeave`: int/ptr → `retval.replace(ptr(v))`; f32/f64 → `this.context.xmm0 = ab16` (VERIFIED 42.5 [ext-frida §3.6]) | same |
| `replace` | `Interceptor.replace(A, new NativeCallback(() => constant, ret, args))`. The original is not called. VERIFIED replace and revert; a second replace throws "already replaced" → `HookConflict` [ext-frida §3.6]. Tiny functions get `replace({target, relocation:"forced"}, cb)` (A-40) | `Interceptor.revert(A)` + flush + invalidate |

Details:
- `when.thread_ids` and `when.every_n` filters.
- `max_hits` counts applications, and `duration` bounds the lifetime.
- `record:true` emits `override/1` rows; `detail` holds the original values replaced, as cells.
- The detached guard and the agent-call bypass (§13.4) apply.
- `NativeCallback`s are pinned in `keep` until after revert plus settle.
- After revert, the bytes at each patch site must equal `originals`, else `verification.ok:false`.

Every observation made while an override is active must carry it in `perturbation.active_effect_ids`. That is
host-side bookkeeping from `EffectHint` [rea-evidence §10.5].

---

## 15. Dumps and thread state (`dump.ts`): feeding dump-backed emulation

### 15.1 `dumpStart` → job `dump`

Planning happens on the JS thread before any suspension, because enumeration APIs may take the loader lock:
- `module`: `{base, size}`, plus `module.enumerateRanges('---')` for the hole fallback.
- `range`: as given.
- `ranges`: the filter is applied to an `enumerateRanges` snapshot, capped at `max_total_bytes`.
- `thread`: TEB through NtQueryInformationThread; PEB at `TEB+0x60`; stack bounds from NT_TIB; TLS through
  `TEB+0x58` `ThreadLocalStoragePointer` (array entries until null, ≤ 64) and `TEB+0x1480` `TlsSlots[64]` (A-41).
  Static TLS block sizes come from each module's IMAGE_TLS_DIRECTORY (§8.1).

**Capture**, sliced at 8 ms, one region at a time:
- Read ≤ `dump_chunk_bytes` (4 MiB) with `readByteArray`. Whole images read without errors, ntdll 2.5 MB in 9 ms
  [ext-frida §3.14].
- On an AV, fall back to per-range reads. Unreadable parts are zero-filled and recorded in `holes`.
- Each chunk goes out as `send(BlobMessage, chunk)` immediately (600 MB/s binary [ext-frida §1.9]) and counts against
  flow control.

**`suspend:"all"`**, for consistent thread state:
1. Suspend every non-cloaked thread (exclusive `SuspendThread`).
2. Capture thread contexts, stacks, TEB/PEB/TLS and the explicitly listed `range` items, at most 64 MiB in total, into
   agent memory using `Memory.copy` only. No enumeration and no `send` happen while threads are suspended (A-32).
3. Resume all threads in `finally`, guarded by a 2 s watchdog.
4. Send the copies.

Module images and `ranges` filters are always captured live and marked `taken.suspended:false` for those regions.

**Manifest** (`bea-dump/1`, delivered in the job's done message): modules, regions (`blob`, `kind`, `base`, `size`,
`protection`, `module`, `holes`, `sha256`), threads (`ThreadState`), `module_map_epoch` and `truncated`.
- The shape matches bea-emu's planned `source:{kind:"dump", modules, regions, thread{teb, regs}}` [ext-backends §9.11].
- The host adds file sha256 and paths. Region `sha256` is computed in the agent with the `Checksum` API when available
  (A-42); the host always recomputes it.
- Images are in **mapped** layout, not file layout [ext-frida §3.14].
- **The emulator must take FPCW and MXCSR from `ThreadState`.** The gcc/msvcrt fixture ran with FPCW 0x37F and MXCSR
  0x1FA0 (F14), not the bridge defaults of 0x027F/0x1F80 [ext-backends §2.4].

### 15.2 `captureThreadState({tid, xmm, teb, tls})`

1. `threads.context(tid, CONTEXT_ALL = 0x10001F)` (exclusive Suspend/GetThreadContext/Resume).
2. Registers from the CONTEXT offsets (§5.6): `eflags +0x44`, `mxcsr +0x34`, `fpcw = FltSave.ControlWord +0x100`,
   `xmm0..15 +0x1A0` (A-11).
3. Add TEB, PEB, stack and TLS as above.

Calling this on the agent thread's own tid is refused (`BadParams`): that thread is the one running the code.

---

## 16. `run_script` isolation

`run_script` code **never** runs inside the BEA agent.

**Host side.**
- A separate script: `session.createScript(userSource, {name: "bea-user-<n>", runtime: "qjs"})`.
- Its own `logHandler`, and bounded message capture (REA's caps [rea-runtime §5]).
- Hard duration, then `unload()`.
- Server-level gate (orchestrator decision); effect flags `executesTargetCode`, `instrumentsTarget`,
  `writesTargetMemory`.

**What the agent guarantees, and what it cannot.**

| Concern | Status |
|---|---|
| User exception handlers stealing BEA traps | **Prevented.** BEA's handler is registered at load and never re-registered, so it runs first (F15). It returns `true` only for BEA traps, which stops the chain (A-33). User handlers see everything else afterwards |
| User code blocking BEA (one JS thread for all scripts, VERIFIED [ext-frida §1.7]) | **Not preventable.** RPCs, flushes and ack processing stall while user JS runs. Mitigations: the host's duration cap, and bounded ack waits (§6.6), so a crash or exit during a user script still proceeds after the timeout |
| User code detaching or altering BEA instruments | **Detected.** The host calls `fingerprint()` before and after. Checks: patch heads equal the expected trampolines (`originals` + recorded heads), DR7 on sampled threads, guard pages still guarded, BEA's followed-thread set. Mismatches produce `NoticeMessage{instrument-interference}` and a limitation on later evidence. `Interceptor.detachAll()` in a user script detaches only that script's listeners (A-34) |
| User code reading or writing anything | **By design.** That is what the gate is for |

---

## 17. Agent-side bounds (`src/shared/agentLimits.ts`)

The host may lower any default in `hello.limits`. It may raise one only up to the hard cap. Disk quotas (512 MiB ledger,
256 MiB per stream, 4 GiB blobs; orchestrator decision) are host-side. These limits protect **target memory and the
agent JS thread**.

| Limit | Default | Hard | Basis |
|---|---|---|---|
| `rpc_slice_ms` (soft; slow RPCs listed in status) | 20 | 50 | one JS thread [ext-frida §1.7] |
| `job_slice_ms` | 8 | 20 | ≈8 ms worst added RPC latency |
| `flush_ms` | 50 | 1000 | VERIFIED batching [ext-frida §1.9] |
| `batch_max_rows` / `batch_max_bin_bytes` | 2000 / 1 MiB | 10000 / 4 MiB | VERIFIED sizes |
| `stream_max_pending_rows` / `_bytes` | 20000 / 4 MiB | 100000 / 16 MiB | drop `buffer_full` beyond |
| `max_streams` | 64 | 128 | |
| `flow_high_water_bytes` / `flow_low_water_bytes` | 32 MiB / 8 MiB | 256 MiB / high÷2 | 21 GB blow-up without bounds [ext-frida §1.9] |
| `max_instruments` | 128 | 512 | |
| `max_js_hooks` | 256 | 1024 | user hooks; profiles counted separately |
| `max_native_hooks` × `native_ring_records` | 32 × 32768 (5 MiB each) | 64 × 262144 | |
| `max_profile_api_hooks` | 128 | 256 | catalog ≈ 70 |
| `profile_events_per_api` | 10000 | 1000000 | `per_api_cap` drops |
| `handle_cache_entries` | 65536 | 262144 | |
| `max_capture_args` / `max_deref_depth` | 16 / 8 | 32 / 16 | |
| `max_string_chars` / `max_capture_bytes` (per capture; default per capture 256 / 64) | 1024 / 4096 | 4096 / 65536 | |
| `max_backtrace_depth` / `backtrace_per_sec` | 16 / 100 | 64 / 1000 | ACCURATE backtrace cost |
| `max_duration_ms` | 3,600,000 | 3,600,000 | every instrument bounded |
| `max_hits_cap` | 10,000,000 | 100,000,000 | |
| `page_guard_max_pages` | 64 | 256 | two exceptions per access |
| `hwbp_verify_threads` | 64 | 256 | GetThreadContext cost |
| `stalker_max_threads` | 4 | 8 | queue memory (A-25) |
| `stalker_queue_capacity` / `stalker_drain_ms` | 1<<21 / 50 | 1<<22 / 250 | VERIFIED loss fix |
| `stalker_max_blocks` | 1<<20 | 1<<22 | 24 B each (block_counts slots; also the call_summary slot cap) |
| `stalker_settle_ms` | 300 | 2000 | VERIFIED re-follow advice |
| `scan_max_concurrent` | 8 | 16 | |
| `scan_max_candidates` | 4,194,304 | 16,777,216 | (8 + elem) B each in target |
| `scan_snapshot_bytes` | 256 MiB | 1 GiB | unknown-initial scans |
| `scan_page_rows` | 1000 | 4096 | |
| `call_max_vectors` (per RPC) / `call_max_wall_ms` | 1024 / 50 | 1024 / 1000 | |
| `call_scratch_bytes` / `call_buffer_bytes` | 16 MiB / 1 MiB | 256 MiB / 16 MiB | |
| `call_coverage_blocks` | 100000 | 1000000 | |
| `run_on_thread_timeout_ms` | 2000 | 30000 | |
| `read_max_bytes` / `typed_max_reads` | 1 MiB / 256 | 4 MiB / 1024 | |
| `write_max_bytes` | 64 KiB | 1 MiB | |
| `disasm_max_insns` / `disasm_max_bytes` | 2048 / 64 KiB | 8192 / 256 KiB | |
| `dump_chunk_bytes` / `dump_max_bytes` / `dump_max_concurrent` | 4 MiB / 2 GiB / 1 | 16 MiB / 4 GiB / 2 | host blob quota 4 GiB |
| `list_page_max` | 5000 | 20000 | |
| `snapshot_ttl_ms` / `max_snapshots` | 30000 / 4 | 300000 / 16 | |
| `max_jobs` | 8 | 16 | |
| `agent_heap_soft_bytes` | 256 MiB | 1 GiB | `Frida.heapSize` above this → new instruments and scans refused with `ResourceLimit{agent_memory}` + notice |

---

## 18. Lifecycle, shutdown and unload

- **Boot**: §3.2. **Ready → hello**: §2.2.
- **`shutdown({revert:true, timeout_ms})`**, for attached targets and CLI one-shots:
  1. `phase = "shutting-down"`. Only `status` and `ping` are admitted from here.
  2. Cancel jobs.
  3. Stop every instrument in reverse creation order with full revert (§5.7).
  4. Close scans and free the native arrays.
  5. Final flush.
  6. Return `ShutdownResult` with `unreverted[]`.
  7. The host then unloads the script and detaches.
- **Owned targets**: the host kills first and does not call `shutdown`. A revert before a kill is pointless, and the
  SDK's 2 s budget needs kill-first [rea-testing §0.5].
- **Unload without shutdown** (host crash, transport loss).
  - Interceptor listeners belonging to the script are removed by Frida (A-35).
  - Debug registers, BEA guard pages and code writes are **not**.
  - A DR trap or guard-page access with no BEA handler goes to the app's SEH as an unhandled single-step or
    guard-page exception, which **can crash an attached target**.
  - Mitigation: `rpc.exports.dispose`, which Frida invokes on script unload (A-36). It is defined outside
    `AgentRpcMethods` and is not callable by the host. It synchronously runs the disarm parts of §11.2 and §11.3 (API
    unset on all threads; restore page protections) and reverts BEA code writes from `originals`.
  - Without `dispose` support, the host rule is absolute: **never unload the agent of an attached target with armed
    watches; call `shutdown` first.**
- **Process exit**: the exit hook (§7.4) does a final flush and a bounded ack; instruments end with `process-exit`.
  **Crash**: last-chance report (§7.4).
- The host records the detach reasons: `application-requested` / `process-terminated` [ext-frida §1.5].

---

## 19. Testing the agent

**Unit lane** (Vitest, no Frida; `tests/unit/agent/**`):
- **Fakes.** Agent modules access GumJS globals only through `env.ts`. The tests supply fakes:
  - `FakeMemory`: a paged byte map that can simulate AV, guard and unmapped pages;
  - `FakeProcess`: threads, ranges, modules;
  - `FakeInterceptor`: records attach/detach and invokes callbacks with a scripted context, including `xmmN`
    ArrayBuffers;
  - `FakeStalker`.
- **Covered logic:**
  - encoding (Hex, bits, ScalarInput);
  - Win64 slot mapping, including `hidden_ret_ptr` and stack slots;
  - deref chains with failure cells;
  - DR7 masks and validation;
  - page-guard state machine (guard → step → re-arm, nested pages, suspension windows);
  - stream admission, flush, drop deltas and the flow-control hysteresis;
  - ack waiter token routing;
  - handle cache and parent tracking;
  - every profile decoder against byte fixtures captured from the S4 lab (F9 offsets);
  - scan op semantics against a JS reference implementation;
  - overlay disassembly fix-ups (with a fake `Instruction.parse`);
  - the `mapThrown` table.

  This answers BRIEF L13: logic is unit-tested on fakes, and the real behavior in acceptance.
- **C kernels** are compiled with host gcc against `tests/native/gum-shim.h` in a separate `test:native` lane. The
  lane is allowed to spawn processes; it is not the composition lane [rea-testing §2].

**Contract tests:**
- The `satisfies AgentRpcImpl` and `_noExtra` compile checks (agent build).
- Host zod mirrors of every `AgentRpcMethods` result, with an `expectTypeOf<z.infer<…>>().toEqualTypeOf<…>()`
  equality test.
- `binaryLayouts` offsets against the C `offsetof` printed by the native lane.

**Acceptance lane** (real Frida 17.23.2 and gcc fixtures, serial, owned-PID ledger [rea-testing §11]). Each design-lab
finding becomes a regression test:
1. The level map on `bt_fixture ops`: profile rows equal a golden, pointer-free projection (api, decoded args with the
   lab directory normalized, status, parent chain) (F5, F6, F9, F10, F16).
2. `hookInstall(ntdll!NtAllocateVirtualMemory)` and `kernel32!VirtualAlloc` → `HookDenied` (F8).
3. `quick` mode: every row arrives and the exit message carries code 0 (F11, F12). With a host that never acks, the
   target still exits within the bound.
4. Crash fixture: first-chance row, last-chance report with code 0xC0000005 and `information[0]=1` (F13), then jobhost
   exit code. FPCW/MXCSR are recorded (F14).
5. Page-guard watch: write deltas exact, instruction exact, two threads, target healthy after disarm (F19).
6. Debug-register watch on all threads plus a thread created after arming, then disarm verified through
   `debugRegisterState` [ext-frida §3.9].
7. Hook on a 4-byte function → `relocation:"forced"` [ext-frida §3.6].
8. Hook installed while a thread is followed: hits seen, no crash over 10 iterations (invalidate) [ext-frida §3.8].
9. `block_counts`: unfollow, settle and release with no crash over 10 iterations (keep-alive).
10. `callFunction` with f32/f64 bits: exact results; a fault result for a null pointer, target alive; `runOnThread`
    result.
11. A dump manifest consumed by the bea-emu bridge, plus a differential call (the user's workflow).
12. The CE scan workflow (first exact i32 → increased → results) [ext-frida §3.4].
13. Two scripts: a user handler registered after BEA never receives BEA's DR traps (F15, A-33).

---

## 20. Assumptions (BELIEVED) and the lab check for each

| Id | Assumption | Lab check before relying on it |
|---|---|---|
| A-1 | frida.Compiler builds the staged tree (`agent/` + `shared/` with relative imports) with `typeCheck:'full'` | Build the skeleton with one shared import; expect zero diagnostics |
| A-2 | `satisfies` on the spread object plus `_noExtra` catches missing and extra methods under the built-in checker | Introduce a missing and an extra method; both must fail the build |
| A-3 | Persistent `recv` re-arming under message load never misses an ack or flow post | 10k flow posts plus 100 concurrent ack waits |
| A-4 | Microseconds from QPC through the CModule pointer call are monotonic and consistent across threads | Compare against `Date.now()` over 10 s on 4 threads |
| A-5 | GumJS `Checksum` API shape (`new Checksum('sha256').update(ab).getString()`) | Probe it; if absent, omit the agent sha256 |
| A-6 | Multi-producer ring publication (atomic head + commit word written last); `GUM_IC_GET_FUNC_DATA` delivers `Interceptor.attach`'s third argument | Native hook on `hot_fn` from 4 threads: rows = calls, `torn` = 0 |
| A-7 | A CModule can call a function pointer passed as an extern (QPC) | Probe |
| A-8 | NativeFunction call cost for `bea_next_g`/`bea_now_us` with exclusive scheduling ≈ 0.2–0.5 µs | Microbenchmark in QJS |
| A-9 | NaN payloads may be canonicalized when floats cross JS numbers into a NativeFunction | Pass a signaling-NaN pattern; compare xmm bits via a hook on the callee |
| A-10 | THREAD_BASIC_INFORMATION `TebBaseAddress +0x8`; NT_TIB `StackBase +0x8`, `StackLimit +0x10` | Compare with `gs:[0x30]` from a hook on the same thread |
| A-11 | CONTEXT offsets beyond those verified (`Rcx…R15`, `Xmm0 +0x1A0`, `FltSave.MxCsr +0x118`) | `GetThreadContext` on a thread stopped at a known hook: compare with `this.context` |
| A-12 | `Interceptor` detach after its module unloaded is safe inside try/catch | Hook an export of a test DLL, `FreeLibrary`, then detach |
| A-13 | GumEvent x64 field layout | First-batch self-check against `Stalker.parse` (built in) |
| A-14 | `Thread.backtrace(this.context)` inside the UEF hook walks through `KiUserExceptionDispatcher` into the faulting frames | Crash fixture: compare with the first-chance backtrace |
| A-15 | `TerminateProcess(GetCurrentProcess())` reaches `NtTerminateProcess(-1)` without `RtlExitUserProcess`; hooking `NtTerminateProcess` is safe | Fixture mode calling `TerminateProcess(self)` |
| A-16 | `ModuleMap.find` takes no loader lock; module-observer callbacks run on the loading thread; deferring installs via `setImmediate` avoids loader-lock deadlocks | `LoadLibrary` storm from 4 threads with hooks plus profiles active |
| A-17 | Linux support is a feature subset: no profiles, no hwbp/page-guard handlers, no UEF; first-chance handler, hooks, Stalker, scans, calls and dumps work | Later; mark Linux best-effort |
| A-18 | Reading a target `PAGE_GUARD` page from the agent consumes the guard | Fixture with a guard page: read through Frida, then `VirtualQuery` |
| A-19 | Frida-internal allocations are absent from `enumerateRanges` (supported by `findRangeByAddress == null` [ext-frida §3.2]) | A scan for a marker written into an agent `Memory.alloc` block returns 0 hits |
| A-20 | Interceptor also follows `jmp rel32` thunks; only `jmp [rip+x]` was observed (F5) | Hook a `jmp rel32` thunk in a test DLL; check `patched_at` |
| A-21 | Catalog rows marked **B** (argument layouts per Windows SDK headers) | Extend `bt_fixture` with registry writes under a lab-only HKCU key the test deletes, sections, WSAAccept, WinHTTP to a loopback server, a successful `CreateProcess` of a fixture child (killed), `TerminateProcess(self)` |
| A-22 | Hooking `NtMapViewOfSection`/`NtUnmapViewOfSection` is deadlock-free | `CreateThread` + `LoadLibrary` cycle as in F8 |
| A-23 | `NtQueryObject(ObjectNameInformation)` can hang on synchronous pipe handles, so the agent never uses it for files | Not to be tested; avoid by design |
| A-24 | The caution list really is risky | Promote entries to safe only after an F8-style run |
| A-25 | Stalker queue memory grows with use rather than being preallocated per thread | Measure private bytes with 1<<21 capacity on 1 and 4 threads |
| A-26 | `MemoryAccessMonitor` works as a page-guard fallback | VERIFIED already [ext-frida §3.10]; fallback only |
| A-27 | Clearing DR6 B-bits in `nativeContext` is harmless and avoids stale slot attribution | Two slots alternating hits |
| A-28 | TEB stack bounds identify thread stacks for refusing page-guard watches | Unit-check against `listThreads` stack ranges |
| A-29 | Kernel-mode accesses (syscalls) to a guarded page consume the guard and/or fail the syscall | `ReadFile` into a watched buffer: status plus verifier count |
| A-30 | `Stalker.exclude` cannot be undone | Check the GumJS API surface (`typeof Stalker.unexclude`) |
| A-31 | `put_callout` passes per-block `user_data` | Built into acceptance test 9 |
| A-32 | Suspending all target threads while copying with `Memory.copy` (no enumeration, no `send`) cannot deadlock the agent | Dump with `suspend:"all"` under a `LoadLibrary`/heap storm |
| A-33 | A handler returning `true` stops the exception handler chain across scripts | Acceptance test 13 |
| A-34 | `Interceptor.detachAll()` in another script leaves BEA's listeners intact | Acceptance via `fingerprint` |
| A-35 | Script unload removes that script's Interceptor listeners | Unload with a hook installed; check that the bytes are restored |
| A-36 | Frida calls `rpc.exports.dispose` on script unload | Probe; without it, the host rule in §18 is mandatory |
| A-37 | Frida `bool` NativeFunction type semantics (1-byte) | Call a `bool`-returning fixture export |
| A-38 | `runOnThread` to a thread blocked in an infinite wait never runs; a hung call on that thread leaves the JS thread responsive | Fixture thread in `WaitForSingleObject(INFINITE)` |
| A-39 | Writing float bits into a stack argument slot in `onEnter` changes the callee's argument | `mix_args` slot 5 (f64 on the stack) |
| A-40 | `Interceptor.replace({target, relocation:"forced"})` works for tiny functions | `add_ints` replace |
| A-41 | x64 TEB offsets: `ThreadLocalStoragePointer +0x58`, `ProcessEnvironmentBlock +0x60`, `TlsSlots +0x1480` | Compare `TlsGetValue(i)` with `TEB+0x1480+8i` |
| A-42 | `Checksum` availability (see A-5) | — |
| A-43 | TinyCC CModule code can read Capstone operand details (`insn->detail->x86.operands[0]`) inside a Stalker transform | Compile the call-summary transform; compare its direct targets with `Stalker.parse` call events |

---

## 21. What the agent requires from the host (obligations)

1. **Build** (§2.1): stage → frida.Compiler → `dist/agent/bea-agent.js` + meta. Fail on diagnostics.
2. **Load** (§2.2):
   - `runtime:"qjs"`; `logHandler` before `load`; `message` connected before `load`;
   - fail on `type:"error"` or `fatal`;
   - wait for `ready` (5 s) and check `protocol`, `protocol_minor` and `build_id`;
   - `hello(config)`; on spawn, resume only after `hello`.
3. **The `AgentRpc` port** (`src/ports/AgentRpc.ts`): `call<K>(method, params, {signal, timeoutMs})`.
   - It uses a `frida.Cancellable` [ext-frida §1.7] and per-method deadlines (default 5 s; `callFunction`:
     `max_wall_ms` + 5 s, or the `runOnThread` timeout + 5 s).
   - It handles tuple replies (F1) and maps transport errors per §4.11.
   - It never sends BigInt.
4. **Message router**:
   - `batch`: store the raw payload as a hash-chained chunk with its `RowKind` / `BinaryLayout`. Check `bseq`
     continuity and account `dropped`.
   - `blob`: assemble by id, recompute sha256.
   - `job`: resolve waiters.
   - `instrument`: update handles and finalize the stream manifest on `ended`.
   - `crash` / `exit`: persist, then **post `{type:"ack", token}` immediately**.
   - `fault` / `notice`: logs and status.
5. **Flow acks**: post `{type:"flow", received_bytes}` after every 1 MiB or every 100 ms (§6.5).
6. **Decoding**: `binaryLayouts`, `apiProfiles` (names by id), `winConstants` (symbolic NTSTATUS, flags,
   dispositions), and VA→module+RVA reconstruction from `s:modules` rows by `g`.
7. **On-disk PE facts**: preferred ImageBase, file sha256, long section names, file bytes for rebasing verification
   [ext-frida §3.14]. The agent supplies in-memory facts only.
8. **Gates**: computed from server config and ownership, enforced in the host, and passed in `hello.gates`.
9. **Shutdown order**:
   - owned → kill first;
   - attached → `shutdown({revert:true})` → `unload` → `detach`;
   - never unload an attached agent with armed watches before `shutdown` (§18).
10. **Evidence bookkeeping** from `EffectHint`s (effects, `perturbation.active_effect_ids`, irreversibility), and
    stream manifests from `instrument` `ended` summaries [rea-evidence §10.5, §10.6].
11. **`run_script` hosting** with `fingerprint()` before and after (§16).
12. **Tool mapping assumptions** (S-docs owning contracts may rename): `hook_function` → `hookInstall`, or
    `profileInstall` when `profiles` is given; `watch_memory` → `watchInstall`; `trace_execution` → `traceStart`;
    `stop_instrumentation` → `instrumentStop`; `read_memory` → `readMemory`/`readTyped`; `disassemble` →
    `disassemble`; `scan_*` → `scan*` + jobs; `call_function` and the live leg of `diff_function` → `callFunction`;
    `override_function` → `overrideInstall`; `dump_memory` → `dumpStart`; `list_*` → inspection methods;
    `map_address` → host arithmetic + `resolveTargets` + `readMemory`.
