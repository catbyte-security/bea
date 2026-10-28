# Frida 17.23.2 on Windows x64: verified API reference for BEA

Key: `ext-frida`. Written 2026-10-28 on the host: Windows 11 Pro 10.0.26200, Ryzen 7 7800X3D, Node 24.18.0, gcc 16.1.0 (WinLibs MinGW-w64, msvcrt, SEH).
Frida Node binding: `<rea-checkout>/node_modules/frida` (package.json `"version": "17.23.2"`). Nothing in the REA clone was modified. All builds and runs happened in the lab dir.
Agent typings: `@types/frida-gum@19.12.0`, installed locally in the lab dir only. They describe a newer API surface than 17.23.2, so this file records which typed APIs exist at runtime.

Labels used below:

- **VERIFIED** means I ran it here, or I read the exact code at the cited path:line.
- **BELIEVED** means it comes from docs, typings or memory and was not exercised.
- **OBSERVED-FLAKY** means it happened in some runs and not in others.

Lab directory (every script, fixture and raw output): `<scratch>/bea-lab/ext-frida/`

- `fixture.c` → `fixture_gcc.exe` (`gcc -O2 -g -Wall -o fixture_gcc.exe fixture.c -lm`). This is a fake "game loop".
  - `struct car { float speed; int counter; double pos[3]; }` is the global `g_car`, exported.
  - Exported non-inlined functions: `physics_step(struct car*, float dt)`, `mix_args(int,float,double,float,int,double)`, `four_floats(f,f,f,f)`, `add_ints`, `hot_fn`, `touch_counter`, `car_energy(const car*, double)`.
  - Flags: `--iters N --crash-after N --hot N --sleep MS --worker --stdin --av-handled --alloc MB`.
  - The image base is 0x140000000. It is relocated by high-entropy ASLR (seen at 0x7ff7...).
  - The x64 build has `.pdata`. Symbols are DWARF only, with no PDB.
- `lib.mjs` holds the shared host helpers: the frida import, `spawnFixture`, `killOwned`, `dump`.
- `run_agent.mjs <agent.js> [--runtime qjs|v8] [--resume-first] [--stdio] -- <fixture args>` is the generic runner. It spawns, attaches, loads, resumes, collects messages and kills.
- Host experiments are `h1..h21*.mjs`. Agent experiments are `a1..a17*.js`. Each raw result is in `out_*.json`.
- MSVC is not usable. `cl.exe`/`link.exe` exist under `VS/18/Community/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64`, but there is no `vcvarsall.bat`, no MSVC `lib/x64` and no Windows SDK. Because of that, **PDB-based DebugSymbol behaviour was NOT verified**. Only gcc/DWARF binaries were tested.

Every process I spawned was killed. Leftovers were checked with `tasklist /FI "IMAGENAME eq fixture_gcc.exe"` (none at the end). I never attached to anything I did not spawn.

---

## 0. TL;DR: the facts that should shape BEA

1. **The host API works on Windows.** All of these are VERIFIED:
   - spawn suspended with argv, env/envp and cwd;
   - `stdio:'pipe'` capture through `device.output`, plus stdin through `device.input`;
   - attach in about 90 ms the first time and about 10 ms after that;
   - resume, kill and detach.

   `device.processCrashed` **never fires on Windows**. A crash, a kill and a normal exit all show up only as `session.detached('process-terminated', crash=null)`.
2. **`frida.Compiler` exists in frida-node 17.23.2 and works.** It bundles TypeScript agents and type-checks them with built-in GumJS typings; no tsconfig or `@types` are needed. A cold build takes about 170 ms, a warm build about 15 ms. The default output is Frida's multi-file ESM bundle (`📦 … ✄`), which loads in both QJS and V8. esbuild (in REA's node_modules) producing an IIFE also works. VERIFIED.
3. **The default runtime is QJS** (`Script.runtime === "QJS"`). Measured QJS vs V8 trade-offs:
   - QJS has cheaper hooks: an empty JS onEnter costs about 0.44 µs, against about 1.1 µs on V8.
   - QJS has cheaper Stalker JS callouts: about 6M/s, against about 0.85M/s on V8.
   - QJS is about 35x slower in tight JS loops: a float scan runs at 33 MB/s, against 1.17 GB/s on V8.
   - QJS frees objects eagerly through refcounting. This crashed the target when a CModule used by Stalker went out of scope (see §3.9).
4. **The Windows x64 `CpuContext` exposes `xmm0..xmm15` as 16-byte ArrayBuffers, and they are both readable and writable.** Float and double arguments and float returns can therefore be captured and modified in `Interceptor.attach`. There is no rflags, no ymm and no debug-register field; for those use `nativeContext` with the Windows CONTEXT offsets. VERIFIED.
5. **Hardware watchpoints and breakpoints exist as `ThreadDetails` instance methods** and work on Windows: `setHardwareWatchpoint(id, addr, size, 'r'|'w'|'rw')`, `setHardwareBreakpoint(id, addr)` and the matching `unset*`.
   - They are per-thread.
   - They are delivered to `Process.setExceptionHandler` as `type:'single-step'`. This is true for data watchpoints and for execute breakpoints.
   - Data traps report pc = the instruction *after* the access, with `memory` = null.
   - **Frida does not validate the parameters.** An id ≥ 4 corrupts DR7. Misaligned addresses are silently aligned down. `'r'` behaves like `'rw'`.
   - **`unset*` from the JS thread is racy:** 3 to 5 of 8 unsets failed while traps were frequent. The reliable disarm is to clear DR7 and DRn in `details.nativeContext` from inside the handler.
   - **Execute breakpoints loop forever unless the handler sets RF (EFlags bit 16) or clears DR7 in `nativeContext`.**
6. **`MemoryAccessMonitor` works on Windows.** It uses guard pages, covers every thread, and fires once per page per enable. It reports the faulting instruction itself (`from`), plus `operation` and `address`. Re-arming through `setImmediate` gave about 43 events/s. VERIFIED.
7. **Stalker works:**
   - call, ret, block and compile events; 32 bytes per event on x64;
   - `Stalker.parse`, transforms with JS or CModule callouts, `addCallProbe`;
   - **oracle coverage of a single in-process call** via `NativeFunction(..., {traps:'all'})`.

   The default `queueCapacity` (16384 events per 250 ms drain) **silently drops events** above about 65K events/s. Raising `queueCapacity` fixes that. Call events are very expensive on call-heavy code (about 55 to 90x slowdown).
8. **Do not mix Interceptor changes with an active Stalker follow.** A hook added after a block was compiled is invisible to the followed thread. Detaching a hook while the thread is followed crashed the target in 1 of 4 runs. `Stalker.invalidate(tid, addr)` fixes both cases. VERIFIED.
9. **`send()` has no backpressure.**
   - About 8K messages/s is the host-side ceiling, the same for both runtimes.
   - Sending once per call from a hook at 2M calls/s grew the target to **about 21 GB** before I killed it.
   - Batching works: JSON batches deliver about 1M items/s and binary batches about 1.2M items/s, with no loss.
   - A CModule ring buffer drained into binary `send()` delivers about 5.4M events/s.
   - Binary attachments move about 600 MB/s.
10. **One JS thread serves every script in the target**, across sessions and runtimes. A busy RPC handler blocks every other script's RPC (measured 400 ms of head-of-line blocking). RPC round-trip is about 0.3 ms. `frida.Cancellable` cancels RPCs and device lookups.
11. **Symbols on gcc/MinGW binaries come from dbghelp and see exports only.**
    - `DebugSymbol.fromAddress` returns the *nearest preceding export* with no displacement, which is misleading for static functions.
    - `DebugSymbol.moduleName` is wrong for system DLLs: it reported "fixture_gcc.exe" for kernel32!Sleep.
    - Use `Process.findModuleByAddress` together with `Process.findFunctionRange` (.pdata based, exact) instead.
12. **ASLR mapping recipe (VERIFIED):** `runtime = module.base + (staticVA - preferredImageBase)`. The **preferred ImageBase must be read from the on-disk PE** (or from REA/Ghidra metadata). The Windows loader rewrites `OptionalHeader.ImageBase` in memory to the actual base.
13. **Frida injection is visible.**
    - `frida-agent.dll` plus 24 system DLLs are loaded into the target and show up in `tasklist /M`.
    - Frida hides `frida-agent.dll` from its own `enumerateModules`.
    - After `session.detach()`, 11 of those DLLs stay loaded.
14. **`exceptor:'off'` makes ordinary agent mistakes fatal:** even `ptr(0x10).readU32()` kills the target. Keep the default. With it, bad reads throw a JS `Error`, and `NativeFunction` crashes are *stolen* into JS exceptions carrying type, address, memory and context. The process survives. VERIFIED.

---

## 1. Host API (frida-node 17.23.2)

### 1.1 Import and export shape (VERIFIED)
- The package is ESM (`"type":"module"`, `main: build/src/frida.js`) and loads `frida_binding.node` through the `bindings` package.
- **Default export:** an object with 160 keys, including `getLocalDevice`, `spawn`, `attach`, `Compiler`, the enums and so on.
- **Named exports** also exist (`spawn`, `attach`, `getLocalDevice`, `Compiler`, `ScriptRuntime`, `Stdio`, `SessionDetachReason`, …).

  ```js
  const mod = await import("file:///<rea-checkout>/node_modules/frida/build/src/frida.js");
  const frida = mod.default ?? mod;
  ```
- **Typings:**
  - `build/src/frida.d.ts` re-exports the types from `frida_binding.d.ts` (2000+ lines).
  - Key line references in `frida_binding.d.ts`: `Device` 182-241, `Crash` 478-484, `Session` 516-531, `Script` 535-559, `Compiler` 710-725, `CompilerOptions` 876-885, `SessionOptions` 922-931, `ScriptOptions` 933-938, enums 1210-1305, `SpawnOptions` 1984-1992, `Message` 2001-2020.
  - REA does not use these. It ships its own minimal ambient module at `rea/src/frida/frida-bindings.d.ts` (81 lines), because frida is an optionalDependency. BEA can type against the package's own `frida.d.ts`, since it is bundled with the package.
- Host-side wrapper behaviour (read in `frida.js`):
  - `ScriptServices` RPC (36-124): requests are posted as `["frida:rpc", id, "call", name, args]`.
  - `ScriptExportsProxy` (125-181): a trailing `Cancellable` argument and a trailing `Buffer` argument are popped off and treated specially (144-154).
  - `then`/`catch`/`finally` are reserved names, so `await script.exports` is safe.
  - Log messages (`type:"log"`) are routed to `script.logHandler` (55-56, 203-218).

### 1.2 Devices and system parameters (VERIFIED, `h1_host_basics.mjs` → `out_h1.json`)
- `frida.enumerateDevices()` took 556 ms on the first call (it initialises the device manager). It returned:
  - `local` "Local System" `type:'local'`
  - `socket` "Local Socket" `type:'remote'`
  - `barebone` "GDB Remote Stub" `type:'remote'`
- `frida.getLocalDevice()` returned in 0.2 ms once initialised.
- `device.querySystemParameters()` →
  `{arch:'x64', os:{version:'10.0.26200', id:'windows', name:'Windows'}, platform:'windows', name:'PC', access:'full'}`

### 1.3 Process enumeration (VERIFIED)
`device.enumerateProcesses({scope, pids})`, measured on 183 processes:

| scope | time | `parameters` |
|---|---|---|
| `'minimal'` | 1.9 ms | `{}` |
| `'metadata'` | 33.7 ms | `path, user, argv, ppid, started` |
| `'full'` | 531 ms | metadata fields plus `icons` (2 RGBA Buffers) |

- **`ppid` is a BigInt.** `JSON.stringify` throws on it, so convert before serialising.
- `started` is an ISO string.
- `{pids:[...]}` filters the result.
- **GOTCHA:** after a target spawned with `stdio:'pipe'` has exited, `enumerateProcesses({pids:[pid]})` *still returns it*. Frida holds a handle, so the process is a zombie. The full list and `tasklist` correctly show it gone (`h12_pipe_zombie.mjs`). Without a pipe the pid filter behaves correctly (`h9_exit_liveness.mjs`). **Do not use the pid filter as a liveness check.**
- `device.getProcess(globName)` (frida.js:430-444) does a lowercase minimatch over `enumerateProcesses`. If more than one process matches it throws `"Ambiguous name; it matches: …"`. VERIFIED with `"fixture_gcc*"`.

### 1.4 Spawn, stdio, stdin and early instrumentation (VERIFIED)
`device.spawn(programOrArgv, {argv, env, envp, cwd, stdio, ...aux})` (frida.js:456-495):

- **Program and argv:**
  - If `programOrArgv` is an array, element [0] is the program and the whole array is argv. A 1-element array means "no argv".
  - With a string program you can pass `argv` explicitly, and `argv[0]` can be anything (verified `custom-argv0`).
- **Environment:** `env` is *merged* into the inherited environment (PATH stays set). `envp` *replaces* the whole environment (PATH was gone). Both are objects that get turned into `K=V` string vectors.
- **`cwd`** works, for example `C:\Windows`.
- **Unknown keys** go into `aux`.
- **Timings:** spawn took 6.5 ms. The suspended process is already listed with full argv. `resume` took 0.2 ms.
- **`stdio:'pipe'` works on Windows.** `device.output.connect((pid, fd, data:Buffer) => …)` delivers fd 1 and fd 2, and **a zero-length Buffer means EOF** on that fd. With `stdio:'inherit'` (the default) no output events are delivered.
- `device.input(pid, Buffer)` writes to the target's stdin; the fixture echoed it.
- **Pre-resume state** (agent loaded before resume; `a13_dump_early.js`):
  - The main thread is at `ntdll!RtlUserThreadStart`, with entrypoint `mainCRTStartup`.
  - `g_frame == 0`, so `main` has not run yet.
  - **29 modules** are already present: the exe's own imports *plus* the DLLs pulled in by frida-agent.
  - 3 ntdll worker-pool threads exist.
  - A hook installed then caught the very first `physics_step` call (`counter==0`).

  This gives the early-instrumentation sequence: `spawn → attach → createScript/load → resume`.

### 1.5 Attach, sessions, detach reasons and crashes (VERIFIED)
- **Attach timings:** `device.attach(pid, opts)` took about 90 ms for the first attach in a host process (agent injection). Later attaches to new processes took 10-12 ms. Attaching to an already-running process that I spawned outside Frida took 87 ms.
- **Session members:** `session.pid`, `session.persistTimeout` (0 by default), `session.isDetached()`, `session.detach()`, and the `session.detached` signal with handler `(reason, crash)`.

| Event | `detached` reason | `crash` | Notes |
|---|---|---|---|
| `session.detach()` | `application-requested` | null | Target keeps running. |
| `device.kill(pid)` | `process-terminated` | null | Also when killed while still suspended. |
| Normal exit | `process-terminated` | null | |
| Unhandled crash (null write) | `process-terminated` | **null** | `device.processCrashed` **never fired**. |

- `SessionOptions` on Windows (`h16`, `h18`):
  - Accepted and behaving like the default: `realm:'native'`, `exceptor:'full'|'handler-only'`, `persistTimeout`, `exitMonitor:false`, `threadSuspendMonitor:false`, `unwindBroker:false`.
  - `realm:'emulated'` → `"Error: Emulated realm is not supported on this OS"`.
  - **`exceptor:'off'`:** attach succeeds, but any agent bad read or crashing NativeFunction call **kills the target**. `load()` rejects with `"The connection is closed"`.
- **Crash capture** therefore has to happen in the agent through `Process.setExceptionHandler` (§3.12). The host only sees `process-terminated`.
- After an unhandled crash the PID disappeared within 500 ms (`h11`); no WerFault was seen. Even so, BEA should always kill its own spawned targets explicitly.

### 1.6 Scripts: runtimes, messages and errors (VERIFIED, `h2_scripts.mjs` → `out_h2.json`)
- `session.createScript(src, {name, runtime:'qjs'|'v8'|'default', snapshot, snapshotTransport})`.
  - `name` shows up in stack traces as `/name.js`.
- **Timings for a small agent:**

  | Runtime | createScript | load | unload |
  |---|---|---|---|
  | QJS | 1.2 ms | 0.9 ms | 1.1 ms |
  | V8 | 8.7 ms | 3 ms | 0.4 ms |

- **Agent-side facts:**
  - `Script.runtime` is `"QJS"` or `"V8"`; the default is QJS.
  - `Frida.version` is `"17.23.2"`.
  - `Frida.heapSize` is 1.2-1.8 MB at baseline.
  - `Process.codeSigningPolicy` is `'optional'`.
  - `Process.pageSize` is 4096 and `Process.pointerSize` is 8.
- `script.message.connect((message, data) => …)`:
  - `{type:'send', payload}`.
  - `{type:'error', description, stack, fileName, lineNumber, columnNumber}` for uncaught errors, including ones thrown in timers. QJS gives `columnNumber` 1; V8 gives real columns.
- **`load()` RESOLVES even when the top level throws.** The throw arrives only as an `error` message. BEA must treat error messages received during load as a load failure.
- A syntax error makes `createScript` reject with `"Script(line 1): SyntaxError: expecting ';'"`.
- `console.log/warn/error` → `script.logHandler(level, text)` with level `'info'|'warning'|'error'`. Messages of type `log` never reach `message`.
- `script.post(obj, Buffer)` arrives agent-side as `recv('type', (msg, data:ArrayBuffer) => …)`.
- `send(obj, ArrayBuffer)` arrives host-side as `data: Buffer`.
- **Bytecode:** `session.compileScript(src, {runtime:'qjs'})` returned 105 bytes, and `createScriptFromBytes` worked. On V8: `"compilation to bytecode is not supported by the V8 runtime"`.
- **Snapshots:** `session.snapshotScript(embedSrc, {runtime:'v8'})` produced 453 KB in 17 ms, and `createScript(src, {snapshot, runtime:'v8'})` saw the snapshotted global.
- `script.eternalize()` succeeded.
- **Destruction:** `script.unload()` emits `destroyed`, after which `isDestroyed===true`. An RPC after unload, or one still pending when `session.detach()` happens, rejects with `"Script is destroyed"`.

### 1.7 RPC (VERIFIED)
- **Return-value mapping:**
  - `rpc.exports = {sync(){}, async asyncFn(){}}`; both appear on the host as Promise-returning functions.
  - `undefined` → `null`.
  - A `NativePointer` → string `"0x7ff7…"`.
  - An `ArrayBuffer` → Node `Buffer`.
  - Nested JSON is preserved.
  - **BigInt arguments throw on the host** ("Do not know how to serialize a BigInt").
- **Errors:**
  - A thrown error arrives as an Error with `name` and `message` preserved and the agent stack copied. QJS adds `fileName` and `lineNumber`.
  - A missing method gives `"unable to find method 'doesNotExist'"`.
- **Latency:** sequential round-trip about 300-350 µs on both runtimes. 200 parallel calls took 13-15 ms.
- **Cancellation:** `await script.exports.fn(arg, cancellable)` with `new frida.Cancellable()` and `cancellable.cancel()` → `"Operation was cancelled"` after about 200 ms. The script stays usable. `frida.getUsbDevice({timeout:300})` → `"Timed out while waiting for device to appear"`.
- **One JS thread for everything** (`h20_isolation.mjs`): every script in the process (same session, other session, QJS or V8) reported the same agent thread id. A `busy(400ms)` RPC in one script delayed `ping()` in every other script by 400 ms. Keep RPC handlers short and chunk scans with `setImmediate`. `Worker` exists (`typeof Worker === 'function'`) but was **not exercised** (BELIEVED to need an ESM bundle with a worker entry).

### 1.8 TypeScript agents: `frida.Compiler` (VERIFIED, `h3_compiler.mjs`, `h16_session_opts.mjs`)

```js
const compiler = new frida.Compiler();               // optional DeviceManager arg
compiler.diagnostics.connect((d) => diags.push(d)); // array of {category, code:BigInt, file:{path, line:BigInt(0-based), character:BigInt}, text}
const bundle = await compiler.build("C:/…/agent/index.ts", {
  projectRoot: "C:/…/agent",        // CompilerOptions fields are accepted although BuildOptions is typed {}
  bundleFormat: "esm" | "iife",     // default esm
  typeCheck: "full" | "none",       // default full
  sourceMaps: "included" | "omitted",
  compression: "none" | "terser",
});
```
- **Output formats:**
  - The default ESM output looks like `"📦\n1137 /index.js\n592 /index.js.map\n✄\n…"` (Frida multi-file bundle). `createScript(bundle)` loads it in QJS and V8.
  - `iife` produces a plain `"use strict"; (() => {…})()`.
  - `terser` made it 540 bytes.
- **Timings:** first build 167 ms; later builds 13-20 ms.
- **Type checking uses typings built into Frida:** a project with *no tsconfig and no node_modules* still reported `Type 'number' is not assignable to type 'string'.`
- On type errors `build()` rejects with `"Compilation failed"` and the diagnostics signal carries the details. `typeCheck:'none'` builds anyway.
- `watch`, `buildLibrary`, `watchLibrary`, `LanguageServer` and `PatternCompiler` (an ImHex-pattern-style decoder, `frida_binding.d.ts:738-874`) exist in the typings but were **not exercised**.
- **Alternative:** esbuild 0.28.2 from REA's node_modules with `{bundle:true, format:'iife', platform:'neutral', target:'es2022'}` built in 77 ms and loaded in both runtimes. Either works. `frida.Compiler` saves BEA from carrying a bundler dependency and type-checks against the exact GumJS version.

### 1.9 Message throughput (VERIFIED, `h15_msgrate.mjs`, `h13_throughput.mjs`)

| Experiment | QJS | V8 |
|---|---|---|
| 50,000 small `send({i})` in a loop: host receipt rate | 8.2K msg/s (agent enqueued in 0.33 s; host took 6.1 s) | 7.8K msg/s |
| 2,000 × 64 KB JSON arrays | 60 MB/s (agent JSON-bound) | 75 MB/s |
| 2,000 × 64 KB binary `send(meta, ArrayBuffer)` | **603 MB/s** | **579 MB/s** |

Hook-delivery variants on `hot_fn` (tight loop, fixture `--sleep 0 --hot 1000`; the agent self-stops after 1.5 s; host counts items):

| Variant | QJS calls/s (=items delivered) | V8 | Loss |
|---|---|---|---|
| No hook | 853M/s | n/a | n/a |
| Empty JS `onEnter` | 2.28M/s | 0.89M/s | n/a |
| `send()` per call | target outran host: about 156K msgs delivered in 20 s, final message never arrived; the earlier unbounded run reached **21 GB RSS** | same | n/a |
| JSON batch (2000 items/msg + 50 ms timer) | 1.01M/s | 0.67M/s | 0 |
| Binary batch (`Int32Array(16384)`/msg) | 1.20M/s | 0.60M/s | 0 |
| CModule `onEnter` → native ring (1M entries) → JS drain every 20 ms → binary `send` | **5.4M/s** | V8 run delivered 8.0M items, but its final message did not arrive within 20 s (unexplained) | 0 (QJS) |

---

## 2. Agent API: what exists in 17.23.2 (VERIFIED, `a1_introspect.js` → `out_a1.json`)

**Removed** (they report `typeof === 'undefined'`): `Memory.readU32`, `Memory.writeU32` (all `Memory.read*`/`write*`), static `Module.findBaseAddress`, `Module.enumerateExports`, `Module.getExportByName`, `Module.ensureInitialized`, `Process.enumerateModulesSync`.
`Object.getOwnPropertyNames(Module)` → `["length","name","prototype","load","findGlobalExportByName","getGlobalExportByName"]`.

**Present** (all `function`/`object`):
- `Process.getFunctionRange`/`findFunctionRange`, `getThreadById`/`findThreadById`, `runOnThread`, `attachThreadObserver`, `attachModuleObserver`
- `Memory.findPointers`, `ControlFlowGraph`
- `Profiler` and samplers (`CycleSampler` …)
- `Interceptor.replaceFast`, `Interceptor.defaults` (`{}`), and the `InstrumentationTarget` object form (`relocation`, `scenario` work)
- `MemoryAccessMonitor`, `NativePointer.readVolatile`/`writeVolatile`, `ArrayBuffer.wrap`
- `Worker`, `Cloak`, `SqliteDatabase`, `Checksum`, `File`, `ApiResolver`, `ModuleMap`, `CModule`, `Kernel`

**Typed in @types 19.12.0 but ABSENT at runtime:** `RustModule`.

`Module` instance prototype: `name, version, path, base, size, ensureInitialized, enumerateImports, enumerateExports, enumerateSymbols, enumerateRanges, enumerateSections, enumerateDependencies, findExportByName, findSymbolByName, getExportByName, getSymbolByName, toJSON`.

---

## 3. Agent API details (Windows x64, VERIFIED unless marked)

### 3.1 Process and Module
- `Process.mainModule` is `fixture_gcc.exe`. `Process.enumerateModules()` returns 29 modules; frida-agent.dll is cloaked.
- `module.version` is `null` on Windows, even for system DLLs.
- Names keep their loader casing (`KERNEL32.DLL`, `KERNELBASE.dll`). `getModuleByName('KERNEL32.DLL')` and `('kernel32.dll')` both work (case-insensitive).
  - `get*` throws `"unable to find module 'nope.dll'"`; `find*` returns `null`.
- `module.enumerateExports()`:
  - Returns `{type:'function'|'variable', name, address}`.
  - Exported data (`g_car`) is typed `variable`.
  - There is **no `size`**.
- `module.enumerateImports()` returns `{type, name, module:'KERNEL32.dll', address, slot}`. **`slot` is the IAT entry address**, which makes IAT hooking possible (§3.7).
- `module.enumerateSymbols()` on a gcc PE (dbghelp, 36 ms for the first call):
  - **It only sees the 12 exports.** `g_car` is typed `'function'` (wrong).
  - `size` is the distance to the next symbol (physics_step 320 against a real 181).
  - Static functions are invisible. kernel32 has 1698 symbols, again exports only since no PDB was available.
- `module.findSymbolByName('physics_step')` returned **null** even though enumerateSymbols lists it. Use `findExportByName` or `DebugSymbol`.
- `module.enumerateSections()`:
  - Returns `{id:'0..text', name:'.text', address, size}`.
  - **gcc's long section names come back unresolved**: `.debug_*` appear as `"/4"`, `"/14"`, … because the COFF string table isn't read.
- `module.enumerateDependencies()` returns **`[]` on Windows**.
- `Module.findGlobalExportByName('Sleep')` works. The `get*` variant throws `"unable to find global export 'x'"`.
- `Module.load('version.dll')` returns a `Module`.
- `Process.findModuleByAddress(p)` and `ModuleMap(filter)` (`has`, `find`, `findName`, `values`) work.

### 3.2 Memory ranges
- `Process.enumerateRanges('rw-')` takes a protection string *or* `{protection, coalesce:true}`. On a small process: 259 ranges plain, 238 coalesced.
- **There is no `file` field on Windows at all**: 0 of 79 rw ranges, 0 of 57 r-x ranges, and 0 of the module ranges. Attribute ranges to modules yourself with `findModuleByAddress` or a `ModuleMap`.
- `module.enumerateRanges('r--')` gives the per-section protections (r--/r-x/rw-).
- `Process.getRangeByAddress(p)` / `findRangeByAddress(p)` return `{base, size, protection}`.
  - A `Memory.alloc(64)` block (Frida heap) gave `findRangeByAddress === null`.
- `Process.enumerateMallocRanges()` found 5663 heap blocks in 2 ms. Entries have `{base, size}` and no protection.

### 3.3 NativePointer reads and writes
- Working accessors:
  - `readFloat()`, `readDouble()`, `readS32()`, `readU32()`, `readU64()` (UInt64), `readPointer()`
  - `readByteArray(n)` → ArrayBuffer
  - `readUtf8String()`, `readCString(maxLen)`, `readUtf16String`/`readAnsiString`
  - `readVolatile(n)`
  - **An optional `offset` argument works in 17.23.2:** `car.readS32(4)`, `car.readFloat(0)`.
- Writes chain: `p.writeFloat(1).add(4).writeS32(0)`.
- **A bad address throws `Error("access violation accessing 0x10")`** (a plain Error) and the process survives with the default exceptor.
- `ArrayBuffer.wrap(ptr, size)` gives zero-copy access; use it with `DataView`/`Float32Array`. Note that in V8 it is *slower* to iterate than a copied `readByteArray` (§3.5).
- Other helpers: `hexdump(ab|ptr, {header:false, ansi:false, length})`, `ptr.toMatchPattern()` (8-byte LE pattern string), `compare`, `equals`, `strip`, `toString(10)`, `toJSON`.
- Writing to code without `Memory.protect` → `"access violation accessing 0x…"`.

### 3.4 Memory scanning: Cheat-Engine-style primitives
- `Memory.scanSync(base, size, pattern)` returns `[{address, size}]`. Accepted patterns, all verified:
  - exact: `"42 45 41 5f 4d"`
  - byte wildcard: `"42 45 41 ?? 4d"`
  - nibble wildcard: `"4? 45 41"`
  - r2-style mask: `"40 45 41 5f : f0 ff ff ff"`
  - regex: `"/BEA_MARKER_v\\d/"`, where the match size is the regex match length
  - `new MatchPattern("…")` for reuse
- Errors: a bad pattern throws `"invalid match pattern"`; an unreadable range throws `"access violation accessing 0x10000"`. Wrap each range in try/catch.
- `Memory.scan(base, size, pattern, {onMatch(addr, size){ return 'stop'? }, onError(reason), onComplete()})` is the async form and works.
- `Memory.findPointers(rangeOrRanges, [values], {mask})` returns `[{address, value}]` sorted. It is SIMD-backed and very fast.
- CE workflow verified on `g_car.counter`:
  1. First scan for the exact int32 over all `rw-` ranges: 77 hits, target included.
  2. Next scan, "increased", by re-reading the hit list: 2 hits, target included.
  3. An exact float pattern scan finds `g_car.speed`.

Throughput on a 512 MB pseudo-random heap block (`a3_scanbench.js`, fixture `--alloc 512`):

| Method | QJS | V8 |
|---|---|---|
| `Memory.scanSync` 8-byte exact (ptr pattern) | 1.80 GB/s (512 hits) | 1.80 GB/s |
| `Memory.scanSync` with `??` wildcard | 1.82 GB/s | 1.73 GB/s |
| `Memory.findPointers` (1 value) | **~30 GB/s** (16 ms) | ~28 GB/s |
| JS tolerant float scan, `readByteArray` 16 MB chunks + Float32Array | **33 MB/s** | 1.17 GB/s |
| JS tolerant float scan, `ArrayBuffer.wrap` (no copy) | 33 MB/s | 153 MB/s |
| CModule (TinyCC) tolerant float scan | 1.0 GB/s | 1.0 GB/s |
| `readByteArray` + binary `send` of 64 MB (4 MB chunks) | 24 ms agent-side, all received in about 37 ms | same |

The tolerant float compare found 799 hits in every implementation, so the variants agree. **BEA:** use exact or wildcard `scanSync` for byte/int/exact-float scans, `findPointers` for pointer scans ("who points at X"), and a CModule (or V8) for range, tolerance or relational compares. Never use QJS JS loops over large memory.

### 3.5 alloc, protect and patchCode
- **Allocation:**
  - `Memory.alloc(64)` is `rw-` on Frida's heap.
  - `Memory.alloc(pageSize, {protection:'rwx'})` gives `rwx`.
  - `Memory.alloc(pageSize, {near: main.base, maxDistance: 0x7fff0000})` landed 0x10000 below the module.
- **Strings:** `Memory.allocUtf16String('héllo')` and `allocAnsiString` round-trip.
- **Protection:** `Memory.protect(pageAlignedPtr, pageSize, 'rwx')` returns `true`, and `Memory.queryProtection(p)` returns `'rw-'`/`'r-x'`.
- **`Memory.patchCode(addr, 16, code => { new X86Writer(code, {pc: addr})… })`** worked:
  - `add_ints(10,3)` returned 7 after patching it into a subtraction, and 13 after restoring.
  - Protection stayed `r-x`.
- `Memory.copy` and `Memory.dup` work.

### 3.6 Interceptor (`a4_hooks.js`, `a12_interceptor_opts.js`, `a16_modify.js`)
**Context fields on Windows x64** (`this.context` in onEnter/onLeave, instruction probes, exception handler):
`pc, sp, rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8..r15, rip, xmm0..xmm15` (+`toJSON`).
- `xmmN` is a **16-byte ArrayBuffer**.
- There is **no rflags/eflags, no ymm, no segment or debug registers.**
- **QJS:** the fields are prototype accessors, so `for…in`/`Object.keys` return nothing (constructor `Object`). **V8:** they are own enumerable properties (constructor `CpuContext`). `JSON.stringify(ctx)` works in both, but **xmm values serialise as `{}`**. BEA must serialise from an explicit register list.

Win64 argument reading (verified on `mix_args(int a, float b, double c, float d, int e, double f)` and `four_floats`):

```js
const f32 = (ab) => new Float32Array(ab)[0], f64 = (ab) => new Float64Array(ab)[0];
onEnter(args) {
  const c = this.context;
  const a = args[0].toInt32();          // ecx
  const b = f32(c.xmm1);                // 2nd positional slot => xmm1 (args[1] is garbage rdx)
  const cc = f64(c.xmm2), d = f32(c.xmm3);
  const e = args[4].toInt32();          // Frida maps args[4+] to [rsp+0x28+8*(i-4)] (shadow space handled)
  const f = c.rsp.add(0x30).readDouble();   // or bits of args[5] -> double via DataView
}
onLeave(retval) { const r = f64(this.context.xmm0); }  // float/double return is in xmm0; retval == rax (garbage)
```

**Modification** (verified, both runtimes):
- `args[0] = ptr(5)` changed the argument.
- `retval.replace(ptr(123))` changed the integer return.
- `this.context.xmm0 = ab` in onLeave changed the float return (42.5).
- `this.context.rcx = ptr(100)` and `args[4] = ptr(1000)` (stack argument) worked.
- `this.context.xmm2 = ab` (double argument) worked.
- `this.context.xmm1 = ab` in physics_step onEnter changed dt: the speed delta became 9.81 instead of 0.157.

Other members:
- `this.returnAddress`, `this.threadId`, `this.depth`.
- **`this.lastError`** (Windows; it was 126). There is no `errno`.
- In onLeave, `retval` is `rax`.

**Instruction probe:** `Interceptor.attach(fnStart.add(0x36), function (args) { this.context… })` worked mid-function. At the store `mov [rbx+4], eax`, `eax` held the new counter and memory still held the old one.

**GOTCHA:** `Instruction.parse(hookedAddress)` returns the hook's `jmp …`, not the original code. Disassemble from a pre-hook copy, from the file bytes, or before attaching.

**Replace:**
- `Interceptor.replace(target, new NativeCallback((p, dt) => orig(p, dt * 2), 'float', ['pointer','float']))` with `orig = new NativeFunction(target, …)` calls the original. Interceptor bypasses itself on the replacing thread.
- `Interceptor.revert(target)` restores it.
- A second replace of the same target → `"already replaced this function"`.
- `replaceFast(target, cb)` returns a trampoline to the original (the target becomes `jmp qword ptr [rip+2]`). It worked: 17 calls in 17 frames. **OBSERVED-FLAKY:** one run got 0 callbacks while the agent's JS thread was inside `Thread.sleep()`. Avoid `Thread.sleep` in agents.

**Tiny functions:** `add_ints` is `lea eax,[rcx+rdx]; ret` (4 bytes, then padding).
- `attach`, `replace` and `replaceFast` all failed with `"unable to intercept function at 00007FF…; please file a bug"`.
- **`Interceptor.attach({ target: addr, relocation: 'forced' }, cbs)` worked** (overwrites into the padding).
- `relocation: 'checked'` and `'unchecked'` still fail.
- `touch_counter` (8 bytes) attached fine.
- `{target, scenario:'offline'}` is accepted (use it before resume).

**Commit, detach and races:**
- Changes are committed when the JS turn ends or when `send()`/an RPC returns. `Interceptor.flush()` forces it. Right after `attach()`, code at the target is unchanged until the flush. Always call `Interceptor.flush()` after attach/replace when you are about to call the target yourself or measure immediately.
- **Late callbacks:** in QJS one extra `onEnter` ran *after* `Interceptor.detachAll()` + `flush()` (an in-flight invocation). Guard JS handlers with a "detached" flag.
- `Interceptor.attach(ptr('0x1234'), …)` → `"access violation accessing 0x1234"`.

**Overhead per hooked call:** empty JS onEnter about 0.44 µs (QJS) and 1.1 µs (V8); CModule onEnter writing a ring about 0.19 µs (§1.9).

**IAT hook** (no inline patch, `a14`):
1. `slot = main.enumerateImports().find(i => i.name === 'Sleep').slot`. The slot is `r--` after loading.
2. `Memory.protect(page, 4096, 'rw-')`.
3. `slot.writePointer(nativeCallback)`. This caught 10 `Sleep` calls in 300 ms.
4. Restore with `slot.writePointer(orig)`.

### 3.7 NativeFunction and NativeCallback (oracle calls)
- These calls all returned exact results, on a scratch copy of the struct so game state is not perturbed:
  - `new NativeFunction(addr, 'float', ['pointer','float'])` → physics_step(scratch, 0.5) = 14.905 (expected 10 + 9.81 × 0.5).
  - `'double', ['int','float','double','float','int','double']` → mix = 15.375.
  - `'float', ['float','float','float','float']` → 1234.
  - `'double', ['pointer','double']` → car_energy.
- Struct-typed signatures such as `[['int','int']]` construct fine. By-value struct calls were **not** exercised.
- **Exception stealing (default `exceptions:'steal'`):** `physics_step(ptr(0), 0.1)` throws a JS `Error("access violation accessing 0x0")` with:
  - `type:'access-violation'`
  - `address` (faulting pc)
  - `memory:{operation:'read', address:'0x0'}`
  - `context`, `nativeContext`

  The target keeps running.
- **`{traps:'all'}` combined with `Stalker.follow(Process.getCurrentThreadId(), {events:{compile:true}})`** around one call produced the call's exact block coverage: entry, the `speed>50` branch block, and the blocks inside `sin`. This is the in-process oracle coverage primitive (§3.8).
- `{scheduling:'exclusive'}` is **required** when calling thread-control APIs such as `SuspendThread`/`GetThreadContext` on threads that may run JS callbacks. With the default cooperative scheduling the JS lock is released during the native call. A trapping thread can then take the lock and be suspended while holding it, and that **deadlocked a V8 run**. Exclusive scheduling fixed it (`a6d` vs `a6e`).
- `Process.runOnThread(tid, fn)` → Promise. It ran on the game thread (tid matched) with about 15 ms latency, because that thread was sleeping in `Sleep(16)`. Use it for thread-affine oracles (TLS, thread-confined state).

### 3.8 Stalker (`a5*.js`, `a14`)
- **Defaults:** `trustThreshold 1`, `queueCapacity 16384` (events), `queueDrainInterval 250` ms. Events are **32 bytes each on x64**.
- `Stalker.follow(tid, {events:{call, ret, exec, block, compile}, onReceive(ab), onCallSummary(summary), onEvent(nativeCb), transform, data})`, `Stalker.unfollow(tid)`, `Stalker.flush()`, `Stalker.garbageCollect()`.
- **`Stalker.parse(ab, {annotate, stringify})` formats:**
  - `['call', location, target, depth]`
  - `['ret', location, target, depth]`
  - `['block', start, end]`
  - `['compile', start, end]`

  `annotate:false` drops the leading type. Following starts mid-stack, so the first events are `ret` with negative depth.
- **Stalker blocks are dynamic blocks.** They split after `call` and do not split at join points. For physics_step the compile events were `+1760, +177e, +17b6`, while the static CFG has `+1760, +177e, +1786, +1808`. Map coverage to static blocks by range overlap. Lighthouse-style start+size output is fine.
- **Compile-event coverage** (one event per block, regardless of how often it runs) is the cheap coverage path: 481 unique main-module blocks in 600 ms with no measurable FPS cost on a 30 fps loop.
- **Transforms:** `transform(iterator){ let i = iterator.next(); … iterator.putCallout(ctx => …); do iterator.keep(); while ((i = iterator.next()) !== null); }` works. A CModule transform (`gum_stalker_iterator_next/keep/put_callout`) passed as `transform: cm.transform, data: ptr` works and counted physics_step entries **exactly**: hits equal last − first + 1 of the `counter` value seen inside the callout, in every run.
- `onCallSummary` delivers `{targetHex: count}` per drain: 5 batches in about 1.2 s, 1-8 keys each, in `a5b`/`a5d`. In `a5` (500 ms window, light workload) the merged summary came back **empty**, unexplained. Treat it as best-effort and prefer `onReceive` or a CModule transform when counts matter.
- `Stalker.addCallProbe(addr, args => …)` / `removeCallProbe(id)` work while the thread is followed (args[0] was the car pointer).
- `Stalker.exclude({base, size})` is accepted. It didn't change call counts in my workload, because the calls were inside the main module.

**Overhead on a call-heavy tight loop** (fixture `--sleep 0 --hot 20000`, about 47K frames/s unstalked):

| Mode | Frames/s | Notes |
|---|---|---|
| Not followed | 47,064 | |
| `follow` with no events | 28,600 (1.65x slower) | |
| `compile` events | 27,900 | |
| `call` events, default queue | about 510 (**about 90x slower**) | Delivered only 68,267 events/s, which is exactly the queue capacity limit (16384/250 ms) → **silent loss** |
| JS callout on every main-module block | QJS 97–100; V8 14.9 | QJS about 6.0M callouts/s; V8 about 0.85M/s |
| CModule callout on every main-module block | QJS about 190 | About 11M callouts/s |

**Loss fix (VERIFIED `a14`):** set `Stalker.queueCapacity = 1<<21; Stalker.queueDrainInterval = 50;` *before* `follow`. In a window with 32 complete frames I then received exactly 64,000 hot_fn call events (32 × 2000). With the defaults about 3–6 % were lost.

**Lifetime and interplay gotchas** (all VERIFIED):
- **QJS + CModule:** when the CModule object was dropped right after `unfollow` (it went out of scope), QJS freed it immediately while the thread was still in Stalker code, and **the target crashed (2 of 2 runs)**. Keeping `globalThis.keep = [cm, …]` fixed it. Keep CModules and NativeCallbacks alive until well after `unfollow` + `flush` + `garbageCollect`.
- An Interceptor hook added *after* the followed thread compiled the block is **not seen** (0 hits). `Stalker.invalidate(tid, fnAddr)` after attach/detach makes it visible (33–37 hits).
- Hook → follow → **detach hook while followed** (no invalidate) → **target crashed in 1 of 4 runs**, and the stale hook kept firing. 0 of 4 crashed with `Stalker.invalidate`. Rule: change hooks only when no thread is followed, or invalidate.
- Re-following immediately after `unfollow` worked in the controlled test. In one mixed V8 run the next CModule follow produced 0 hits. Prefer `flush` + `garbageCollect` and a short settle (about 300 ms) before re-following the same thread.

### 3.9 Hardware breakpoints and watchpoints (`a6*.js`, `a15`, `a17`)
**API** (these are **instance methods of `ThreadDetails`**, from `Process.enumerateThreads()` / `Process.getThreadById(tid)` / thread-observer callbacks):

```js
t.setHardwareWatchpoint(id /*0..3*/, address, size /*1|2|4|8*/, conditions /*'w'|'rw'|'r'*/);
t.unsetHardwareWatchpoint(id);
t.setHardwareBreakpoint(id /*0..3*/, address);   // execute
t.unsetHardwareBreakpoint(id);
```
Each call returns immediately (setMs 0).

**Delivery:**
- `Process.setExceptionHandler(d => …)` receives **`d.type === 'single-step'`** for both data watchpoints and execute breakpoints; never `'breakpoint'`. `d.memory` is **null**.
- Data watchpoints trap **after** the access: `d.address`/`d.context.pc` is the *next* instruction (physics_step+0x39 for the store at +0x36). Recover the accessing instruction with `Process.findFunctionRange(pc)` plus a linear `Instruction.parse` sweep until `insn.next.equals(pc)`. That correctly found `mov dword ptr [rbx + 4], eax`.
- Which slot fired: read DR6 from `nativeContext` (B0..B3 = bits 0..3). Windows x64 `CONTEXT` offsets, verified by reading back the expected Dr0 address and Dr7:
  - `ContextFlags +0x30`
  - `EFlags +0x44` (u32)
  - `Dr0..Dr3 +0x48/+0x50/+0x58/+0x60`
  - `Dr6 +0x68`
  - `Dr7 +0x70`

**Encoding observed** (`a17`; DR7 with LE bit 8 set by Frida):

| Call | DRn | DR7 | Hits |
|---|---|---|---|
| id0, car+8, 8, 'w' | DR0=car+8 | `0x90101` (L0, RW=01, LEN=10) | pos[0] store (`+0x17dd`) only |
| id1, counter, 4, **'r'** | DR1 | `0xf00104` (RW=**11**, LEN=11) | reads **and** writes: 'r' ≡ 'rw' |
| id2, speed, 2, 'w' | DR2 | `0x5000110` (LEN=01) | speed store |
| id3, speed, 1, 'w' | DR3 | `0x10000140` (LEN=00) | speed store |
| id0, **counter (+4), 8** | DR0=car+4 | `0x90101` | **aligned down**: counter and speed stores both trap |
| **id5**, counter, 4 | none set | `0xa8a20044` (**garbage**) | 0 hits; no error thrown |

**No validation:** size 3, size 16, misaligned addresses, id 4/5, `'r'`, and setting a breakpoint and a watchpoint in the same id all "succeed". BEA must validate: id 0..3; size ∈ {1,2,4,8}; address aligned to size; `'r'` reported as `'rw'`; 4 slots shared between breakpoints and watchpoints.

**Per-thread semantics:**
- Armed on the game thread only: 0 of the worker thread's writes were seen.
- Armed on all 5 threads: game writes (+0x1799) and worker writes (`touch_counter` +0x1937) were both caught.
- **New threads:** `Process.attachThreadObserver({onAdded(t){ t.setHardwareWatchpoint(…) }})`. `onAdded` runs **on the new thread itself**, before its start routine, and is also called for every existing thread at attach. The new thread's first write was caught.

**The unset race** (`a6d`, `a6e`):
- While the watchpoint traps frequently ('rw' on `speed`, about 3 traps per frame), `t.unsetHardwareWatchpoint(id)` called from the agent JS thread **failed 3/8 (QJS), 4/8 (QJS) and 5/8 (V8)** times. Afterwards DR7 (read with `GetThreadContext`) was still `0xf0501` and traps continued.
- Cause (inferred from timing): the trapping thread is inside exception dispatch, waiting for the JS lock. The unset's `SetThreadContext` is then overwritten when the dispatcher restores the CONTEXT captured at the trap.
- **Reliable protocol (8/8):** set a flag, and in the next trap write `nativeContext+0x70 (Dr7) = 0` (or clear only that slot's L/G and RW/LEN bits) and `Dr0..3 = 0`, return true, *and* also call `unset*()` for threads that are not trapping. Verify with `GetThreadContext` (needs `{scheduling:'exclusive'}`).

**Execute breakpoints** (`a6b`, `a6c`):

| Handler behaviour | Result |
|---|---|
| Plain `return true` | **Infinite re-trigger**: 200+ traps, the game thread advanced 1 frame, and `unsetHardwareBreakpoint` from the JS thread could not stop it |
| `nc.add(0x44).writeU32(nc.add(0x44).readU32() \| 0x10000)` (set RF), then `return true` | Exactly one trap per call (13/15, 16/16, 11/11 hits/frames) |
| Clear DR7 in `nativeContext` | One-shot breakpoint (1 hit) |

The portable `d.context` has no eflags field (`ctxHasEflags: []`).

### 3.10 MemoryAccessMonitor (`a7_mam.js`)

```js
MemoryAccessMonitor.enable({ base: page, size: 4096 }, { onAccess(d) { /* d.operation 'read'|'write'|'execute', d.from, d.address,
  d.rangeIndex, d.pageIndex, d.pagesCompleted, d.pagesTotal, d.threadId, d.context */ } });
MemoryAccessMonitor.disable();
```
- It fires **once per page per enable** (guard-page semantics); one enable gave exactly 1 notification.
- `from` is the **faulting instruction itself** (e.g. `touch_counter+0` for `add [rcx+4],1000`), so no back-stepping is needed, unlike hardware watchpoints.
- It covers **all threads**, and it works on code pages: an `execute` access at `physics_step`.
- **Re-arm loop:** in `onAccess`, call `setImmediate(() => { disable(); enable(...) })`. That gave 60 accesses from 2 threads in about 1.4 s, about 43/s. It is page-granular, so it also caught unrelated `g_frame` writes on the same page; filter by `d.address`.
- In QJS `Object.keys(d)` shows only `['context']`, because the other fields are accessors.

### 3.11 Exceptions and crash capture (`a8_crash.js`, `h8_crash_host.mjs`)
`Process.setExceptionHandler(d => …)` sees, both VERIFIED:
- the fixture's null write: `type 'access-violation'`, `address` = the faulting pc, `memory {operation:'write', address:'0x0'}`, `context` (all registers), `nativeContext`;
- **first-chance exceptions the app handles itself** (kernel32 `IsBadReadPtr` AV): returning `false` lets the app's SEH handle it and the game continues.

The details object has no exception code or EXCEPTION_RECORD; use `type`.

Other types seen:
- `illegal-instruction` (gcc puts a `ud2` after the null store);
- `single-step` (hardware breakpoints and watchpoints).

Patterns that were verified:
- **Report before death:** `send(info); recv('ack', () => {}).wait(); return false;`. The host posts `{type:'ack'}` when the report arrives; the ack wait took 0–1 ms locally. The host got the full report (registers, `Thread.backtrace(d.context, Backtracer.ACCURATE)`, a stack hexdump) and then `detached('process-terminated')`.
- **Recover:** `d.context.pc = d.address.add(Instruction.parse(d.address).size); return true;`. The process continued. It hit the gcc `ud2` next, which the same trick skipped, then ran to normal exit.
- The ACCURATE backtrace lists *return addresses* (callers). Prepend the faulting pc yourself.

### 3.12 DebugSymbol, ApiResolver, ControlFlowGraph, Instruction (`a11_misc.js`)
**DebugSymbol** (dbghelp; gcc DWARF binary, no PDB):
- The first call took about 30 ms.
- `fromAddress(physics_step+0x10)` → `{name:'physics_step', moduleName, fileName:'', lineNumber:0}`. The string form is `"0x… fixture_gcc.exe!physics_step"` with no "+0x10". `fileName` and `lineNumber` are `''`/`0`, not null, when there is no line info.
- **Static function** at `+0x1940` (`worker_main`) → `'touch_counter'`, i.e. the **wrong nearest export**.
- **`moduleName` is wrong for other modules:** kernel32!Sleep, ntdll and frida-agent addresses all reported `"fixture_gcc.exe"`.
- Lookups by name:
  - `fromName('physics_step')` and `fromName('fixture_gcc!physics_step')` work.
  - `getFunctionByName('physics_step')` works; `getFunctionByName('worker_main')` → `"unable to find function with name 'worker_main'"`.
  - `findFunctionsNamed` and `findFunctionsMatching('*physics*')` work; `'kernel32!Sleep*'` returned 4.
- `DebugSymbol.load(exePath)` changed nothing, since dbghelp can't read DWARF.
- **BEA:** do symbolization itself (exports + REA/Ghidra symbols + `.pdata` function ranges) and use DebugSymbol only as a hint.

**ApiResolver('module')**:
- `exports:fixture_gcc.exe!*physics*` → name = **full module path** + `!physics_step`.
- `imports:fixture_gcc.exe!Sleep` → `KERNEL32.dll!Sleep`, with the resolved address in KERNEL32.
- `sections:fixture_gcc.exe!.text` → includes `size`.
- A `/i` suffix makes it case-insensitive.
- `new ApiResolver('objc')` → `"the specified ApiResolver is not available"`.

**`Process.findFunctionRange(addr)`** returns `{base, size}` from `.pdata` and is exact: physics_step 181 bytes and touch_counter 8 bytes, both matching objdump. `getFunctionRange` throws when there is no range.

**`new ControlFlowGraph(fn)`**:
- Members: `.entrypoint`, `.entryBlock`, `.blocks[{start, end, successors[], predecessors[], immediateDominator, instructions[]}]`, `.findBlockContaining()`, `.dominates()`, `.enumerateDominatingSites()`.
- physics_step gave 4 blocks that matched objdump: `1760→{1808, 177e}`, `177e→1786`, `1786→(ret)`, `1808→1786`.

**`Instruction.parse(p)`** on x64:
- Fields: `address, next, size, mnemonic, opStr, groups[]` (capstone groups: `mode64`, `sse1`, `call`, `branch_relative`), `operands[]`, `regsAccessed{read, written}`, `regsRead[]` (implicit), `regsWritten[]` (implicit), `toString()`.
- `constructor.name` is `'Instruction'`; `X86Instruction` is not exposed by name.
- **Operands:**
  - `{type:'reg', value:'rbx', size:8, access:'r'}`
  - `{type:'imm', value:'48', size, access:''}`. **Immediates are decimal strings**, e.g. a call target `"140701662810544"`; use `ptr()` or `BigInt`.
  - `{type:'mem', value:{base:'rip', scale:1, disp:43635}, size:4, access:'r'}`. **RIP-relative disp is relative to `next`**: absolute = `insn.next.add(disp)`.
- A bad address throws `"access violation accessing 0x10"`.

### 3.13 Threads, backtraces and observers
- `Process.enumerateThreads()` → `[{id, name?, state, context, entrypoint?{routine, parameter?}, set/unsetHardware*}]`.
  - Frida's own threads are cloaked.
  - **`state` was `'running'` even for threads sleeping in `Sleep()`**; it is unreliable.
  - `name` was undefined.
  - `entrypoint.routine` identifies threads: main = `mainCRTStartup` (+0x105f), worker = `worker_main` (+0x1940), ntdll pool threads = `ntdll+0x24990`.
- `Process.getThreadById(tid)` / `findThreadById(1)` → `null`.
- `Thread.backtrace(this.context, Backtracer.ACCURATE)` from physics_step gave 5 correct frames: main → `__tmainCRTStartup` → `mainCRTStartup` → `BaseThreadInitThunk` → `RtlUserThreadStart`.
- `FUZZY` gave 7 frames, adding **false positives** (`msvcrt!onexit`, `atexit`).
- `Thread.backtrace()` without a context, from the agent thread, returns frida-agent frames and is useless.
- `Process.attachModuleObserver({onAdded, onRemoved})` calls onAdded synchronously for all 31 existing modules, then for `version.dll` after `Module.load`.
- `Process.attachThreadObserver({onAdded, onRemoved, onRenamed})` calls onAdded for the 4 existing threads, then on a new `CreateThread`, running *on the new thread* (§3.9). onRemoved fires on exit.
- `Process.runOnThread(tid, fn)`: see §3.7.

### 3.14 Static↔runtime mapping (ASLR) and module dumps
```js
// a11: preferred base must come from disk (loader rewrites the in-memory header)
const nt = main.base.add(main.base.add(0x3c).readU32());
nt.add(0x18 + 0x18).readU64();                 // => 0x7ff7a8a10000  (actual base, NOT preferred)
const f = new File(main.path, "rb"); const hdr = f.readBytes(0x400); f.close();
const dv = new DataView(hdr); const fileBase = dv.getBigUint64(dv.getUint32(0x3c, true) + 0x30, true); // 0x140000000
const runtime = main.base.add(ptr("0x" + (BigInt("0x140001760") - fileBase).toString(16)));          // == physics_step export
```
- `File(path,'rb').readBytes(n)` works inside the agent.
- For BEA's evidence, also record the module path, size, and the file hash/TimeDateStamp, so a REA/Ghidra address is applied only to the same image.
- **Dumps:** `module.base.readByteArray(module.size)` read whole images in one call without errors (exe 135 KB, ntdll 2.5 MB in 9 ms, kernel32 0.8 MB). Per-range reads over `module.enumerateRanges('---')` also succeeded. `send({…}, buf)` delivered a 135 KB image. The in-memory image is *mapped* layout, not file layout, and its header ImageBase differs from the file.

### 3.15 Miscellaneous verified
- `new Profiler()`, `prof.instrument(fn, new CycleSampler(), {describe(args){…}})`, `prof.generateReport()` →
  `<profile-report><thread><node name="physics_step" total-calls="14" total-duration="36876"><worst-case duration="4746">speed=5.494</worst-case>…`
  This gives cheap worst-case timing per function.
- `Script.evaluate('/plugin.js', src)` → value.
- `await Script.load('/plugin2.js', 'export const answer = 42; …')` → ESM namespace (`answer: 42`). It works in both runtimes.
- **CModule (TinyCC) can include:**
  - `<glib.h>`, `<gum/gumstalker.h>`, `<gum/guminterceptor.h>`
  - `gum_invocation_context_get_nth_argument(ic, n)`
  - `gum_stalker_iterator_next/keep/put_callout`

  `extern` symbols are passed as pointers in the 2nd constructor argument (use `Memory.alloc`'d cells).

---

## 4. Injection footprint and side effects (VERIFIED, `h21_footprint.mjs`)
- **Before attach:** the target started outside Frida had `ntdll, KERNEL32, KERNELBASE, msvcrt` loaded.
- **After attach** it gained **frida-agent.dll** (visible to `tasklist /M`, hidden from GumJS `enumerateModules`) plus these 24 DLLs:
  SHLWAPI, ucrtbase, WS2_32, RPCRT4, ADVAPI32, DNSAPI, IPHLPAPI, sechost, CRYPT32, DSPARSE, USER32, win32u, GDI32, gdi32full, msvcp_win, PSAPI, SHELL32, ole32, combase, bcrypt, WINMM, NSI, IMM32, kernel.appcore.
  There were also 3 ntdll thread-pool threads.
- **After `session.detach()`**, frida-agent.dll unloaded, but **11 DLLs stayed loaded**: ucrtbase, RPCRT4, sechost, USER32, win32u, GDI32, gdi32full, msvcp_win, bcrypt, IMM32, bcryptPrimitives.
- **Consequences for BEA:**
  - Report the detectable footprint in limitations.
  - Detach is not a full restore.
  - Anti-tamper or anti-cheat-protected games may react. That is out of scope here; nothing protected was tested.

---

## 5. QJS vs V8: measured differences

| Aspect | QJS (default) | V8 |
|---|---|---|
| createScript + load (small) | 1.2 + 0.9 ms | 8.7 + 3 ms |
| Empty JS `onEnter` | about 0.44 µs (2.28M/s) | about 1.1 µs (0.89M/s) |
| Stalker JS callouts | about 6M/s | about 0.85M/s |
| JS tight loop (float scan) | 33 MB/s | 1.17 GB/s |
| `ArrayBuffer.wrap` iteration | 33 MB/s | 153 MB/s (slower than copy) |
| Bytecode `compileScript` | yes | no |
| `snapshotScript` | n/a | yes |
| Context object | prototype accessors (`Object.keys` empty) | own enumerable props |
| GC | refcount, eager (**CModule lifetime hazard**) | lazy |
| Stack traces | line only (column 1) | line:column |

**Recommendation:** QJS by default, because hooks and callouts are cheap and the runtime is small. Use CModule for anything per-event or per-byte. Use V8 only for agents that do heavy JS compute.

---

## 6. Gotchas (numbered, all observed)
1. `JSON.stringify` fails on BigInt (`ppid`, compiler diagnostics `line`/`code`). Use a replacer.
2. `load()` resolves even if the top-level agent code throws. Treat `error` messages during load as failure.
3. `device.processCrashed` never fires on Windows; crash detail only comes from the agent exception handler.
4. A dead process spawned with `stdio:'pipe'` is still returned by `enumerateProcesses({pids})`.
5. `send()` has no backpressure: per-event sends at MHz rates grow target memory without bound (21 GB observed). The host ceiling is about 8K msgs/s.
6. One JS thread per target process: a long RPC blocks every script's RPC and messages.
7. `Instruction.parse` at a hooked address shows the hook's `jmp`.
8. Functions shorter than 5 bytes can't be hooked unless you pass `{target, relocation:'forced'}`.
9. Interceptor changes are pending until the JS turn ends or `flush()`; late callbacks are possible after detach.
10. Float args and returns live in `xmmN` (16-byte ArrayBuffer); `args[1]` for a float is garbage, and `retval` is rax.
11. QJS `CpuContext`/details objects have no own keys, so you cannot serialise them generically.
12. Stalker default queue drops events silently above about 65K/s; raise `queueCapacity`.
13. Stalker call events slow call-heavy code by about 90x; use compile events or a CModule transform for coverage.
14. QJS frees a CModule as soon as it is unreferenced, and a Stalker thread still using it crashed the target.
15. Hooks added while a thread is followed are invisible, and detaching hooks while followed crashed the target; use `Stalker.invalidate`.
16. Hardware breakpoints and watchpoints report `type:'single-step'` and `memory:null`; the data-watchpoint pc is post-access.
17. `set/unsetHardware*` validate nothing (id ≥ 4 corrupts DR7, misaligned addresses are aligned down, `'r'` becomes `'rw'`).
18. `unsetHardware*` from the JS thread can lose a race with a trapping thread; disarm through `nativeContext` in the handler.
19. Execute hardware breakpoints loop forever unless the handler sets RF or clears DR7 in `nativeContext`.
20. `NativeFunction` with cooperative scheduling plus `SuspendThread` deadlocked V8; use `{scheduling:'exclusive'}`.
21. DebugSymbol on non-PDB binaries returns the nearest export without displacement, and its `moduleName` is wrong for other modules.
22. `enumerateSymbols` on PE returns exports only, mis-typed (data as `function`) and with gap sizes; `findSymbolByName` returned null.
23. `enumerateSections` shows gcc long names as `/4`; `enumerateDependencies` is `[]`; `module.version` is `null`; ranges have no `file` field.
24. The in-memory PE `ImageBase` equals the runtime base; read the preferred base from disk.
25. `exceptor:'off'` makes any agent memory fault fatal to the target.
26. `Thread.state` reads `'running'` for sleeping threads.
27. `ApiResolver` export and section names carry the full module path.
28. `Instruction` immediates are decimal strings, and RIP-relative `disp` is relative to `insn.next`.
29. Injection leaves 11 system DLLs loaded after detach; frida-agent.dll is visible to OS tooling while attached.
30. `Interceptor.replaceFast` once delivered 0 callbacks while the agent JS thread was in `Thread.sleep` (OBSERVED-FLAKY); don't block the agent thread.

---

## 7. Recommended BEA patterns (snippets that ran here)

**Host session bootstrap with early instrumentation and stdio**
```js
const dev = await frida.getLocalDevice();
const onOut = (pid, fd, data) => data.length === 0 ? eof(pid, fd) : chunk(pid, fd, data);
dev.output.connect(onOut);
const pid = await dev.spawn([exe, ...args], { cwd, env: { BEA_RUN: id }, stdio: "pipe" });
const session = await dev.attach(pid);                       // default exceptor; never 'off'
session.detached.connect((reason, crash) => finalize(reason)); // crash is always null on Windows
const script = await session.createScript(bundle, { name: "bea-core", runtime: "qjs" });
script.logHandler = (lvl, txt) => log(lvl, txt);
script.message.connect((m, data) => m.type === "error" ? agentError(m) : route(m.payload, data));
await script.load();                                          // then check no 'error' arrived
await dev.resume(pid);
// cleanup: await script.unload(); await session.detach(); await dev.kill(pid) (owned targets only)
```

**Bounded event streaming from a hook** (QJS, about 1.2M events/s, loss-free):
```js
const CAP = 16384; let buf = new Int32Array(CAP), n = 0;
Interceptor.attach(target, { onEnter(args) { buf[n++] = args[0].toInt32();
  if (n === CAP) { send({ k: "evt", n }, buf.buffer); buf = new Int32Array(CAP); n = 0; } } });
setInterval(() => { if (n) { send({ k: "evt", n }, buf.buffer.slice(0, n * 4)); n = 0; } }, 50);
Interceptor.flush();
```
For rates above about 1M/s use the CModule ring (`a10_throughput.js`, variant `cmodule-ring`), and count `dropped` explicitly so coverage can be reported.

**What writes this address** (hardware, reliable arm and disarm):
```js
let disarm = false;
Process.setExceptionHandler((d) => {
  if (d.type !== "single-step") return false;
  const dr6 = d.nativeContext.add(0x68).readU64();            // which slot (bits 0..3)
  report({ tid: Process.getCurrentThreadId(), pcAfter: d.context.pc, dr6 });
  if (disarm) { d.nativeContext.add(0x70).writeU64(0); for (let i = 0; i < 4; i++) d.nativeContext.add(0x48 + 8 * i).writeU64(0); }
  return true;
});
const arm = (t) => t.setHardwareWatchpoint(0, addr, 4, "w");  // validate id/size/alignment first
Process.enumerateThreads().forEach(arm);
const obs = Process.attachThreadObserver({ onAdded: arm });   // runs on the new thread
// stop: obs.detach(); disarm = true; threads.forEach(t => t.unsetHardwareWatchpoint(0)); verify via GetThreadContext({scheduling:'exclusive'})
// writer = instruction whose .next == pcAfter (sweep from Process.findFunctionRange(pcAfter).base)
```
Use `MemoryAccessMonitor` (process-wide, page-granular, reports the faulting instruction itself) when the 4 debug-register slots or per-thread arming are a problem.

**Execute breakpoint without looping:** in the handler, `nc.add(0x44).writeU32(nc.add(0x44).readU32() | 0x10000); return true;`

**Oracle call with coverage and crash safety:**
```js
const fn = new NativeFunction(addr, "float", ["pointer", "float"], { traps: "all" });
const blocks = [];
Stalker.follow(Process.getCurrentThreadId(), { events: { compile: true },
  onReceive(ev) { for (const [s, e] of Stalker.parse(ev, { annotate: false })) blocks.push([s, e]); } });
let ret, fault = null;
try { ret = fn(scratchStruct, 0.1); } catch (e) { fault = { type: e.type, address: e.address, memory: e.memory }; }
Stalker.unfollow(); Stalker.flush();   // keep any CModule/NativeCallback referenced until after GC
```

**Coverage of a running thread:** set `Stalker.queueCapacity = 1 << 21; Stalker.queueDrainInterval = 50;`, use `events:{compile:true}` (or a CModule transform for hit counts), and `Stalker.invalidate` after any hook change.

---

## 8. Not verified / open
- PDB symbol resolution through dbghelp (no MSVC libs or SDK on this machine), and the symbol-server path (`symsrv.dll` is absent).
- `Worker` use, `Compiler.watch`, `LanguageServer`, `PatternCompiler`, `Script.enableDebugger`, `snapshotTransport:'shared-memory'`.
- Struct-by-value `NativeFunction` arguments.
- Behaviour against protected or anti-debug games. Only my own fixture was exercised.
- Why the V8 `cmodule-ring` run never delivered its final message (the data itself arrived).
- Whether Stalker `onCallSummary` is lossy under queue pressure.
- drcov or Lighthouse export of compile-event coverage is BELIEVED straightforward (module-relative start plus size) but was not round-tripped through Lighthouse.
