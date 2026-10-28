# REA process ownership & Windows native support → BEA process-supervision design

Research key: `rea-process`. Sources: REA clone at `<rea-checkout>` (read-only, v6.7.0 per
`native/windows/build/manifest.json`), plus lab experiments in
`<scratch>/bea-lab/rea-process/`
(`sleeper.c`, `jobhost.c`, `exp.mjs`, `frida2.mjs`, `hard.mjs`, `inherit.mjs`, `dbg.mjs`).

Legend: **VERIFIED** = I read the code at the cited line or ran it in the lab. **BELIEVED** = from docs or memory, not re-checked here.

---

## 0. TL;DR

- REA's Windows story is a **custom Node-API addon** (`native/windows/build/rea-windows-x64.node`, ~880 KB, built by a
  Linux/MinGW cross lane). It provides two things: (1) **owned process trees** built on unnamed Job Objects with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no breakaway, and atomic assignment via `PROC_THREAD_ATTRIBUTE_JOB_LIST`
  while the child is suspended; and (2) a **private-runtime filesystem** (NTFS handle-based path admission, private
  DACLs, snapshots, recursive cleanup). The process half is about 500 lines of C++ (`native/windows/src/process.cc`). The TypeScript
  wrapper `src/windows/WindowsOwnedProcess.ts` polls the addon every 25 ms for output and exit.
- REA's **POSIX** story is far heavier (about 3,200 lines across `ProcessOwnership.ts` and `ProcessOwnershipObservation.ts`). Each child gets a
  dedicated process group (`detached: true`) and an env run token (`REA_PROCESS_RUN_ID`). Identity comes from start time
  (`/proc/<pid>/stat` field 22 on Linux, a runtime-compiled Swift sysctl helper on macOS). Cleanup is a multi-pass
  "token-verify every member, then `kill(-pgid, SIGKILL)`, then sweep for token-bearing escapees" algorithm with
  revalidation limits. **BEA does not need any of this** if it uses kernel containment (Job Object or subreaper).
- REA only falls back to `taskkill /PID <pid> /T /F` in two places (Electron cleanup, Ghidra fallback) and explicitly
  says that is "not Job Object ownership proof". REA **refuses PTY process capture on Windows** because descendant
  cleanup is unverified. REA's Frida integration **never kills** a spawned target: on close it detaches and *resumes*
  it.
- **Lab results (VERIFIED on this host):**
  1. Node's own `child_process.spawn` (non-detached) kills the **direct child only** when Node exits (libuv global job).
     Grandchildren **survive**. `detached: true` children all survive.
  2. `taskkill /T /F` kills an intact tree in about 100 ms. If the root has already exited it fails with exit 128
     (`ERROR: The process "<pid>" not found`) and **leaks** surviving descendants. It cannot follow orphans.
  3. A **170-line C helper** (`jobhost.c`) owns a KILL_ON_JOB_CLOSE job and kills **everything** in about 105 ms. That
     includes orphaned, `DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP`, and `CREATE_BREAKAWAY_FROM_JOB`-attempting
     descendants. Three triggers all work: a control "kill" line, killing the helper process, and stdin EOF. A hard `TerminateProcess` of the
     *parent Node* also kills the whole tree, through the chain libuv job → helper dies → job handle closes → tree dies.
  4. A **Frida-spawned** process is suspended and *not in any job* (`wasInJob=0`). The helper can `AssignProcessToJobObject` it
     **before `device.resume()`**, which gives full containment. `device.kill(pid)` kills **only the root**, and the child
     survives. A Frida-spawned target **survives the death of the Node process** that spawned it.
  5. Frida can **attach to a helper-created `CREATE_SUSPENDED` process** (script loaded, 34 modules visible) before the
     helper resumes it. The exit code is reported by the helper (7 in the test).
  6. With `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, a crashing target exits in about 250 ms with NTSTATUS `0xC0000005` as its
     exit code, with no WER dialog hang.
- **Recommendation:** ship a tiny standalone helper executable, `bea-jobhost.exe` (C, MinGW or MSVC, about 200 lines), one
  instance per spawned target. Use the same idea later as `bea-reaper` on Linux (`PR_SET_CHILD_SUBREAPER` + pgid + pdeathsig).
  Do **not** build a Node-API addon, and do not rely on taskkill, PowerShell, or Frida's kill for tree ownership. Attached
  (not spawned) processes never enter a BEA job, so requirement (d) holds by construction: BEA cannot kill an attached
  process through its kill path.

---

## 1. REA inventory (what lives where)

| Path | Lines | Role |
|---|---|---|
| `native/windows/README.md` | 240 | Contract for the addon: Job Objects, private runtimes, retries, verification lanes |
| `native/windows/build/manifest.json` | 9 | `{packageVersion:"6.7.0", platform:"win32", architecture:"x64", abiVersion:1, nodeApiVersion:8, artifact, artifactSha256}` |
| `native/windows/build/rea-windows-x64.node` | binary (881,284 B) | The addon (present in this clone) |
| `native/windows/src/addon.cc` | 191 | Single exported function `call(operation: string, args: unknown[])`, type-tagged opaque handles, error mapping, env cleanup hook |
| `native/windows/src/process.cc` | 514 | `process_spawn/poll/alive/terminate/close/stdin_write/stdin_close/caller_token`, `inspect` self-test |
| `native/windows/src/filesystem.cc` | 844 | `open/close/read/runtime_create/mkdir/open/write/snapshot/snapshot_cancel/close`, cutter bridge helpers |
| `native/windows/src/authority.hpp`, `handle_close.hpp` | 268+206 | `Failure` (constraint + Win32 code + path), RAII `Handle` with "close-blocked" retry semantics |
| `tests/fixtures/windows/processBoundary.cc` | – | Conformance probe (breakaway with `CREATE_BREAKAWAY_FROM_JOB`, env ordering, affinity) |
| `src/windows/WindowsNativeLoader.ts` | 231 | Verifies manifest version, SHA-256, PE32+ x64 header, N-API ≥ 8, then runs `inspect` self-test; caches result |
| `src/windows/WindowsOwnedProcess.ts` | 431 | EventEmitter + PassThrough streams over the addon; 25 ms poll loop; `kill()` = terminate job; `cleanup()` ≤ 5 s settle |
| `src/windows/WindowsPrivateRuntime.ts` | 275 | Private runtime directory owner; cleanup retries 10×100 ms only for Win32 32/33 |
| `src/process/ProviderProcess.ts` | 953 | `spawnOwnedProviderProcess` (Windows → `WindowsOwnedProcess`, POSIX → `spawn(detached)`), `ProviderProcessSupervisor` (bounded capture, stop escalation) |
| `src/process/OwnedCommand.ts` | 467 | `runOwnedCommand(spawn, {timeoutMs, diagnosticBytes, …})` short-lived command runner with typed `OwnedCommandFailure` |
| `src/process/ProcessOwnership.ts` | 1820 | POSIX token-verified group cleanup; `cleanupWindowsProcessTree` (taskkill) |
| `src/process/ProcessOwnershipObservation.ts` | 1371 | `ps -axo pid=,ppid=,pgid=,uid=,stat=,command=`, `/proc` identity, env token reads, lineage observation |
| `src/process/DarwinProcessRunTokenReader.ts` | 794 | Compiles a Swift sysctl helper at runtime (swiftc/xcrun) to read KERN_PROCARGS2 env + start identity |
| `src/process/ExecFileOutput.ts`, `ExecFileBoundedOutput.ts` | 220, 73 | execFile wrappers: stop-signal + 5 s grace → SIGKILL; head+tail bounded capture |
| `src/process/ProviderDeadline.ts` | 158 | `ProviderStartupDeadline`: monotonic absolute deadline composed with caller AbortSignal |
| `src/process/WindowsBatchCommand.ts` | 81 | Safe `.bat/.cmd` invocation through `cmd.exe /d /e:on /v:off /s /c` (CVE-2024-27980) |
| `src/process/WindowsAuthority.ts` | 123 | Capability reporting: `job_object_process_ownership`, `private_runtime_dacl`, `reparse_safe_path_admission` |
| `src/process/LinuxResourceLimits.ts` | 88 | `prlimit --as --fsize --cpu --core=0` argv builder + inherited-limit clamp from `/proc/self/limits` |
| `src/process/ownedDebuggerSession.ts` | 314 | GDB/Rizin inferior identity via `/proc/<pid>/stat` start time; detach-with-timeout |
| `src/process/capture/*` | ~5k | PTY (node-pty) process capture on Linux/macOS only |
| `src/main/processShutdown.ts`, `src/main/shutdown.ts` | 117, ~150 | Server shutdown triggers + idempotent teardown |
| `src/providers/*` | ~700 | `retainOwnedCommandCleanup`, `closeAnalysisClient` (cleanup failures become retained lease objects) |
| `src/filesystem/*` | ~1.1k | "Owned" descriptors: stable-file admission, hashing, staged outputs with truthful close results |
| `scripts/rea.mjs` | 257 | Dispatcher: `--mcp`/`mcp` → `dist/mcp/main.js`; `mcp --http`; `mcp doctor`; else Incur CLI. No process-ownership logic; it handles SIGPIPE exit 141 and empty `USERPROFILE` |

Packages (VERIFIED from `package.json`): `cross-spawn@7.0.6` (used only in `src/application/UpdateRuntime.ts:5`),
`@lydell/node-pty@1.1.0` (PTY capture, `src/process/capture/ProcessHarness.ts:281`), `frida@17.23.2` (optional).
`execa`, `tree-kill`, and `signal-exit` exist in `node_modules` only as transitive dependencies. REA's own code does not import them.
**No** `tree-kill`/`ps-list`/`pidtree` style helper is used. REA deliberately avoids PID-enumeration kill-trees on Windows.

---

## 2. REA's Windows native addon in detail

### 2.1 Loader and authority (VERIFIED, `src/windows/WindowsNativeLoader.ts`)

- The addon path is **package-relative only** (`new URL("../../native/windows/build/rea-windows-x64.node", import.meta.url)`, line ~205).
  There is no environment override, and README states that "There is no environment override for loading an arbitrary native module".
- Admission checks run in order (lines 109–170):
  1. `platform === "win32" && arch === "x64"`
  2. `process.versions.napi >= 8`
  3. `manifest.packageVersion === PACKAGE_METADATA.version`
  4. SHA-256 of the file matches the manifest
  5. PE checks: `MZ` → `PE\0\0` → machine `0x8664` → optional header `0x20b`
  6. `require()` it
  7. `binding.call("inspect", [])` must return an object with `atomicJobAssignment: true, killOnOwnerClose: true, privateDacl: true, …` (zod strict).
- Failure stages `host | artifact | self-test | inspection` with remediation text; `self-test` failures are `retryable` and the cache is
  dropped on next query (`systemWindowsNativeAuthority`, line 188).
- `addon.cc:183-191`: Node-API symbols are **delay-imported from "node.exe"** and a `__pfnDliNotifyHook2` hook resolves them
  against `GetModuleHandleW(NULL)` so Bun or other hosts can load it. This kind of portability trick is why addon packaging is costly.

### 2.2 Single entry point (VERIFIED, `addon.cc:141-165`)

`call(operation, args[])` dispatches `"inspect"`, `"process_*"` → `processCall`, everything else → `filesystemCall`.
Resources are `napi_wrap`ped objects tagged with a fixed `napi_type_tag` (`0x45fcbf0b49e84fe3, 0x9e3e5074130de843`).
A forged object fails with `ERROR_INVALID_HANDLE` ("Native handle does not belong to REA"). Errors carry
`code` (`ENOENT|EACCES|ERR_REA_WINDOWS_NATIVE`), `constraint`, `requestedPath`, `win32Code`, `win32Message`, and optional
`cleanup*` fields. An env cleanup hook (`napi_add_env_cleanup_hook`) closes a pending runtime at environment teardown.

### 2.3 `process_spawn` (VERIFIED, `process.cc:91-214`)

Signature from JS: `call("process_spawn", [command, commandLine, cwd, envEntries[], protocolStdin?, memoryLimitBytes?])`.
Steps:
1. Requires an **absolute drive path** executable (`X:\`). `/` is translated to `\` only for drive-absolute paths (`authority.hpp: ordinaryDriveSeparators`).
2. `createJob(memoryLimit)`: `CreateJobObjectW(nullptr, nullptr)` (unnamed and **non-inheritable**). The flags are
   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` plus optionally `JOB_OBJECT_LIMIT_JOB_MEMORY`. REA **reads the policy back** and requires exact equality, which proves no
   `BREAKAWAY_OK`/`SILENT_BREAKAWAY_OK` (lines 24–41).
3. If there is a memory limit, an I/O completion port is associated **before** any process joins, so `JOB_OBJECT_MSG_JOB_MEMORY_LIMIT`
   cannot be missed (lines 45–54). The limit must be a positive safe integer that is page-aligned.
4. Pipes: `CreatePipe` with inheritable SA, then the parent's end is made non-inheritable (`SetHandleInformation(..., HANDLE_FLAG_INHERIT, 0)`).
   stdin is `NUL` unless `protocolStdin`.
5. `STARTUPINFOEXW` with **two attributes**: `PROC_THREAD_ATTRIBUTE_JOB_LIST` (atomic job membership at creation, Win10 1607+)
   and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (only the 3 std handles are inherited, which prevents handle leaks into the target).
6. Environment: entries are sorted with `CompareStringOrdinal(..., TRUE)` (ordinal, case-insensitive), deduplicated **last
   wins**, and passed as a `CREATE_UNICODE_ENVIRONMENT` block.
7. `CreateProcessW(exe, line, …, TRUE, CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, …)`.
8. While suspended, it normalizes the child token's **default owner** to the user SID (`SetTokenInformation(TokenOwner)`), because elevated
   tokens default file owner to Administrators. It copies the caller's **CPU affinity** (only if both share one processor group)
   and **priority class**.
9. `IsProcessInJob(child, job)` must be TRUE, otherwise `TerminateJobObject` and fail. Then `ResumeThread`.
10. Returns `{pid, jobAssigned: true, killOnOwnerClose: true, jobMemoryLimitBytes?, handle}`.

### 2.4 Observation and termination (VERIFIED, `process.cc:216-470`)

- `process_poll(handle)` returns `{stdout: Buffer, stderr: Buffer, stdoutEnded, stderrEnded, exitCode|null, activeProcesses, memoryLimitReached?, peakJobMemoryBytes?}`.
  Reads are non-blocking through `PeekNamedPipe` + `ReadFile` in 64 KiB chunks, capped at **1 MiB per poll per stream**
  (`kMaximumReadPerPoll`, line 217). `ERROR_BROKEN_PIPE` means EOF. `activeProcesses` comes from `JobObjectBasicAccountingInformation`.
  Exit comes from `WaitForSingleObject(process, 0)`.
- `process_alive` returns `ActiveProcesses`. `process_terminate` calls `TerminateJobObject(job, 1)` if active > 0.
- `process_close` closes job → process → pipes → port. The source comment says "Closing the job is the crash-safe authority; no PID enumeration is used".
  A failed `CloseHandle` leaves the handle "close-blocked" for a later retry, and a handle no longer in the table is dropped (`handle_close.hpp`).
- `process_stdin_write` runs blocking `WriteFile` on a Node async worker, so a child that stops reading cannot block the JS thread.
- `process_caller_token` reports elevation, admin membership, integrity level, whether the default owner is the user, and `inJob`.
- `inspect` creates a probe runtime directory, closes it, creates a job + `JOB_LIST` attribute + memory-limited job + port, and reports capabilities.

### 2.5 TypeScript wrapper (VERIFIED, `src/windows/WindowsOwnedProcess.ts`)

- Builds the command line with `quoteWindowsProcessArgument` (line 49). It **always** quotes, doubles backslashes before `"`
  and trailing backslashes, and rejects NUL. The exe token gets `/`→`\`. `verbatim` passes pre-quoted cmd.exe lines.
- Poll scheduling: `#schedule(delay = 25)` (line 294). It re-polls immediately (0 ms) when output was non-empty and **stops native
  reads while a consumer stream is backpressured**, with a 1 s wake timer. `outputIncomplete` is set if a backpressured
  stream was destroyed during cleanup.
- `'exit'` fires when the root exits. `'close'` fires only when root exited **and** both pipes ended **and** `activeProcesses === 0`,
  so the whole job settled. Then `process_close` runs.
- `kill(signal)` ignores the signal and terminates the **job**: "never a PID supplied by another caller" (line 213).
- `cleanup()`: kill → wait for settle up to **5 s** (line 273) → `{cleaned, signaled}` or `{cleaned:false, reason}`.
  A failed `process_close` leaves `#releasePending` so retry does only the close.
- `unref()/ref()` so an unsettled job does not keep the host alive.

### 2.6 Filesystem half (summary only, VERIFIED from README + `WindowsPrivateRuntime.ts`)

Path admission opens every component with `FILE_FLAG_OPEN_REPARSE_POINT` and rejects reparse points. Identity is
volume serial + 128-bit file ID + final path. Private runtime dirs are created relative to parent handles with `NtCreateFile` and a protected DACL
(current user + SYSTEM only). Immutable snapshots stream 64 KiB at a time on a worker with cancellation. Recursive cleanup goes by handle.
Retries happen only for sharing/lock codes 32/33, up to 10 × 100 ms (`WindowsPrivateRuntime.ts:55-56`). This exists because REA hands
bearer-token descriptors and analysis copies to Ghidra or Java bridges. **BEA does not need this** unless it also hands secrets to helper
processes. A `fs.mkdtemp` under the BEA state dir is enough for dumps, traces, and coverage files.

### 2.7 What REA's Windows addon does *not* do

- It runs **no PID-based tree enumeration** and never calls `OpenProcess` on arbitrary PIDs.
- It has **no attach-to-existing-process ownership**. REA never adopts a foreign PID into a job.
- It sends **no graceful termination signal**. Windows has no SIGTERM, and `kill()` is always a hard `TerminateJobObject`.
- REA **does not** use the addon for Frida targets. Frida spawn and attach go straight through the `frida` binding (§5).

---

## 3. REA's POSIX ownership model (why it is so big)

All VERIFIED unless marked.

- **Spawn** (`ProviderProcess.ts:242-325`): it sets the env `REA_PROCESS_RUN_ID=<runId>` (line 263) and calls `spawn(cmd, args, {shell:false,
  windowsHide:true, stdio:[stdin??"ignore","pipe","pipe"], detached: platform !== "win32"})` (line 298). With `detached`, libuv
  calls `setsid()`, so the child leads a new session and process group (pgid = pid). Ownership record:
  `{runId, leaderPid, processGroupId: pid, expectedParentPid: process.pid, expectedCommand, evidenceOwner, captureBaseline?}`.
- **Identity beyond PID:**
  - On Linux, `identity: "linux-starttime:<field 22 of /proc/<pid>/stat>"` (`ProcessOwnershipObservation.ts:992`) is read together with
    ppid/pgid and lifecycle state (zombie/dead/exiting). The run token comes from `/proc/<pid>/environ` (line 1182).
  - On macOS, a Swift helper is compiled at first use (`DarwinProcessRunTokenReader.ts`, `swiftc`/`xcrun swiftc`, timeout
    `REA_SWIFTC_COMPILE_TIMEOUT_MS`). It reads `KERN_PROC_ALL` and `KERN_PROCARGS2`, and macOS hides env for platform binaries
    and foreign UIDs, which leads to an "unverified" category.
  - Facts are **bracketed**: identity → token → identity. The token counts only if both identity reads match (`readProcessOwnershipFacts`),
    which defeats PID reuse between reads.
- **Process table** comes from `ps -axo pid=,ppid=,pgid=,uid=,stat=,command=` (line 936). It returns `[]` on win32.
- **Cleanup** (`cleanupOwnedProcessGroup`, `ProcessOwnership.ts:337-470`):
  1. Read the table.
  2. Plan: token-validate every member of the owned pgid, sampled pgids, and launcher descendants. Any unreadable or mismatched member
     makes the whole cleanup fail closed (`run-token-mismatch`, `environment-unreadable`, `process-identity-unavailable`).
  3. For each group, revalidate, then `process.kill(-pgid, "SIGKILL")` (`ProcessOwnershipObservation.ts:1243`). ESRCH is fine.
  4. Groups that reappear are revalidated at most `OWNED_GROUP_REVALIDATION_LIMIT = 2` times (line 334).
  5. With `sweepTokenOwnedProcesses`, poll for **any live process still carrying the token** for up to
     `PROCESS_CLEANUP_VERIFICATION_GRACE_MS = 1000` at 25 ms intervals (`ProcessLifecycle.ts`). This catches descendants that
     escaped via `setsid` but kept the env.
  - Token reads retry 3×40 ms (`ProcessOwnership.ts:1408-1409`). Exit-refresh confirmation is capped at 8 tables.
- **Why it is complex:** POSIX has no kernel container that a non-root process can create cheaply (cgroups need delegation),
  and `kill(-pgid)` misses `setsid`/`setpgid` escapees. REA compensates with heuristic token sweeps plus identity
  bracketing, and spends hundreds of lines on "unverifiable" edge cases.
- **Debugger inferiors** (`ownedDebuggerSession.ts`) record `{pid, startTime}` on Linux and only confirm "every identified inferior
  ended" (`verifyOwnedInferiorsEnded`). Detach has a 1 s timeout and late debugger output is capped at 64 KiB.
- **Resource limits** (`LinuxResourceLimits.ts`): `prlimit --as=N:N --fsize=N:N --cpu=N:N --core=0:0 -- cmd`, with defaults
  `BOUNDED_PRODUCER_LIMITS = {input 32 MiB, output 4 MiB, command_timeout 30 s, AS 1 GiB, fsize 64 MiB, cpu 30 s}`.
  Configured limits are clamped to never exceed the inherited soft/hard limits read from `/proc/self/limits`.

---

## 4. REA supervision, bounded output, deadlines, shutdown

### 4.1 `ProviderProcessSupervisor` (VERIFIED, `ProviderProcess.ts:332+`)

- Constants (lines 24–27): `DEFAULT_TERMINATION_GRACE_MS = 250`, `DEFAULT_KILL_GRACE_MS = 1000`, `OUTPUT_CLOSE_GRACE_MS = 1000`,
  `MAX_LATE_OUTPUT_BYTES = 64 KiB`.
- Capture keeps an **aggregate** byte budget across stdout+stderr (`maxDiagnosticBytes`). It **always drains** everything,
  counts `observedBytes` separately from retained `bytes`, sets `diagnosticTruncated`, and flags `invalidUtf8` by trying a fatal
  `TextDecoder`. Checkpoints (`checkpointOutput`/`snapshotOutputSince`) slice output per request on a long-lived process.
  An optional `outputToken` scanner finds a marker anywhere, even beyond the retention budget.
- `stop()` is shared and retryable. With an ownership `cleanup()` it runs cleanup and waits for exit (1 s), with a second cleanup if needed.
  Without one it sends SIGTERM, waits 250 ms, sends SIGKILL, and waits 1 s. Statuses: `not-owned | already-exited | verified-cleanup | terminated |
  killed | incomplete{reason}`. After stop it waits ≤ 1 s for output close; otherwise `outputIncomplete` (inherited pipes held
  by escaped descendants are the usual cause).
- `exit` and `close` are recorded separately. Exit is lifetime and close is complete output.

### 4.2 `runOwnedCommand` (VERIFIED, `OwnedCommand.ts:159-446`)

`runOwnedCommand(spawnOptions, {timeoutMs, diagnosticBytes, acceptNonZeroExit?, stdout?: Writable, observeCompleted?}, {signal, retainCleanup?})`:
- `ProviderStartupDeadline(timeoutMs, callerSignal)` gives one **absolute monotonic deadline** (`performance.now()`), exposed as an
  AbortSignal that also follows the caller's signal. `interruption` is `"cancelled" | "timeout"` so the two are never conflated.
  The timer is re-armed if it fires early (`ProviderDeadline.ts:144-157`).
- Loop: `waitForOutputClose(10)`, then check interruption, output-limit overflow, and stream errors. Each failure type becomes a
  typed `OwnedCommandFailure(reason: "cancelled"|"timeout"|"output-limit"|"process", snapshot, cleanupFailure, …)`.
- **Exceeding the output budget is a failure** ("complete-output budget"), not silent truncation. That is a design choice:
  REA wants complete evidence or an explicit failure.
- After any outcome it calls `supervisor.stop()`. An incomplete stop is either handed to `retainCleanup` (the caller keeps the
  owner for later retry) or thrown with `resources: [runId, cwd, "pid:N", "process-group:N"]`. The resource labels
  explicitly "do not authorize signaling".

### 4.3 `execFileBytes`/`execFileBoundedOutput` (VERIFIED)

- `ExecFileOutput.ts`: with `stopSignal`, abort or timeout sends that signal and escalates to SIGKILL after `STOP_GRACE_MS = 5000`
  (line 24). **The promise settles only after the stdio pipes close**, because the source comment says "destroying the readers is not process-family
  completion". The timeout error has `code: "ETIMEDOUT", killed: true`.
- `ExecFileBoundedOutput.ts` is a simple head+tail retention: `head = ceil(limit/2)`, `tail = rest`. Output becomes
  `head … [output omitted] … tail`, and `outputTruncated` is set when `total > limit`. **A good minimal pattern for BEA.**

### 4.4 Server shutdown (VERIFIED, `src/main/processShutdown.ts`, `src/main/shutdown.ts`)

- Triggers: `SIGINT`, `SIGTERM`, **stdin `end`/`close`** (stdio MCP transport; the client closing stdin is the normal stop).
  The HTTP transport uses signals only. Exit statuses are 130 for SIGINT and 143 for SIGTERM.
- `latchSignalShutdown`: a signal during startup is recorded, and a **second** signal exits immediately.
- `createShutdown`: idempotent. It runs `handle.prepareShutdown()` (drains HTTP handlers), then `Promise.allSettled` over cleanup
  owners (transport, Android, optional providers, session). Failed owners stay registered for retry and the failure goes to stderr with exit 1.
- **Important for BEA on Windows:** when an MCP client kills the server it is usually `TerminateProcess`, and no JS runs.
  REA survives this only because the kernel closes the addon's job handle. Any BEA design whose cleanup lives in JS
  handlers will leak targets on Windows (lab §7, test H).

### 4.5 Windows-specific odds and ends (VERIFIED)

- **Batch files:** `WindowsBatchCommand.ts` runs `cmd.exe` from `COMSPEC`, which must be absolute and named `cmd.exe`, as
  `["/d","/e:on","/v:off","/s","/c", "\"tok1\" \"tok2\"…"]` (line 79). It **rejects** tokens with `"%^!&|<>`, CR/LF, NUL, or empty, rather than escaping
  them. `/d` disables AutoRun. Node rejects `.bat/.cmd` without a shell since CVE-2024-27980.
- **Console windows:** every REA Windows child gets `CREATE_NO_WINDOW`. Node spawns use `windowsHide: true`.
- **Paths:** drive-absolute only for the native launcher. UNC, device, and `\\?\` namespaces are refused by admission. SUBST and mounted folders
  are out of scope.
- **Env:** `snapshotEnvironment` is applied, and native ordinal sort + dedup is used because the Windows env block is expected sorted and names are case-insensitive.
- **Empty `USERPROFILE`** is deleted in `scripts/rea.mjs:32-34` (Windows home lookup throws).
- **Fallback taskkill** (`ProcessOwnership.ts:266-301`): `taskkill.exe /pid N /t /f`, `windowsHide`, 5 s timeout. Exit 128 or
  ESRCH maps to `"missing"`. Used by `browser/ElectronProcessCleanup.ts:63-69` ("/t already includes descendants. Do not
  signal cached child PIDs again … they may have exited or been reused") and by the `ghidra/GhidraLauncher.ts:664-671` fallback when
  no `cleanup` capability exists.
- **PTY capture on Windows is refused** (`capture/ProcessCaptureCapability.ts:13-18`): "this adapter does not yet verify descendant
  cleanup".

---

## 5. REA + Frida lifecycle (relevant to BEA's core)

VERIFIED from `src/frida/FridaInstrumentationManager.ts`:
- spawn: `pid = await device.spawn(program, {argv: [program, ...argv]})` (line 306), then `device.attach(pid)` (line 315).
- attach: `device.attach(pid)` on a caller-supplied PID.
- `session.detached` is connected, then `session.isDetached()` is re-checked to avoid losing an early detach (lines 337–343).
- `#closeSession` (lines 702–780): it unloads scripts, `session.detach()`, and then, **for spawned targets, `device.resume(pid)`**
  if the target was never resumed. **It never calls `device.kill`.** No `kill` appears anywhere in `src/frida` (grep).
  `frida-bindings.d.ts` does not even declare `kill`.
- Startup-failure cleanup (`#cleanupStartup`, lines 829–857) also detaches and **resumes** the spawned PID.
- Consequence (lab F3, VERIFIED): REA-spawned Frida targets **outlive** the session and outlive a crashed or killed REA server.
  This is acceptable for REA's "generic script session" scope, but violates BEA requirement (c).

---

## 6. What BEA should and should not copy from REA

Copy:
- **Kernel-enforced containment** (Job Object, no breakaway, KILL_ON_JOB_CLOSE, assignment while suspended, membership check).
- **Kill = terminate the container, never a PID.** Attach-mode PIDs never enter a container.
- **Separate exit and close** events. `close` means the tree settled and all output was drained.
- **Bounded capture that always drains**, with `observedBytes` vs `retainedBytes` and an explicit `truncated`. A head+tail form suits
  crash logs.
- **One absolute monotonic deadline** composed with caller cancellation, with `timeout` vs `cancelled` distinguished.
- **Typed failure reasons** and **retained cleanup owners** when cleanup is incomplete. Never claim cleanup that did not happen.
- Shutdown on SIGINT/SIGTERM/stdin-end, idempotent, retryable.
- Windows argv quoting rules (`quoteWindowsProcessArgument`), batch-file refusal, `CREATE_NO_WINDOW` for console targets.
- Capability self-test reported in `doctor`: prove at startup that a job can be created and assigned.

Do not copy:
- Node-API addon packaging (manifest/version/SHA/PE checks, delay-load hooks, Linux MinGW cross-build lane). A standalone exe gives
  the same kernel guarantee with zero ABI coupling.
- POSIX run-token sweeps, identity bracketing, the Darwin Swift helper, and revalidation passes. Use subreaper + pgid (Linux)
  or honest best-effort (macOS) instead.
- The private-runtime DACL filesystem layer, unless BEA starts handing secrets to child processes.
- Affinity/priority/token-owner preservation. Nice touches, but not needed for BEA's v1.
- Frida "resume on close" semantics for spawned targets. BEA should **kill** spawned targets on session close unless
  `keepAlive: true` was requested.

---

## 7. Lab experiments (VERIFIED on this host: Win11 26200, Node 24.18.0, gcc 16.1 MinGW-w64 msvcrt)

Build: `gcc -O2 -o sleeper.exe sleeper.c`; `gcc -O2 -D_WIN32_WINNT=0x0A00 -municode -o jobhost.exe jobhost.c`
(MinGW **needs `_WIN32_WINNT=0x0A00`** or `PROC_THREAD_ATTRIBUTE_JOB_LIST` is undeclared).

`sleeper.exe <depth> <ms> [orphan] [breakaway] [detached] [crash]` builds a chain of itself and logs `<pid> <depth>` to `%SLEEPER_LOG%`.
- `orphan` = non-leaf processes exit right after spawning.
- `breakaway` = `CREATE_BREAKAWAY_FROM_JOB`, retried without it on `ERROR_ACCESS_DENIED`.
- `detached` = `DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP`.

`jobhost.exe run [--keep-tree] [--suspended] -- <exe> args…` | `jobhost.exe adopt <pid>`:
- Job: unnamed, `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION`, completion port, `PROC_THREAD_ATTRIBUTE_JOB_LIST` + `HANDLE_LIST`, `CREATE_SUSPENDED`.
- `IsProcessInJob` check, then `ResumeThread` (or wait for the `resume` command).
- Control on stdin: `kill`, `resume`. EOF means kill.
- Status NDJSON on **fd 3** (CRT `lpReserved2`, passed by Node's `stdio[3]`).
- Target stdin is NUL, and target stdout/stderr are the helper's own stdout/stderr (pipes to Node).

| # | Experiment | Result |
|---|---|---|
| A | Node parent `spawn(sleeper 2)` (non-detached), parent `process.exit(0)` | child **dead**, grandchild + great-grandchild **ALIVE**. libuv's global job kills only direct children (BELIEVED cause: libuv job has `SILENT_BREAKAWAY_OK`). |
| B | Same with `detached: true` | all three **ALIVE** |
| C | Node parent → `jobhost run -- sleeper 2` → parent exits | all three **dead** |
| D | Same with `orphan breakaway detached` + `--keep-tree` | all three **dead**. Breakaway attempt got `CreateProcess failed 5` (ACCESS_DENIED), as intended. |
| E | `taskkill /PID root /T /F`, intact tree | all dead in **~97 ms**. Output also listed a 4th process (likely `conhost.exe`). |
| F | `taskkill /T /F` after the root exited (orphan chain) | **exit 128 `The process "<pid>" not found`**, great-grandchild **ALIVE** (leak) |
| G1 | jobhost, control `kill\n` | helper exit 0 in ~105 ms, all dead, events `root-exit{activeAfterRoot:2}` → `settled{active:0}` |
| G2 | jobhost, `child.kill()` on the **helper** (TerminateProcess) | all dead in ~108 ms (KILL_ON_JOB_CLOSE) |
| G3 | jobhost, `stdin.end()` | exit 3050 (`0xBEA` from `TerminateJobObject`), `killed{activeBefore:4}`. 4 = 3 sleepers + 1 more (likely conhost). All dead. |
| G4 | jobhost normal run, root exits with orphans | exit = root code 0, stragglers terminated (default policy) |
| G5 | argv round-trip through helper (`"a b"`, `q"uote`, `back\slash\`, `""`, `trail\\"x`, `ünï`) into `node -e` | **exact match** |
| H | outer driver `TerminateProcess`es a *parent node* that owns a jobhost tree | all tree members **dead** (libuv job kills helper → helper's job closes) |
| I | `sleeper crash` (null write) under jobhost | helper exit `0xC0000005` in ~248 ms. No WER hang (`DIE_ON_UNHANDLED_EXCEPTION`). |
| F1 | Frida `device.spawn(sleeper 2 detached)` → `jobhost adopt <pid>` → `device.resume` → kill helper | adopt reported `wasInJob:0`. **All 3 dead.** |
| F2 | Frida-spawned `sleeper 1`, `device.kill(rootPid)` | root dead, **child ALIVE** (single-process kill) |
| F3 | node frida-spawns `sleeper 0` + resume, then node exits | target **ALIVE** after node exit |
| S | `jobhost run --suspended -- node -e …` → Frida `device.attach(pid)` + script while suspended → `resume` | attach + script load in 183 ms (`"34 modules at attach"`), target ran, exit 7 reported by helper, stdout passed through |
| P | Frida `device.spawn(node, {stdio:"pipe"})` → adopt → resume | stdout/stderr via `device.output` `(pid, fd, data)` (empty data = EOF). Exit code 9 from helper. |
| Q | Frida `device.spawn` with **default stdio** inside a Node child whose stdout is a pipe | nothing leaked into host Node's stdout. Still: always use `stdio:"pipe"`. |
| Z | PowerShell `Get-CimInstance Win32_Process` / `tasklist /FO CSV` cost | 371 ms / 441 ms per call |

Bug found while building the helper (VERIFIED): a helper thread blocked in CRT `fgets(stdin)` **holds the stdin FILE lock**.
When `main` returns, CRT `exit()` deadlocks flushing stdin, so the helper printed `settled` but never exited (and once reported an
odd exit code). Fix: read control with raw `ReadFile(GetStdHandle(STD_INPUT_HANDLE))` and leave with `fflush(NULL); ExitProcess(code)`.

All lab processes were reaped. The final `tasklist` checks for `sleeper.exe` and `jobhost.exe` and the test PIDs found nothing.

---

## 8. Windows options for BEA, evaluated

Requirements: (a) run with args/env/cwd/timeout and bounded stdout/stderr/exit code; (b) kill owned trees reliably;
(c) targets do not outlive the server unless `keepAlive`; (d) never kill attached processes.

| Option | (a) | (b) tree kill | (c) crash-safe | (d) | Cost / risks |
|---|---|---|---|---|---|
| Plain Node `spawn` + `child.kill()` | yes | **no**: kills root only | **partial**: root dies via libuv job, descendants leak (A) | yes | zero code |
| Node `spawn` + `taskkill /T /F` | yes | **partial**: misses orphans, fails when root already exited (F) | **no**: needs JS to run | yes if PID kept | ~100 ms + process spawn per kill. A reused PID as tree root could hit unrelated processes. |
| PowerShell / CIM tree walk + `Stop-Process` | yes | partial (same ppid problem) | no | yes | 370+ ms per enumeration, execution-policy and profile issues |
| Frida `device.spawn/kill` | yes (`stdio:"pipe"`, but **no exit code**) | **no**: single PID (F2) | **no**: target survives host death (F3) | yes | no extra code |
| FFI (e.g. `koffi`) calling `CreateJobObjectW`/`AssignProcessToJobObject` in-process | yes | yes if assigned before any child is created. With Node `spawn` the child is already running, so there is a race. | **yes** (job handle closes with node) | yes | Another prebuilt native dependency (BELIEVED to work, not tested). Node `spawn` can't create suspended, so a full `CreateProcessW` + pipe plumbing in JS would be needed. |
| Custom Node-API addon (REA's way) | yes | yes | yes | yes | ABI, packaging, and build-lane overhead (REA: manifest, SHA, PE checks, MinGW cross lane, delay-load hooks) |
| **Standalone helper exe owning a Job Object (recommended)** | yes (pipes pass through, exit code via status channel) | **yes**: TerminateJobObject (G1–G3) | **yes**: libuv job kills helper, kernel kills tree (C, D, H) | **yes**: attach never touches a job | ~200 lines of C, ~100 KB exe. One extra process per target. Works with any Node or Bun version. |
| Same helper in Rust | same | same | same | same | Rust std doesn't parse `lpReserved2` (BELIEVED), so fd 3 would need a manual parse or a named pipe. Larger binary (~150–300 KB). |

**Recommendation: `bea-jobhost.exe`, one per spawned target, written in C** (or C++), built with MinGW-w64 (`-D_WIN32_WINNT=0x0A00 -municode -O2 -s
-static-libgcc`) or MSVC (`cl /O2 /MT`). Ship it prebuilt in the npm package with a SHA-256 check at load, the cheap part of REA's loader.
- Why not a broker owning many jobs: a per-target helper makes "kill tree" = "kill helper" and "server died" = "helper died" both kernel-enforced, with no multiplexed protocol to get wrong.
- Why C over Rust: the MSVCRT/UCRT `lpReserved2` makes Node's `stdio[3]` appear as fd 3 for free (VERIFIED for MinGW msvcrt; BELIEVED for UCRT).

### 8.1 Helper contract (proposed)

```
bea-jobhost.exe run   [--suspended] [--keep-tree] [--kill-on-root-exit (default)] [--mem-limit BYTES]
                      [--cwd DIR] [--env-file PATH | env inherited from helper] -- <exe> [args...]
bea-jobhost.exe adopt <pid> [--expect-creation-time <100ns>]      # Frida-spawned, still suspended
bea-jobhost.exe probe                                              # doctor: create job, spawn+assign a trivial child, report

stdin  (fd 0) : control, newline-delimited: "resume" | "kill" ; EOF => kill tree, exit
stdout (fd 1) : passed to target as its stdout (Node reads it directly)
stderr (fd 2) : passed to target as its stderr
status (fd 3) : NDJSON events from helper:
  {"event":"hello","helperPid":N,"helperInJob":0|1,"version":"x","protocol":1}
  {"event":"started","pid":N,"creationTime100ns":T,"suspended":bool,"jobAssigned":true,"breakaway":false,"killOnClose":true}
  {"event":"adopted","pid":N,"creationTime100ns":T,"wasInJob":bool}
  {"event":"resumed","previousSuspendCount":1}
  {"event":"root-exit","code":C,"activeAfterRoot":K}
  {"event":"killed","activeBefore":K,"rootCode":C}
  {"event":"memory-limit"}                         # JOB_OBJECT_MSG_JOB_MEMORY_LIMIT
  {"event":"settled","active":0,"peakJobMemory":B}
  {"event":"error","stage":"open|assign|create|membership|job-policy","win32":E}
exit code     : root's exit code (NTSTATUS for crashes), or 0xBEA when BEA terminated the job
```

Implementation rules, learned the hard way (VERIFIED where noted):
- Use `CreateJobObjectW(NULL, NULL)`. The job must be **unnamed** so no other process can open it, and its handle **non-inheritable** so the target doesn't hold its own job open.
- Flags: `KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION`, **no** `BREAKAWAY_OK`/`SILENT_BREAKAWAY_OK`. Read the policy back as REA does.
- Use `PROC_THREAD_ATTRIBUTE_JOB_LIST` + `CREATE_SUSPENDED`, then the `IsProcessInJob` check, then resume. Fallback for old Windows: `AssignProcessToJobObject` while suspended.
- `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` must list only the 3 std handles. Make sure they are inheritable first (`SetHandleInformation`).
- Create the completion port **before** assignment so no messages are missed.
- Read control through **raw `ReadFile`**, never CRT stdio in a thread. Exit via `ExitProcess` (deadlock VERIFIED above).
- Pass `CREATE_NO_WINDOW` for console targets. GUI targets ignore it (BELIEVED). Use a fresh `STARTUPINFO` without `STARTF_USESHOWWINDOW`
  so a helper started with `windowsHide` doesn't hide a GUI target's window (BELIEVED).
- Use CRT argv quoting for building the target command line (G5 VERIFIED). Refuse `.bat/.cmd` targets, or route them through REA's
  `cmd.exe /d /e:on /v:off /s /c` with metacharacter rejection.
- Adopt mode opens with `PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`. Verify
  `GetProcessTimes` creation time equals what BEA recorded at spawn (PID-reuse guard). Assign, then report `wasInJob`.
  Since Windows 8, nested jobs mean a process already in a job can still be assigned (BELIEVED; F1 had `wasInJob:0` anyway).
- Settlement means `ActiveProcesses == 0`. The count includes `conhost.exe` instances for console targets (observed extra members in G1/G3/I).
  After `TerminateJobObject`, poll up to ~1 s.

### 8.2 Node side (TypeScript sketch)

```ts
// bea/src/process/OwnedTarget.ts (sketch)
export type Containment = "win32-job" | "linux-subreaper" | "posix-pgid" | "none";
export interface OwnedTargetOptions {
  exe: string; args: readonly string[]; cwd?: string; env?: Record<string, string>;
  timeoutMs: number; maxOutputBytes: number;    // aggregate, head+tail retained
  suspended?: boolean;                          // for Frida attach-before-resume
  keepAlive?: boolean;                          // survive server shutdown (explicit opt-in only)
  signal?: AbortSignal;
}
export interface OwnedTargetResult {
  pid: number; creationTime100ns: string; containment: Containment;
  exit: { code: number | null; kind: "normal" | "ntstatus" | "bea-kill" | "unknown"; codeHex?: string };
  ended: "exited" | "timeout" | "cancelled" | "killed";
  stdout: { text: string; retainedBytes: number; observedBytes: number; truncated: boolean; invalidUtf8?: true };
  stderr: { /* same */ };
  tree: { activeAfterRoot: number; settled: boolean };
  limitations: string[];                         // e.g. "brokered launches (COM/WMI/Steam) are outside the job"
}

const child = spawn(JOBHOST, ["run", ...(o.suspended ? ["--suspended"] : []), "--", o.exe, ...o.args], {
  stdio: ["pipe", "pipe", "pipe", "pipe"],      // control, target stdout, target stderr, status
  cwd: o.cwd, env: o.env, windowsHide: true,    // NOT detached: helper stays in libuv's kill-on-close job
});
```

- Timeout and cancel: write `"kill\n"` to `child.stdin`. If there is no `settled` within 2 s, `child.kill()` (TerminateProcess on the
  helper), which also kills the tree through the kernel (G2).
- Completion: wait for the helper's `exit` **and** `close` on stdout/stderr. The helper holds its copies of the pipe handles until it exits,
  and it exits only after the job settled, so `close` means complete output from the whole tree.
- Bounded capture: reuse REA's head+tail pattern (`ExecFileBoundedOutput.ts`) but always drain. Report `observedBytes`.
  Unlike REA's `runOwnedCommand`, **don't fail** on overflow. Dynamic-analysis targets are chatty; truncation is evidence.
- Server shutdown: on SIGINT/SIGTERM/stdin-end, end every helper's stdin (EOF kills). A hard server death is covered by the kernel
  (H). `keepAlive` targets need two changes. First, spawn the helper with `detached: true` so it is outside libuv's job. Second,
  pass `--ignore-eof`, because the control pipe reaches EOF when the server dies and that would otherwise kill the tree. BEA must
  also persist `{helperPid, targetPid, creationTime}` to its state dir so a later server can re-adopt or kill it. Keep this opt-in and rare.
- Attach mode: **never** route through jobhost. Record `{pid, creationTime, imagePath}` observed via Frida
  (`device.getProcessByPid`) and Win32 `GetProcessTimes` (through a tiny `jobhost observe <pid>` mode, or skip it). BEA's kill tool
  must refuse attached sessions (`ownership: "attached" → kill not permitted; use detach`).

### 8.3 Frida integration on Windows (two verified paths)

- **Path 1 (preferred for instrumentation from first instruction):** `pid = device.spawn(exe, {argv, env, cwd, stdio:"pipe"})`
  (suspended), then `jobhost adopt <pid>`, wait for `adopted`, `device.attach(pid)`, load scripts, `device.resume(pid)`. Output comes
  via `device.output`, and the exit code via jobhost `root-exit` (F1, P). The target is fully contained before it executes a single
  instruction of its own.
- **Path 2 (a target that must use BEA's own pipes/env handling):** `jobhost run --suspended`, then `device.attach(pid)` + scripts,
  then `"resume\n"` (S). VERIFIED with node.exe as target. Caveat (BELIEVED): Frida's own spawn path handles early-init
  instrumentation more carefully (it controls the loader breakpoint). Attaching into a raw `CREATE_SUSPENDED` process forces process
  initialization on Frida's injected thread, and some targets (TLS callbacks, anti-debug, .NET) may behave differently. Prefer Path 1.
- Session close for spawned targets: unload scripts, detach, then `kill` via jobhost (not `device.kill`, F2), unless `keepAlive`.

---

## 9. Linux / macOS design

### 9.1 Linux: `bea-reaper` helper (C, same protocol as jobhost) (BELIEVED; not lab-tested here, Windows host)

```c
prctl(PR_SET_CHILD_SUBREAPER, 1);       // orphans in our subtree reparent to us, not init
prctl(PR_SET_PDEATHSIG, SIGKILL);       // + check getppid() != original_ppid after the call (race)
pid_t pid = fork();
if (pid == 0) { setpgid(0, 0); /* optional: prlimit, raise(SIGSTOP) for --suspended */ execvp(exe, argv); _exit(127); }
// parent: poll(stdin, signalfd(SIGCHLD)); reap with waitpid(-1, &st, WNOHANG) in a loop
// kill: kill(-pid, SIGKILL); then repeatedly: for each /proc/<p>/stat with ppid == getpid() -> kill(p, SIGKILL)
//       (subreaper guarantees every live descendant is either in our pgid tree or reparented to us)
// settled: waitpid(-1) returns ECHILD  => subtree is provably empty
```

- Gives tree containment equivalent to a Job Object for everything forked under it, including `setsid` and double-fork
  daemons. The only escapes are processes created by *other* services (systemd user units, D-Bus activation).
- `PR_SET_PDEATHSIG` fires when the parent **thread** that forked exits (BELIEVED). libuv forks from the event-loop thread, so this is fine.
  The stdin-EOF lifeline is a second, portable guard.
- Use pidfds (`pidfd_open`, Linux ≥ 5.3) inside the helper for race-free signaling of the root if desired.
- An optional stronger mode is cgroup v2 via `systemd-run --user --scope -p …` + `cgroup.kill` (kernel ≥ 5.14). It needs systemd and
  delegation, so offer it as an option, not the default.
- Frida on Linux: a `device.spawn` target is **not** a child of the reaper, and a process can't be moved into another session's pgid.
  Options: (i) let the reaper fork + `raise(SIGSTOP)`-before-exec and have Frida attach after exec (needs testing); (ii) Frida spawn +
  record `{pid, starttime}` + at teardown `device.kill` + kill descendants found by a `/proc` ppid walk with starttime checks
  (best-effort, report `containment: "none"` + `limitations`). **Open question.**

### 9.2 macOS (BELIEVED)

- There is no subreaper, Job Object, or cgroup equivalent. The helper uses `setpgid` and a lifeline (stdin EOF or `kqueue EVFILT_PROC NOTE_EXIT` on the
  parent PID). Kill is `kill(-pgid, SIGKILL)` plus a periodic `proc_listchildpids`/`proc_pidinfo(PROC_PIDTBSDINFO)` sample of
  descendants `{pid, start time}`, killed at teardown after an identity check. Orphans reparent to launchd and are only caught if
  sampled first. Report `containment: "posix-pgid"` with that limitation.
- Do **not** replicate REA's runtime-compiled Swift helper. Ship a prebuilt universal binary, or v1 just uses Node:
  `spawn(..., {detached: true})` + `process.kill(-pid, "SIGKILL")` + shutdown hooks. That is not crash-safe, so say so in evidence.

### 9.3 Pure-Node POSIX fallback (v0)

`spawn(exe, args, {detached: true, stdio: ["ignore","pipe","pipe"]})`, then `process.kill(-child.pid, "SIGKILL")` on timeout,
cancel, or shutdown. It is correct for well-behaved trees. It leaks `setsid` escapees and leaks everything if the server is SIGKILLed.
This is acceptable for an early Linux/macOS milestone **if reported** as `containment: "posix-pgid", crashSafe: false`.

---

## 10. Evidence / provenance fields BEA should attach to every process operation

```jsonc
{
  "process": {
    "ownership": "spawned" | "attached",
    "pid": 1234, "creationTime100ns": "134375926185954180", "image": "C:\\...\\target.exe",
    "containment": { "kind": "win32-job", "breakawayAllowed": false, "killOnClose": true,
                     "assignedBeforeFirstInstruction": true, "helperPid": 5678, "crashSafe": true },
    "launch": { "argv": [...], "cwd": "...", "envDelta": {"KEY": "..."}, "suspended": true, "via": "frida-spawn+adopt" | "jobhost-run" }
  },
  "termination": { "reason": "exited" | "timeout" | "cancelled" | "killed-by-request" | "server-shutdown",
                   "method": "terminate-job", "activeBefore": 4, "settled": true, "elapsedMs": 105 },
  "exit": { "code": 3221225477, "codeHex": "0xC0000005", "kind": "ntstatus", "name": "STATUS_ACCESS_VIOLATION" },
  "output": { "stdout": { "retainedBytes": 65536, "observedBytes": 912344, "truncated": true, "retention": "head+tail" } },
  "limitations": [
    "Processes launched by brokers outside the job (COM LocalServer, WMI Win32_Process.Create, Task Scheduler, Steam client relaunch, UAC elevation via AppInfo) are not contained.",
    "Exit code 0xBEA means BEA terminated the job."
  ]
}
```

Observations (exit code, timing, output) are direct observations. "Tree settled" is an observation of `ActiveProcesses == 0`.
"Assigned before first instruction" is a derivation from the CREATE_SUSPENDED + JOB_LIST sequence. Brokered escapes are a known unknown.

---

## 11. Pitfalls checklist for BEA

1. **Never inherit the MCP server's stdout into a target.** Stdio transport frames JSON-RPC there. Use explicit pipes (helper) or
   Frida `stdio:"pipe"`. Q showed no leak with Frida's default, but don't rely on it.
2. `detached: true` on Windows **escapes** libuv's job (B). Use it only for deliberate `keepAlive`.
3. `taskkill /T` follows *current* parent PIDs. It misses orphans (F) and could pick up an unrelated process reusing a dead root's PID as
   parent (BELIEVED). Don't use it as the primary mechanism.
4. Frida `device.kill` is single-process (F2), and Frida-spawned targets outlive the host (F3).
5. CRT stdio in a helper thread + CRT `exit()` = deadlock (VERIFIED). Use raw handles + `ExitProcess`.
6. MinGW needs `-D_WIN32_WINNT=0x0A00` for `PROC_THREAD_ATTRIBUTE_JOB_LIST`, and `-municode` for `wmain`.
7. `ActiveProcesses` counts `conhost.exe` for console children (observed off-by-one/two). Don't treat it as "number of target processes".
8. Without `DIE_ON_UNHANDLED_EXCEPTION`, a crashing target can sit in a WER dialog until the deadline (BELIEVED). With it, the crash
   is an exit code (I). Frida's `Process.setExceptionHandler` still runs first for crash capture (BELIEVED).
9. Launchers: Steam/Epic games may re-launch through the client, so the root exits fast and the real game is outside the job. Detect
   "root exited < N s with code 0 and no output", report `ownershipLost`, and suggest attach mode.
10. Elevation: `requireAdministrator` targets fail `CreateProcessW` with `ERROR_ELEVATION_REQUIRED` (740) (BELIEVED). Report it; don't
    ShellExecute `runas` (it would be outside the job).
11. Windows has no graceful SIGTERM. If BEA ever needs "graceful", use `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT)` for console
    targets in a new process group, or `WM_CLOSE` to top-level windows of GUI targets. Default to hard job termination.
12. A PID is not recycled while any handle to the process is open (BELIEVED, Win32 docs). The helper holding the root handle
    pins identity, so record `creationTime` anyway for evidence and for adopt checks.
13. Bun ignores V8 heap flags; REA uses job memory limits for that. BEA can use `--mem-limit` (JOB_MEMORY) for in-process oracle
    calls or fuzz-like loops to stop runaway targets.

---

## 12. Suggested BEA module layout (process layer only)

```
bea/
  native/jobhost/jobhost.c            # ~200 lines, Windows helper (protocol above)
  native/reaper/reaper.c              # Linux helper (later); macOS variant (later)
  native/prebuilt/win32-x64/bea-jobhost.exe + SHA256SUMS
  src/process/HelperLocator.ts        # resolve + SHA-256 check prebuilt helper; dev: build with gcc/cl if missing
  src/process/OwnedTarget.ts          # spawn via helper, status-fd parser, kill/resume, settle, bounded capture
  src/process/BoundedCapture.ts       # head+tail retention, observed vs retained bytes, invalidUtf8 flag
  src/process/Deadline.ts             # AbortSignal.any([caller, timeout]) with reason classification
  src/process/ProcessRegistry.ts      # session-id -> {ownership: spawned|attached, helper, identity}; shutdown()
  src/process/shutdown.ts             # SIGINT/SIGTERM/stdin-end; idempotent; ends helper control pipes
  src/process/ntstatus.ts             # small table for exit-code naming (0xC0000005, 0xC0000409, 0xC00000FD, ...)
```

`doctor` should run `bea-jobhost probe`. Report `job_object_containment: available` only if the probe created a job, spawned a
child with `JOB_LIST`, verified membership, and terminated it. This is REA's "capability proven by self-test, not inferred from OS
name" principle at about 1% of the cost.

---

## 13. Open questions

1. Do BEA targets ever need stdin? The helper currently gives NUL. A 5th Node stdio pipe could be forwarded as target stdin if needed.
2. Default policy on root exit: kill stragglers (current default) vs keep-tree-until-settled (`--keep-tree`)? Launchers argue for keep-tree.
3. `keepAlive` semantics and re-adoption across server restarts (persisted `{helperPid, targetPid, creationTime}`)? Is it worth it in v1?
4. Linux Frida-spawn containment: does Frida attach cleanly to a reaper child stopped with `SIGSTOP` right after `execve`? Needs a Linux lab.
5. Prebuilt helper distribution: ship unsigned exes in the npm tarball (like REA's `.node`), or build on first use when gcc/cl is
   present? Windows Defender/SmartScreen behavior for unsigned helpers was not tested (no MOTW on npm-extracted files; BELIEVED no prompt).
6. Should BEA expose job resource limits (memory/CPU rate/process-count `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`) as tool options for oracle calls?
7. Which extra job members show up for console targets (conhost.exe?), and should evidence list them via `JobObjectBasicProcessIdList`?
