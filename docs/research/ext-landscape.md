# BEA external landscape: MCP servers & agent tooling for dynamic binary analysis (as of 2026-10-28)

Key: `ext-landscape`. Author: research subagent. Method: WebSearch + WebFetch of GitHub READMEs/docs,
directory listings (glama, lobehub, mcpservers), Microsoft/LLVM/Undo docs, arXiv abstracts. Plus a small
read-only grep of the local REA clone for cross-reference.

Confidence legend:
- **VERIFIED-WEB**: I fetched the project's own README/docs page in this session and the claim is from it.
- **DIRECTORY**: from third-party directory listing / search snippet only (glama, lobehub, mcp.so, etc.). Weaker.
- **BELIEVED**: my prior knowledge; not re-checked this session.
- **VERIFIED-LOCAL**: read in the local REA clone.

Star counts are as shown on the fetched page on 2026-10-28 (approximate; GitHub rounds "1.6k").
No repo was cloned or executed; nothing was installed; no processes were spawned.

---

## 0. TL;DR for BEA

1. **The space is crowded but shallow.** There are dozens of Frida/x64dbg/GDB/LLDB/WinDbg/Cheat-Engine MCP servers.
   Almost all are *thin command proxies*: `attach`, `execute_command(raw)`, `read_memory`, `set_breakpoint`,
   `get_messages`. Only a handful are engineered seriously:
   - **glslang/windbg-mcp** (Rust, DbgEng, 78-89 tools) — best-in-class session/async/token-budget engineering.
   - **monkeywave/frida-mobile-mcp** (TS, 71 tools) — best-in-class evidence envelope, safety flags, *explicitly
     aligned with REA's evidence envelope* (has `docs/rea.md`). Mobile-focused (Android/iOS), not desktop.
   - **miscusi-peek/cheatengine-mcp-bridge** (1.7k stars, ~180 tools) — the de-facto Cheat-Engine-over-MCP,
     with real first/next scans, persistent scans, HW data breakpoints, DBVM "find what writes".
   - **mq1n/GhostMCP** (Rust, injected DLL, 250-336 tools) — the most feature-complete Windows in-process
     toolkit (value scanner, pointer scanner, HW BPs, API tracing with ring-buffer backpressure, safety tokens).
   - **svnscha/mcp-windbg** (1.6k stars) and **Microsoft's official WinDbg MCP** (WinDbg 1.2610.1001.0, Oct 2026).
2. **Nobody combines** structured hooks + Stalker coverage export (drcov) + HW watchpoints + CE-style scans +
   static↔runtime rebasing + in-process function calls as oracles + Unicorn differential testing + an
   evidence/provenance model. Each exists in isolation somewhere; the combination does not.
3. **Static↔runtime address mapping is a real, recognized gap**: ida-pro-mcp issue #449 (rebasing tools) was
   closed "not planned" (2026-06-13). Only bethington/ghidra-mcp has `debugger_static_to_dynamic` /
   `debugger_dynamic_to_static` (GUI-only, Ghidra TraceRmi). frida-mobile-mcp standardizes on `module+0x<offset>`.
4. **Coverage export (drcov) via MCP: nobody.** `stalker-coverage` (non-MCP TS module) emits drcov from Frida.
   No DynamoRIO / Intel PIN MCP server found at all.
5. **Emulation-based differential testing: nobody.** Unicorn MCP exists (`mcp-emulate`/MCPEmulate, 41 tools) and
   Ghidra-P-code `emulate_function` exists (bethington), but no one runs "emulate vs. real in-process call, diff".
6. **Evidence/provenance**: only frida-mobile-mcp (evidence_id, coverage, limitations, provenance, effects,
   persisted store) and glslang/windbg-mcp ("results are evidence, not verdicts"; sound vs best-effort verdicts)
   take it seriously. Project Ire (Microsoft) validates claims against a "chain of evidence" — research precedent.
7. **Pitfalls repeatedly reported**: token blowup from raw debugger text (pwndbg-mcp author recommends tmux
   instead!), tool-count limits (Gemini rejects 209 tools; ~90-100 tool client limits), blocking main-thread
   deadlocks (ida-pro-mcp #217), modal dialogs hanging calls (GhidraMCP), Ctrl-C killing targets, async-mode
   surprises (LLDB), `SESSION_LOST` when target crashes, anti-Frida crashes, BSOD risk (CE "query memory region
   routines"), persistent breakpoints confusing the LLM (Undo talk).

---

## 1. Frida-based MCP servers

There is **no official Frida MCP** (no frida.re / oleavr project found). All community.

### 1.1 dnakov/frida-mcp — https://github.com/dnakov/frida-mcp  (VERIFIED-WEB + DIRECTORY)
- ~460 stars, 65 forks, only 5 commits, MIT. Python, official MCP Python SDK. PyPI `frida-mcp`. Frida >=16.
- Tools (13, per mcp.directory guide): `enumerate_devices`, `get_device`, `get_usb_device`, `get_local_device`,
  `enumerate_processes`, `get_process_by_name`, `attach_to_process`, `spawn_process`, `resume_process`,
  `kill_process`, `create_interactive_session`, `execute_in_session`, `get_session_messages`.
  Resources: `frida://version`, `frida://processes`, `frida://devices`.
- Design: REPL-style. Arbitrary JS via `execute_in_session`; hook output queued until `get_session_messages`.
- Issues: #1 "enumerate_processes returns process list from Windows" (device-pinning bug — agent got local list
  when meaning remote), #2 "error create_interactive_session", #6 remote connection. Effectively unmaintained.
- Takeaway: most-starred Frida MCP is the thinnest. Popularity ≠ quality in this space.

### 1.2 nonsleepr/frida-mcp.ts — https://github.com/nonsleepr/frida-mcp.ts  (VERIFIED-WEB)
- 3 stars. TypeScript on Bun; Frida >=17. `npx --yes github:nonsleepr/frida-mcp.ts`.
- Tools: `spawn_process(program,args?,device_id?)` (paused), `resume_process(pid)`, `kill_process(pid)`,
  `create_interactive_session(process_id)`, `execute_in_session(session_id, javascript_code, wait?)`,
  `load_script_file(session_id, script_path, wait?)`, `download_file(file_path, output_path, pid?)`.
- **Messages as resources**: `frida://sessions/{sessionId}/messages` (default 100, consumed on read),
  `.../messages/{limit}` with `last:N` / `all`. `wait` seconds = collect initial output before returning.
- Resource templates: `frida://devices/{id}/processes/by-name/{name}`, `.../processes/{pid}/module` (main module
  base/size).
- Limitations: no close-session tool; consume-on-read messages (can't re-read; bad for provenance).
- Takeaway: "wait N seconds then return what arrived" is a common, simple pattern for hook output. Consume-on-read
  is an anti-pattern for evidence (BEA should use cursors, not destructive reads).

### 1.3 monkeywave/frida-mobile-mcp — https://github.com/monkeywave/frida-mobile-mcp  (VERIFIED-WEB) ★ most relevant
- 15 stars, 56 commits, MIT, 2026. Node >=22.12, frida-node `^17.24.3`. npm + MCPB + MCP registry. CI on Node 22/24
  Linux/macOS/Windows. Mobile (Android/iOS) focus.
- **71 tools, two tiers.**
  - Tier 1 (35, high-level): `get_status`, `frida_help`, `detect_app_technologies`, `explore_app`, `get_app_info`,
    `search_classes_and_methods`, `describe_class`, `discover_crypto`, `find_secrets_in_memory`,
    `generate_memory_pattern`, `monitor_crypto`, `capture_tls`, `bypass_ssl_pinning`, `trace_coverage`,
    `drive_coverage`, `trigger_and_wait`, `mobile_action`, `hook_method`, `trace_method`, `watch_loads`,
    `execute_script`, `validate_script`, `run_prebuilt_script`, `search_recipes`, `save_script`,
    `list_saved_scripts`, `run_saved_script`, `export_script`, `read_memory`, `write_memory`, `scan_memory`,
    `get_messages`, `get_evidence`, `export_evidence_bundle`, `stop_instrumentation`, `unload_script`.
  - Tier 2 (36, primitives): `list_devices`, `select_device`, `get_device_info`, `list_processes`,
    `list_applications`, `get_frontmost_application`, `spawn_process`, `attach_process`, `resume_process`,
    `kill_process`, `list_threads`, `detach_session`, `list_sessions`, `spawn_gating`, `child_gating`,
    `eternalize_script`, `enumerate_modules`, `enumerate_exports`, `enumerate_imports`, `enumerate_symbols`,
    `resolve_address`, `analyze_native_function`, `dump_module_memory`, `hook_function`, `unhook_function`,
    `frida_server_status|install|start|stop`, `adb_shell`, `adb_logcat`, `adb_pull`, `adb_push`, `adb_forward`,
    `inject_library`.
- **Safety flags (all default OFF)**: `FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS` (gates execute_script and custom
  hook bodies → `CUSTOM_SCRIPTS_DISABLED`), `FRIDA_MCP_MEMORY_WRITE` (→ `MEMORY_WRITE_DISABLED`),
  `FRIDA_MCP_ALLOW_NATIVE_INJECTION`, `FRIDA_MCP_ALLOW_ADB_SHELL`; `allowedDevices`; `maxSessions`=4;
  `sessionTimeoutMinutes`=30; rate limits (10 scripts/min, 60 memory reads/min, 5 sessions/min →
  `RATE_LIMIT_EXCEEDED`, retryable); audit log `~/.config/frida-mobile-mcp/audit.jsonl`;
  `dump_module_memory` writes only under cwd/tmp/config dir; HTTP loopback by default, bearer token required
  for non-loopback, Host/Origin validated.
- **Sessions**: `SESSION_LOST` ("script destroyed") on crash/detach; `get_status` lists sessions, hooks, traces,
  *recent detaches and crashes*; re-running a hook tool auto-creates a fresh session. `eternalize_script` =
  fire-and-forget.
- **Events**: buffer `maxMessageBuffer`=1000; `get_messages(since)` paginates; `trigger_and_wait` does an action
  then blocks until hook output or reports none arrived.
- **Output limits**: `FRIDA_MCP_MAX_RESPONSE_CHARS`=25,000 default; `read_memory` ≤4 MB; evidence store caps
  200 MB / 5,000 entries / 2,048 KB per entry, oldest pruned. Responses in **TOON** by default (token-saving),
  `response_format: markdown|json` selectable.
- **Context budget controls** (serialized `tools/list` size, from docs/rea.md): full 247,472 B; `core` profile
  115,881 B (47%); `compact` schemas 83,359 B (34%); core+compact 43,055 B (17%).
  Env: `FRIDA_MCP_TOOL_PROFILE=core`, `FRIDA_MCP_TOOLS_EXCLUDE` (globs), `FRIDA_MCP_SCHEMA_PROFILE=compact`;
  `get_status` reports `hidden_tools`.
- **Evidence envelope (docs/interop.md)** — every response including errors:
  `result`, `evidence_id` (UUID, mirrored in `_meta.evidence_id`), `limitations`, `coverage{status:
  complete|partial|unknown, scope?, next_offset?, truncated?}`, `raw_result`, `session_context`,
  `suggested_next[{call, reason}]`, `_meta.provenance` (target-derived content marked untrusted),
  `_meta.effects` (`executesForeignCode`, `mutatesTarget`, `writesFilesystem`, ...).
  Persisted at `~/.config/frida-mobile-mcp/evidence/YYYY-MM-DD/<evidence_id>.json` + `index.jsonl`, mode 0600.
  Retrieval: `get_evidence`, `export_evidence_bundle` (JSON/MD), resources `frida://evidence`, `frida://evidence/{id}`.
- **Error schema**: `isError:true`, `error{code, category, message, retryable, remediation, recovery_actions,
  context}`, optional `details.partial_observation` (what was seen before failure). Codes UPPER_CASE.
- **Address convention**: `module+0x<offset>` shared across Ghidra/IDA/Frida; also `module!symbol`, ObjC
  `-[Class sel]`, Java `Class.method(sig)`. "Hook by evidence": inputs `{module, offset}`,
  `{module, address, image_base}` (i.e., static address + static image base → rebased), `{class, signature}`.
- **REA interop (docs/rea.md)**: says "REA has no plugin API and no MCP-client mode", so both servers are
  registered side-by-side and the agent routes. Mapping table: REA `structuredContent.normalized_result` vs
  their `structuredContent.result`; REA snake_case codes with `recovery.kind` vs their UPPER codes with
  `category`/`retryable`; `RATE_LIMIT_EXCEEDED` ↔ REA `resource_constraint`. Routing: desktop binaries →
  REA's Frida lane; mobile → them. "Never hold one PID in sessions on both servers." Finding ledger: prefix
  evidence IDs `rea:` / `frida:`.
- Limitations: Android spawn suspended >~10 s gets killed (Frida 17.6+ can't disable); anti-Frida detection
  causes crashes; ControlFlowGraph "inspect" needs Frida 17.12+ with linear-disasm fallback reported in
  `limitations` (nice: degraded mode surfaces as a limitation, not an error).
- **Implication for BEA**: this project already occupies "Frida + REA-style evidence" for *mobile*. BEA should
  (a) target desktop native (Windows first), (b) reuse REA's envelope exactly (not a look-alike), and (c) beat it on
  the things it doesn't do: drcov coverage export, HW watchpoints, CE-style iterative scans with handles, in-process
  call oracles, Unicorn differential tests, static↔runtime rebasing against REA/Ghidra project addresses.

### 1.4 0xhackerfren/frida-game-hacking-mcp — https://github.com/0xhackerfren/frida-game-hacking-mcp (VERIFIED-WEB)
- 85 stars, 5 commits, MIT. Python, Frida >=16, stdio. "Cheat Engine-like functionality for AI agents".
- 42 tools:
  - Process (6): `list_processes`, `attach`, `detach`, `spawn`, `resume`, `get_session_info`.
  - Memory (10): `scan_value(value, type)`, `scan_next(value)`, `scan_changed`, `scan_unchanged`,
    `scan_pattern("89 47 44 ?? ?? 5B 7A", "r-x")`, `get_scan_results`, `clear_scan`, `read_memory`,
    `write_memory("0x12345678","E7030000")`, `list_memory_regions`.
  - Modules (5): `list_modules`, `get_module_info`, `get_module_exports`, `get_module_imports`, `resolve_symbol`.
  - Hooks (6): `hook_function(on_enter JS, on_leave JS)`, `replace_function(addr, retval)`,
    `intercept_module_function("game.dll","CheckLicense", on_leave="retval.replace(1);")`, `hook_native_function`,
    `unhook_function`, `list_hooks`.
  - Debugging (4): `set_breakpoint` (software, implemented *via hooks*), `remove_breakpoint`, `list_breakpoints`,
    `read_registers`.
  - Scripts (3): `load_script`, `unload_script`, `call_rpc`.
  - Windows UI (5): `list_windows`, `screenshot_window`, `screenshot_screen`, `send_key_to_window`, `focus_window`.
  - Meta (3): `list_capabilities`, `get_documentation`, `check_installation`.
- Value types: int8/uint8/int16/uint16/int32/uint32/int64/uint64, float, double, string. Region filters `rw-`
  (default for value), `r-x` (default for AOB), `rwx`, `r--`.
- `scan_next` implementation (DIRECTORY, glama tool page): batch-reads candidate addresses via Frida script and
  filters by packed new value — i.e., single global scan state (one scan at a time), no handles.
- Missing: freeze/lock, HW watchpoints, pointer scans, unknown-initial scans, increased/decreased, float tolerance.
- Takeaway: shows CE-style via Frida is feasible; BEA should add scan *handles* (multiple concurrent scans),
  unknown-initial + relative ops, float epsilon, and results kept server-side.

### 1.5 dryfryce/frida-mcp (DIRECTORY only)
- 55 tools, `frida_` prefix. Has `frida_hook_function`, `frida_memory_scan`, `frida_java_find_instances`,
  **`frida_stalker_trace`** ("very powerful but heavy", optional thread id) — the only Stalker tool I found in any
  MCP. Glama quality score 3.1/5; reviewer called 55 tools "excessive"; overlapping hook tools
  (`frida_hook_function`, `frida_intercept_method`, `frida_java_hook_method`, `frida_objc_hook_method`) confuse.

### 1.6 Others (DIRECTORY)
- **1shin-7/ya-frida-mcp** (37 stars, WIP): 59 tools in 7 categories (`frida_ls_devices`, `frida_add_remote`,
  `frida_enable_spawn_gating`, `frida_ps`, `frida_spawn`, `frida_attach`, `frida_inject`, `frida_rpc_call`,
  `frida_get_messages`, `frida_compile_script`, `frida_snapshot_script`, `frida_memory_read|write|scan|protect`,
  `adb_*`, `frida_server_*`). FastMCP. Has MCP *prompts* as workflow templates incl. Stalker tracing.
- **rmorgans/frida-mcp** (14 tools; `--remote-address 10.211.55.3 --remote-alias windows_vm` — remote device
  aliases). GitHub URL 404'd for me (renamed/removed?).
- **cbxss/frida-mcp** (mobile security; `memory_search`, `memory_list_modules`), **fuzzmind/frida-mcp**,
  **octopus/frida-mcp** (Android), **zhizhuodemao/frida-mcp**, **276793422/frida_mcp**, **cengziyang22-bit/frida-mcp**.
- **yfe404/frida-stalker-skills** — not a server; *Agent Skills* that drive Stalker via an existing Frida MCP's
  `call_rpc_export` + `get_session_messages`. Shows skills-over-thin-MCP as an alternative distribution model.
- Warning noted by search: some glama listings link to suspicious zip downloads (e.g., a "Gindhar2112" repo).

### 1.7 Non-MCP Frida prior art worth reusing (BELIEVED unless noted)
- **WorksButNotTested/stalker-coverage** — TS module that emits **DynamoRIO drcov** from Frida Stalker
  (DIRECTORY-confirmed). Exactly what BEA needs for coverage export into Lighthouse/Cartographer/Ghidra.
- Frida `frida-trace` handler model (onEnter/onLeave per function, auto-generated stubs) — the UX baseline for
  "hook with structured arg capture".
- Synacktiv **Frinet** (SSTIC 2024; Frida + Tenet-style trace). Execution trace for Tenet trace explorer.

---

## 2. x64dbg MCP servers (Windows)

### 2.1 Wasdubya/x64dbgMCP — https://github.com/Wasdubya/x64dbgMCP (VERIFIED-WEB)
- 604 stars, 74 forks, 19 commits. Python MCP server `x64dbgmcp.py` + C++ plugin `.dp64/.dp32` (CMake+MSVC).
- Claims "40+ x64dbg SDK tools" but README names only `CMDEXEC` (e.g., `init <full path>`) and `GetModuleBase`.
- Limitations: restarting a crashed/hung target requires full exe path; x64dbg ignores out-of-range addresses so
  the model must first call `GetModuleBase`; **"large token counts"** are a concern — README suggests a proxy
  ("Headroom") to compress context.

### 2.2 AgentSmithers/x64DbgMCPServer — https://github.com/AgentSmithers/x64DbgMCPServer (VERIFIED-WEB)
- 743 stars, 106 forks, 185 commits. C# .NET Framework plugin; raw `HttpListener`; SSE on port 50300
  (`/sse`, `/message/`); Claude Desktop needs an STDIO↔SSE proxy.
- Tools: `ExecuteDebuggerCommand(command)` (returns bool), `ExecuteDebuggerCommandWithVar(command, resultVar,
  pollMs, pollTimeoutMs)`, `ExecuteDebuggerCommandWithOutput(command)`, `ReadDismAtAddress(addressStr, byteCount)`,
  `ReadMemAtAddress`, `WriteMemToAddress(addressStr, byteString)`, `CommentOrLabelAtAddress`, `GetAllRegisters`,
  `GetLabel`, `GetAllActiveThreads`, `GetAllModulesFromMemMap`, `GetCallStack`.
- Limitations (README): bool result only means "submitted", not "succeeded" — use WithVar/WithOutput; listens on
  all IPs → needs admin/urlacl (localhost-only "planned"); "Context deadline exceeded" timeouts over SSE;
  blocked DLLs crash x64dbg; "not every command fully implemented".
- Takeaway: *poll a debugger variable until set* (`pollMs`, `pollTimeoutMs`) is a crude but practical way to
  synchronize on async debugger state.

### 2.3 bromoket/x64dbg_mcp — https://github.com/bromoket/x64dbg_mcp (VERIFIED-WEB)
- 136 stars, v2.3.0. C++ plugin exposing **153 REST endpoints** on `127.0.0.1:27042` (note: collides with Frida's
  default port 27042!), TS stdio bridge (npm `x64dbg-mcp-server`), Zod-typed, optional `X64DBG_MCP_TOKEN`.
- **23 "mega-tools"** (action-based): control (run/step/pause/raw/scripts/eval), CPU+memory (regs incl. AVX-512,
  read/write/alloc/protect, memmap), stack (callstack, SEH, return addrs), code analysis (disasm, assemble,
  xrefs, basic blocks, CFG, loops), breakpoints & tracing (software, **hardware**, memory, conditional, logging,
  batch, trace logs), symbols/search (labels, comments, AOB, strings), process/system (threads/TEB, handles, TCP,
  PEB, **anti-debug hiding**), patching & dumping (byte patches, PE dump, IAT fix, patch export).
- v2.3.0: malformed HTTP can no longer crash x64dbg; clean connection draining; CORS locked down.
- Takeaway: "mega-tools with an `action` enum" is the dominant answer to tool-count limits. Event handling not
  documented.

### 2.4 Others (DIRECTORY)
- **ouonet/x64dbg-mcp** (Node, stdio or Streamable HTTP; npm `x64dbg-mcp@1.3.1`).
- **rison1337/x64dbgMCP** (GPLv3, x86+x64 CI).
- **SetsunaYukiOvO/x64dbg-mcp** (~273 stars, HTTP/SSE JSON-RPC).
- A **Zig-based** x64dbg plugin with npx launcher, ~80 tools (Korean PyTorch-KR writeup).
- **sarks0/binary-mcp** (10 stars; 147 tools; Ghidra/ILSpy/pefile static + x64dbg & WinDbg live) — see §10.

---

## 3. WinDbg / DbgEng / CDB MCP servers (Windows)

### 3.1 Microsoft official WinDbg MCP (VERIFIED-WEB, devblog 2026-10-06)
- Ships in **WinDbg 1.2610.1001.0** (Store / download page). MCP server *inside WinDbg*, AI client connects through
  a local proxy. **One active MCP client per WinDbg session**.
- Capabilities (no tool names published in the post): inspect target, run debugger commands, review diagnostics
  and source, visualize debugger data, create scripts. Works on live targets, dumps, **TTD traces**.
- **Secure Mode** (default ON when starting MCP): blocks loading/executing untrusted code, launching processes,
  unsafe file ops. Start MCP *before* connecting a target, else "partial Secure Mode" + warning. Sticky until restart.
- **Cross-prompt-injection protection**: classifies debugger output via the client's model using **MCP sampling**,
  blocks flagged content. Claude Code / Codex don't support sampling → must disable protection ("not recommended").
- All AI actions logged and visible in WinDbg UI. "Diagnostician" skill: 5-phase investigation; treats pattern
  matches as hypotheses; writes `.diagnoses\<id>\<yyyyMMdd-HHmmss>.md`.
- Officially supported clients: VS Code, GitHub Copilot CLI.
- Takeaway: Microsoft frames target memory/strings as **prompt-injection vectors** — BEA should mark all
  target-derived strings as untrusted in provenance (REA already does `provenance` untrusted marking for
  frida-mobile-mcp parity).

### 3.2 svnscha/mcp-windbg — https://github.com/svnscha/mcp-windbg (VERIFIED-WEB)
- ~1.6k stars, 165 forks, MIT, Python ≥3.10 or standalone `mcp-windbg.exe` (code-signed, SHA256SUMS).
- 11 tools: `list_dumps`, `open_cdb_dump`, `open_cdb_remote`, `open_kd_session`, `open_kd_dump`,
  `run_cdb_command`, `run_kd_command`, `close_cdb_session`, `close_kd_session`, `send_ctrl_break`,
  `wait_for_break`. `open_*` returns `session_id` like `cdb-1a2b3c4d`.
- Wraps headless `cdb.exe`/`kd.exe` subprocesses. Dump open = one-call triage (`!analyze -v`, stacks, modules,
  threads). Per-call timeout (default 30 s, `--timeout`); on timeout sends CTRL+BREAK and **resynchronizes**.
- `--filter-script` redacts PII/secrets from args/output before leaving the machine.
- Transports: stdio, streamable HTTP. No auth described for HTTP.
- Requires Debugging Tools for Windows (not installed on the BEA host).

### 3.3 glslang/windbg-mcp — https://github.com/glslang/windbg-mcp (VERIFIED-WEB via glama + repo docs) ★ best engineering
- Rust, Windows x64, MIT, v0.23.0. DbgEng bindings in `glslang/dbgscope`.
- **Architecture**: supervisor process speaks MCP; **each target in its own engine worker child process**
  (dbgeng.dll = one debuggee per process). Max 4 sessions; at the limit a new open reclaims the oldest *idle*
  session; if all busy → refused. Each session serial ("one command at a time"). x86 worker for 32-bit/WoW64.
- **78 tools (89 in latest token-budget doc)**, grouped and selectable with `--tools session,inspect,crash`:
  - session: `open_dump`, `open_trace`, `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`,
    `interrupt`, `end_session`, `session_status`, `server_log`
  - inspect: `current_location`, `registers`, `read_memory`, `backtrace`, `modules(refresh)`, `threads`,
    `disassemble`, `dx`, `set_symbol_path`, `execute` (raw)
  - crash: `crash_triage`, `exception_triage`, `decode_error_reporting`
  - exec: `go`, `step_over`, `step_into`, `set_breakpoint`, `breakpoints`, `clear_breakpoints(ids|all)`,
    `run_to_address`, **`continue_async`, `wait_for_stop`, `break_in`**
  - batch: **`debug_batch`** (ordered sequence with assertions and rollback)
  - ttd: `step_back`, `step_over_back`, `reverse_go`, `goto_position`, `ttd_calls`, `ttd_memory`, `ttd_events`,
    `index_trace`, `record_trace`
  - ioctl (11), allocator (pool 6 + heap 5 + `walk_memory`), securekernel (12, opt-in).
- Results use MCP **`structuredContent`**; failures carry stable categories (`invalid_argument`, `debugger`,
  `timeout`, `stale_session`, `target_running`).
- **Async semantics (docs/sessions.md)**: `continue_async` returns an execution handle immediately
  (`running:true`, `breaks_in_ms`); one run per session; target-reading tools refused while running
  (`category: target_running`, not queued); **"A wait that runs out is a poll, not a failure"**;
  **"A stop is read, not taken"** (stop stays filed against its handle — idempotent re-reads); stop flags
  `interrupted`, `timed_out`, `target_gone`; `max_run_ms` default 60 s, max 1 h; control-flow tools wait 60 s
  then break in and report `timed_out`; progress notifications only if caller sends `progressToken` (every 10 s,
  `progress` = seconds elapsed, no `total`).
- **Lifecycle on end**: dump/trace closed; `attach_process` → detached & left running; `launch` → terminated.
  Raw `.attach`/`.detach`/`.opendump` via `execute` **retire** the handle (server can't track it).
- **Token budget engineering (docs/token-budget.md)**: measures minified UTF-8 JSON bytes (~4 B/token); separate
  budgets for tool *surface* (once/conversation) vs *per-result*; CI test ceilings `MODEL_VISIBLE_CEILING`,
  `WIRE_CEILING`, `WORST_TOOL_CEILING` with a golden `tool_budget.json`; per-tool result ceilings with ~35-45%
  headroom; `modules` got `limit` (default 64, max 2000) and returns counts (`matched`, `unloaded_matched`) "so a
  page cannot be mistaken for the full table"; stripped prose from `outputSchema` (391 KB → 178 KB wire, since
  outputSchema is never model-visible); rule: `structuredContent` ≤ 20× text rendering; `registers` default drops
  vector regs (9.8 KB → 3.5 KB). Latest: 89 tools, 139,414 B model-visible. Unbounded (acknowledged):
  `ttd_calls`, `ttd_memory`, `threads`, `execute`, `dx`.
- **Limitations doc** is exemplary honesty: e.g., `reachable_from_dispatch` — "REACHABLE is sound, NOT
  REACHABLE is best-effort"; "Results are evidence, not verdicts. Imports are not calls"; `faulting_frame` is "a
  positional guess, not a verified culprit"; on TTD a broken-in replay "can end past breakpoints it never reported
  hitting"; target data returned unredacted (only transcript masks credential-like strings); rendered names are
  escaped to prevent line injection but structured output is not.
- **Safety**: `--listen` refuses to start without `WINDBG_MCP_LISTEN_TOKEN`; per-client tokens; JSONL transcript
  `WINDBG_MCP_TRANSCRIPT` with redaction; kernel attach + TTD record need admin.
- Takeaway: BEA should copy (1) worker-process-per-target isolation, (2) continue_async/wait_for_stop/break_in
  with "stop is read, not taken", (3) `debug_batch` with assertions, (4) CI-enforced token budgets,
  (5) counts-with-pages, (6) sound vs best-effort verdict labeling.

### 3.4 tonyredondo/debugger-mcp-server (VERIFIED-WEB)
- 3 stars. .NET 10; WinDbg on Windows, LLDB (+SOS) on Linux/macOS. 11 tools: `session`, `dump`, `analyze`,
  `compare` (two sessions/dumps), `report` (JSON/MD/HTML), `watch`, `inspect`, `symbols`, `source_link`,
  `datadog_symbols`, `exec` ("last resort"). Multitenant HTTP API + CLI `dbg-mcp`.
- Takeaway: action-multiplexed coarse tools + `compare` of two snapshots (useful for BEA "diff two runs").

---

## 4. GDB / pwndbg / rr

### 4.1 Ipiano/gdb-mcp — https://github.com/Ipiano/gdb-mcp (VERIFIED-WEB)
- 52 stars. pygdbmi (GDB/MI). One GDB session per server instance. 22 tools: `gdb_start_session`,
  `gdb_execute_command` (CLI or MI), **`gdb_call_function` (separate tool so it can be permissioned separately)**,
  `gdb_get_status`, `gdb_stop_session`, threads/frames (5), breakpoints (5), `gdb_continue`, `gdb_step`,
  `gdb_next`, `gdb_interrupt`, `gdb_evaluate_expression`, `gdb_get_variables`, `gdb_get_registers`.
- "A running program keeps GDB busy, so other commands can time out" → must `gdb_interrupt` first. No wait-for-stop.
- Missing (its own TODO): watchpoints, memory inspection, error recovery, output formatting.

### 4.2 RocketMaDev/pwndbg-mcp — https://github.com/RocketMaDev/pwndbg-mcp (VERIFIED-WEB)
- 38 stars. Tools: `load_executable`, `execute_command`, `pwndbg_status`, `debug_control`,
  `connect_decomp2dbg`, `pwndbg_hard_reset`, `send_to_process`, `eval_to_send_to_process`, `read_from_process`,
  `interrupt_process`, aliases `telescope`, `context`, `heap`, `bins`, `backtrace`, `vmmap`, `xinfo`.
- GDB/MI, interrupts via tty, output in **TOON** ("human-readable and token-saving").
- **Author's own verdict**: "Controlling pwndbg with MCP requires lots of tokens, and it's hard to support debugging
  with python script" → recommends "use a tmux skill and pwndbg skill, and provide AI agent with a tmux session
  instead." Also: the AI "tends to use raw tools like reading /proc/mem to get information"; "All communication are
  encapsulated and user can not observe gdb status"; "Sometimes Ctrl-C kills process or can't wake up GDB."
- Takeaway: a raw-command proxy loses to a terminal. BEA's value must be *structured, summarized, bounded*
  primitives that are cheaper than the terminal, plus human observability (a log/console the user can watch).

### 4.3 pwno-io/pwno-mcp — https://github.com/pwno-io/pwno-mcp (VERIFIED-WEB)
- 281 stars. GDB+pwndbg in an isolated environment; HTTP (port 5500) or stdio; "stateful debugger sessions",
  multi-session; context snapshots (registers, stack, disasm, source, backtrace); `pwncli` exploit workflows;
  RetDec helper. WebSocket streaming I/O listed as *future*.

### 4.4 Others (DIRECTORY)
- **signal-slot/mcp-gdb** (Node; core dumps, memory, stacks), **pansila/mcp_server_gdb** (Rust? GDB/MI,
  `create_session`, `get_all_sessions`), **datobena/gdb-mcp** (PyPI `gdb-mcp`; credits ida-pro-mcp),
  **hnmr293/gdb-mcp** (GDB command reference as an MCP *resource*), **smadi0x86/GDB-MCP** (GDB+LLDB),
  **Mort2000/gdb-lite-mcp** (TS, Node 20+), **birdeclipse/gdb-mcp** (GDB or LLDB, call functions),
  **cnitlrt/pygdbmi-mcp-server**, **sbergeron42/gdb-multiarch-mcp**, **liert/pwndbg-mcp** (HTTP gateway,
  collaborative with user's terminal), **Micro-Evaluation-Group/pwndbg-lldb-mcp**.
- rr (record/replay, Linux only): **karellen-rr-mcp** (`pip install karellen-rr-mcp[rr]`; Claude Code plugin with
  `/karellen-rr-mcp:rr-debug` skill and an `rr-investigator` agent; `RR_MCP_TIMEOUT_FORWARD/REVERSE`),
  **jnjaeschke/rr-mcp** (PyPI `rr-mcp`, 48 tools, multi-process), **schuay/gdb-mcp** (`rr_record`,
  `start_replay_session`, reverse step/continue/finish).

---

## 5. LLDB

### 5.1 LLVM built-in: `lldb-mcp` + `protocol-server start MCP` (VERIFIED-WEB, lldb.llvm.org/use/mcp.html)
- `lldb-mcp` binary speaks MCP over stdio; one process per client connection; multiplexer that also discovers
  running LLDB instances via `~/.lldb/lldb-mcp-<pid>.json` (only at startup).
- 4 tools: `session_create` (→ URI `lldb-mcp://instance/{pid}/debugger/{id}`), `command(command, debugger?)`,
  `sessions_list`, `session_close` (only sessions it created). Resources per debugger and per target.
- Limitations (official): sessions start in **async mode** — `continue` returns before stop, need
  `script lldb.debugger.SetAsync(False)`; **debuggee stdout not returned**; any `lldb-mcp` can run commands in any
  discovered session; protocol version **2024-11-05 → no structuredContent, plain text only**.
- Added in LLVM PR #143628. RFC on discourse.

### 5.2 Community (DIRECTORY)
- **ant4g0nist/lisa.py / lldb-mcp** (~740 stars; LLDB plugin JSON-RPC + MCP translator),
  **stass/lldb-mcp** (widely listed), **benpm/claude_lldb_mcp** (structured tools vs single `lldb_command`),
  **ankur106/LLDB_MCP** (TS).
- REA already has an LLDB call tracer bridge (VERIFIED-LOCAL: `src/native/LldbCallTracer.ts`).

---

## 6. Disassembler-hosted debuggers (IDA, Binary Ninja, Ghidra, radare2)

### 6.1 mrexodia/ida-pro-mcp — https://github.com/mrexodia/ida-pro-mcp (VERIFIED-WEB)
- 13.2k stars, 599 commits. README now says "I recommend using the Official Hex-Rays IDA MCP Server instead!"
- Architecture: `idalib-mcp` supervisor with one idalib **worker process per database**; workers register in a
  discovery dir, outlive supervisor, idle TTL 1 h; `--max-workers` (default 4); every call carries explicit
  `database` id. Env knobs: `IDA_MCP_WORKER_CALL_TIMEOUT`, `IDA_MCP_WEDGED_GRACE_SEC`, health RPC retries, etc.
- **Debugger tools hidden by default** — enable with `?ext=dbg` on the URL:
  `dbg_start()`, `dbg_exit()`, `dbg_continue()`, `dbg_run_to(addr)`, `dbg_step_into()`, `dbg_step_over()`,
  `dbg_bps()`, `dbg_add_bp(addrs)`, `dbg_delete_bp(addrs)`, `dbg_toggle_bp(items)`, `dbg_regs()`,
  `dbg_regs_all()`, `dbg_regs_remote(tids)`, `dbg_gpregs()`, `dbg_gpregs_remote(tids)`, `dbg_regs_named(names)`,
  `dbg_regs_named_remote(tid,names)`, `dbg_stacktrace()`, `dbg_read(regions)`, `dbg_write(regions)`.
- Pagination: search tools return `cursor:{next: offset}` or `{done:true}`; default limit 1000, hard max 10000
  "to prevent token overflow". Batch ops return `[{..., error: null|string}]`. Most ops accept item or list.
- **Issues**: #441 "Debugger extension impossible to use" (no way to set `?ext=dbg` in plugin install path);
  #217 "HTTP requests hang indefinitely due to IDA main thread synchronization deadlock" (open, bug); #266
  `?ext=dbg` silently discarded by stdio proxy; PRs #381/#400/#401 "Fix dbg_start reporting failure on
  successful starts" / "IP grace handling"; **#449 "Add relocation/rebasing tools for runtime-vs-static address
  mapping" — closed *not planned* 2026-06-13** (proposed `calculate_relocation_delta`, `convert_ida_to_runtime`,
  `convert_runtime_to_ida`, `set_relocation_base`; author: manual offset arithmetic is "error-prone" and
  token-wasteful). Open PR #475 debugger headless/stdio.
- Takeaway: debugger-as-extension of a static tool is a second-class citizen (hidden, flaky start detection,
  main-thread deadlocks). BEA as a dedicated dynamic server with first-class rebasing fills a demonstrated need.

### 6.2 Hex-Rays official IDA MCP (DIRECTORY, weak)
- Exists (README of ida-pro-mcp points to it; a mirror describes GUI + headless + shared database sessions).
  Could not confirm debugger tool names.

### 6.3 Binary Ninja (VERIFIED-WEB for fosdickio)
- **fosdickio/binary_ninja_mcp** (457 stars, 50+ tools): static only — `decompile_function`, `get_il`,
  `fetch_disassembly`, xrefs, renames, types, `patch_bytes` (saves to disk by default!). **No debugger tools.**
- **mrphrazer/binary-ninja-headless-mcp**: "debugger APIs are currently not covered" (DIRECTORY).
- BinAssistMCP (36 tools), MCPPhalanx/binaryninja-mcp, Invoke-RE/binja-lattice-mcp: no debugger evidence.
- Binary Ninja's own debugger (Vector35/debugger; GDB RSP / LLDB / DbgEng backends; Python `dbg.add_breakpoint`)
  is **not exposed via any MCP** I could find. Gap.

### 6.4 Ghidra
- **bethington/ghidra-mcp** — https://github.com/bethington/ghidra-mcp (VERIFIED-WEB) ~5.9k stars.
  - Ghidra **TraceRmi** debugger: 16 `/debugger/*` endpoints, **GUI plugin only** (not headless). Backend dbgeng on
    Windows PE, gdb/lldb otherwise. Tools: `debugger_launch`, `debugger_launch_offers`, `debugger_interrupt`,
    `debugger_resume`, `debugger_step` (into/over/out), `debugger_set_breakpoint`, `debugger_remove_breakpoint`,
    `debugger_list_breakpoints`, `debugger_registers`, `debugger_read_memory`, `debugger_stack_trace`,
    `debugger_modules`, `debugger_status`, `debugger_traces`, **`debugger_static_to_dynamic`,
    `debugger_dynamic_to_static`** (ASLR-aware mapping — the only first-class implementation found).
  - **P-code emulation**: `emulate_function` (isolated, controlled register/memory inputs, Ghidra `EmulatorHelper`),
    `emulate_hash_batch` (brute-force API hashes).
  - Can proxy 22 `debugger_*` tools to an *external* dbgeng server (not shipped), off by default, loopback only.
  - **Lazy tool groups**: `search_tools` + `load_tool_group`, default groups `listing,function,program`.
    Reason given: **"Gemini rejects requests that advertise all 209 tools at once."**
  - Script execution opt-in `GHIDRA_MCP_ALLOW_SCRIPTS=1`; localhost no-auth by default; exact Ghidra version lock.
- **themixednuts/GhidraMCP** (VERIFIED-WEB, 92 stars, 396 commits, Ghidra 12.1.4): 14 coarse tools incl. one
  `debugger` tool covering Trace RMI connect/accept/launch, target lifecycle, trace/thread/stack/object discovery,
  live memory/register/watch, static mappings, remote methods, emulation. Opaque `cursor`/`next_cursor`
  pagination with `page_size`/`max_lines`/`max_results`. Known issue: **script-triggered error dialogs make
  requests hang until the dialog is closed**. Request timeout default 600 s.
- **LaurieWired/GhidraMCP** — static only. **ReVa** (Ghidra, streamable HTTP) — static (BELIEVED).
- Ghidra Trace RMI itself has agents for GDB, LLDB, x64dbg, drgn, dbgeng (DIRECTORY/BELIEVED).

### 6.5 radare2
- **radareorg/radare2-mcp (r2mcp)** — https://github.com/radareorg/radare2-mcp (VERIFIED-WEB) 333 stars, C, native
  r2 APIs. Named tools: `open_file`, `analyze`, `sql` (r2xsql plugin), "run" category (raw r2 commands / r2js).
  **No dedicated debugger tools documented**; debugging only via raw `run` (r2's `d*` commands).
  Safety: `-R` read-only / `r2mcp.readonly`, `r2mcp.sandbox` + `.grain`, `r2mcp.permissive`, `r2mcp yolo on|off`
  ("disables approvals and exposes dangerous run tools"), `r2mcp approve` (supervisor approvals), HTTP bearer
  `-a <token>`/`-A`, loopback default.
- **Third-party radare2 MCP with 85 tools** (DIRECTORY): static, ESIL emulation with state preserved across calls,
  RzIL emulation, **live debugging with persistent sessions** (launch/attach, bps, step, regs, mem, maps, threads,
  backtraces), vuln scanning.

---

## 7. Cheat Engine & memory-scanner MCPs

### 7.1 miscusi-peek/cheatengine-mcp-bridge — https://github.com/miscusi-peek/cheatengine-mcp-bridge (VERIFIED-WEB) ★
- **1.7k stars**, 251 forks, v12.0.0, MIT, Python ≥3.10 FastMCP.
- Architecture: agent → stdio → `mcp_cheatengine.py` → named pipe `\\.\pipe\CE_MCP_Bridge_v99` →
  `ce_mcp_bridge.lua` inside Cheat Engine (worker thread for blocking I/O + main thread for GUI/CE API) → target.
  Optional `ce_tcp_relay.py` to run the MCP server in WSL/VM. `CE_MCP_TIMEOUT` default 30 s. Pipe responses capped
  16 MB ("Response too large").
- ~180 tools (from `AI_Context/MCP_Bridge_Command_Reference.md`). Highlights:
  - **Scans**: `scan_all(value?, type='dword', protection='+W-C', scan_option=exact|unknown|between|bigger|smaller,
    value2)` → returns **count only**; `next_scan(value?, scan_type=...|increased|decreased|changed|unchanged|
    increased_by|decreased_by)` → remaining count; `get_scan_results(offset=0, limit=100)`.
  - **Persistent named scans** (multiple concurrent): `create_persistent_scan(name)`,
    `persistent_scan_first_scan(name, ...)`, `persistent_scan_next_scan(name, ...)`,
    `persistent_scan_get_results(name, offset, limit)` (returns `total`), `persistent_scan_destroy(name)`.
  - **Pointers**: `read_pointer(address, offsets?)`, `read_pointer_chain(base, offsets[])` (returns per-step
    `chain` + `final_address`), `pointer_rescan(address, max_depth=4, limit=100)`,
    `analyze_pointer_access(instruction, registers, accessed_address?, is_64bit?)` (pure analysis → `struct_base`,
    `next_scan_value`), `validate_pointer_chains(chains[≤5000], target, include_misses)`.
  - **HW breakpoints (non-breaking, logging)**: `set_breakpoint(address, id, capture_registers=true,
    capture_stack=false, stack_depth=16)`, `set_data_breakpoint(address, id, access_type=r|w|rw, size=1|2|4)`;
    4 slots DR0–DR3 ("No free hardware breakpoint slots"); `get_breakpoint_hits(id?, clear=false)` → hits with
    registers+stack; `remove_breakpoint`, `list_breakpoints`, `clear_all_breakpoints`.
  - **DBVM (hypervisor) "find what writes" (invisible to anti-debug)**: `start_dbvm_watch(address,
    mode=w|r|rw|x, max_entries=1000)`, `poll_dbvm_watch(address, max_results)` (non-stopping),
    `stop_dbvm_watch(address)` → all hits + `hit_count` + `duration_seconds`.
    Documented walk-back recipe: `start_dbvm_watch` → `poll_dbvm_watch` → `analyze_pointer_access` →
    `scan_all(qword)` → `validate_pointer_chains`.
  - **Branch tracing**: `debug_set_last_branch_recording(thread_id, enabled)`,
    `debug_get_last_branch_record(thread_id)` (LBR from/to pairs).
  - Analysis: `disassemble`, `analyze_function`, `find_function_boundaries`, `dissect_structure`,
    `get_rtti_classname`, `find_references(limit 50)`, `find_call_references`, `generate_signature` (**scans all
    memory, "can take several minutes and will block the pipe"**).
  - Execution/injection: `inject_dll`, `inject_dotnet_dll`, `execute_code`, `execute_method`, `auto_assemble`,
    `compile_c_code`, `compile_cs_code`, `generate_api_hook_script`.
  - Kernel (DBK): `dbk_get_cr3`, `read_process_memory_cr3`, `allocate_kernel_memory`, ...
  - Shell gated: `run_command`, `shell_execute` need `CE_MCP_ALLOW_SHELL=1`.
- Warnings: **BSOD risk** — must disable CE Settings → Extra → "Query memory region routines"
  (`CLOCK_WATCHDOG_TIMEOUT`); writes "can crash the target"; HW slot exhaustion.
- Doc inconsistencies noted (type vs scan_option confusion; `pointer_rescan` needs an undefined "pointer map").
- Takeaway: The *API shape* (scan returns count; results paged; named persistent scans; non-breaking HW BPs with
  hit logs; walk-back recipe) is the proven UX. BEA can replicate the core without CE/DBVM using Frida
  `Memory.scan`/`Process.setHardwareWatchpoint` (Frida 17 BELIEVED: `Thread.setHardwareWatchpoint` /
  `Process.setExceptionHandler`) or native Win32 debug registers.

### 7.2 mq1n/GhostMCP — https://github.com/mq1n/GhostMCP (VERIFIED-WEB) ★ most complete in-process toolkit
- 33 stars, EXPERIMENTAL, Rust, Windows. Injected `ghost-agent.dll` (embeds `ghost-core`) ↔ host over TCP
  localhost 13338. Four MCP servers to stay under client tool limits: `ghost-core-mcp` (13340, 85 tools),
  `ghost-analysis-mcp` (13341, 82), `ghost-static-mcp` (13342, 84; r2/IDA/Ghidra/YARA), `ghost-extended-mcp`
  (13343, 85). Each has meta tools `mcp_capabilities`, `mcp_documentation`, `mcp_version`, `mcp_health`.
- Design rationale: "agent kept small and crash-resistant, heavy work in host"; structured JSON with pagination.
- **Value scanner**: 12 modes (exact, changed, unchanged, increased, decreased, greater, less, between, unknown
  initial, fuzzy, ...), iterative refinement, writable/executable/module filters, alignment-based fast scan,
  **live progress with cancellation**, export/import JSON/CSV/**Cheat Engine XML**.
- **Pointer scanner**: 1–10 levels, static-base filter, offset constraints, rescans with **0.0–1.0 stability
  scores**, session comparison, `.ptr` import/export.
- Debugging: INT3 BPs with byte restoration, **HW BPs DR0–DR3**, single-step, thread suspend/resume.
- Execution: call target functions with cdecl/stdcall/fastcall/win64/thiscall; shellcode via direct
  call/CreateThread/NtCreateThreadEx/APC/thread hijack; iced-x86 assembler.
- **API tracing (API Monitor-style)**: **ring-buffer event pipeline with drop-oldest / block / sample
  backpressure**, JSON API packs (kernel32, user32, ntdll, ws2_32, advapi32), server-side filters, presets (File
  Ops, Network, Registry, Errors Only), per-API stats, queue monitoring.
- Conditional BPs with AND/OR/NOT, hit counts, arg/return overrides, audit trail export.
- Dumps: full/region/module dump with Scylla-style IAT rebuild, WinDbg-compatible minidumps, incremental dumps,
  binary diffs, dump catalog.
- AI integration: command batching with conditions, history/replay, **event subscriptions**, "AI-oriented
  summaries", **state diffs**, breakpoint recommendations.
- **Security model**: capability scopes `read` (default) / `write` / `execute` / `debug` / `admin`;
  **safety tokens** (scope + TTL ≤24 h, one-time use); modes Educational / Standard (default; dangerous ops need
  approval) / Expert; protected-process blocklist (csrss, lsass, svchost); token-bucket rate limits; size limits
  with 80% warnings; `patch_preview`, `patch_history`, `patch_undo`; auto-backup.
- Caveats: README's tool count inconsistent (250+ vs 336), "~100" vs "90-tool MCP limit" claims; experimental.

### 7.3 Others (VERIFIED-WEB where noted)
- **PyMemoryEditor MCP** (jeanextreme002; VERIFIED-WEB README): 14 tools; **scan results kept server-side behind a
  handle — "a 40,000-hit first scan costs only a few tokens"**. Cross-platform (Win/Linux/macOS).
- **bethington/cheat-engine-server-python** (DIRECTORY): standalone, read-only by default, whitelist, imports .CT.
- **crain99/ce-mcp** (ASP.NET Core REST plugin, port 6300), **DoranekoSystems/cemcp** (Lua pipe, GPL-3),
  **CheatEngineNet/CheatEngine.Mcp** (C#, v2.0.0-beta.1, CE 7.7), **Yunwu7/ce-mcp** (named pipe, CE 7.6),
  **imrx44/mcp** (Lua HTTP bridge), **un4ckn0wl3z/MemMCP**, **procmem** (pymem, live + dumpfile).
- Reclass fork commit "Add MCP scanner tools" (archived-Reclass) — ReClass.NET-style structure reconstruction
  with MCP scanning (DIRECTORY).

---

## 8. Time-travel debugging (TTD/rr/Undo)

- **Microsoft WinDbg MCP** (official) accepts TTD traces (no TTD-specific tools documented).
- **glslang/windbg-mcp**: `record_trace` (needs TTD.exe + admin), `open_trace`, `index_trace`, `step_back`,
  `step_over_back`, `reverse_go`, `goto_position`, `ttd_calls`, `ttd_memory`, `ttd_events`. User-mode only.
  Replay needs `TTDReplay.dll` copied from WinDbg. `ttd_calls`/`ttd_memory` are *unbounded* outputs (acknowledged).
- **Undo** (Linux C/C++ and Java): `lr4j_mcp_server` (VERIFIED-WEB docs.undo.io/java/MCPServer.html) tools:
  `load_recording`, `list_recordings`, `unload_recording`, `help(topic)`, `continue`/`reverse_continue`,
  `step_into`/`reverse_step_into` (with class exclusion patterns), `step_over`, `step_out` + reverse variants,
  `set_breakpoint`, `set_watchpoint(class, field)`, `set_exception_breakpoint`, `goto_bbcount`, `goto_start`,
  `goto_end`, `go_to_epoch_millis`, `go_to_wall_clock_time`, `goto_object_create`, `get_current_location`,
  `get_thread_stack`, `get_local_variables`, `get_field_value`, `list_threads`, `read_console_output`,
  `get_next_undo_event`/`get_previous_undo_event`, `get_native_stack_trace`, `set_native_breakpoint`,
  `read_memory`, `search_process_memory`, `get_argument_registers`, `get_all_registers`, `addr_to_symbol`.
  Design: one replay process per recording (isolated, parallel), LRU suspension of idle engines under memory
  pressure (handle + breakpoints survive), Python API scripts run *next to the recording and return only results*
  ("saves time and tokens"), timeout 600 s kills the replay process.
  - **Undo CTO talk "Building an MCP debugger — the good, the bad and the weird"** (VERIFIED-WEB summary): provide
    *as few tools as possible* ("smallest vocabulary... that will allow it to solve the problem"); agents fixate on
    a favorite tool; each tool does one thing well; **keep tools stateless — persistent breakpoints confused the
    LLM** (it couldn't explain why execution stopped there later); prefer composable actions like "run to next
    line"; if the model misuses a tool, change the tool; bridge human vocabulary to program symbols ("zombie" →
    Doom's "possessed"); ground answers in recorded state. Reverse-op tool set hidden behind 8–10 tools.
- **rr**: karellen-rr-mcp, jnjaeschke/rr-mcp (48 tools), schuay/gdb-mcp (see §4.4). Linux only.
- **Replay.io MCP** (JS recordings) — out of scope but same "query a recording" paradigm.
- Takeaway for BEA (Windows, no TTD installed): the *recording/query* paradigm is the strongest agent UX (deterministic,
  re-queryable evidence). BEA can approximate with **bounded Stalker/hook recordings stored as artifacts** and queried
  afterwards (calls, memory writes at address X, first/last occurrence), rather than live-stepping.

---

## 9. DynamoRIO / Intel PIN / coverage

- **No DynamoRIO or Intel PIN MCP server found** (two searches). Gap.
- Prior art (non-MCP, BELIEVED unless noted): DynamoRIO `drcov` client + `drcovlib` (VERIFIED-WEB dynamorio.org),
  `drcov2lcov` (also Rust port on crates.io), Lighthouse (IDA/Binja coverage explorer; consumes drcov and PIN
  "CodeCoverage" pintool logs), Cartographer (Ghidra drcov loader), Tenet (IDA trace explorer; PIN tracer),
  Google **TinyInst** (lightweight Windows/macOS instrumentation via debugger APIs; coverage for Jackalope),
  `stalker-coverage` (Frida → drcov), Frida `Stalker` with `events: {compile: true}` for block coverage
  (cheap) vs `{exec: true}` / `{call: true}` (heavy).
- drcov v2 format (BELIEVED): text header `DRCOV VERSION: 2`, `DRCOV FLAVOR: drcov`,
  `Module Table: version 2, count N`, `Columns: id, base, end, entry, checksum, timestamp, path`, module rows,
  `BB Table: M bbs`, then binary `struct { uint32 start /*module-relative*/; uint16 size; uint16 mod_id; }[M]`.
  Module-relative offsets make it ASLR-independent → also the natural static↔runtime bridge.
- monkeywave's `trace_coverage`/`drive_coverage` exist but export only JSON/MD evidence, **no drcov** (VERIFIED-WEB
  interop.md: "The page doesn't cover drcov").

---

## 10. Multi-engine "workbench" servers

- **sarks0/binary-mcp** (VERIFIED-WEB, 10 stars, 147 tools): Ghidra + ILSpyCmd + pefile static (any OS);
  x64dbg (16 grouped tools: execution, SW/HW/memory/DLL-load/exception/conditional BPs with logging, conditional
  tracing, OEP finder, memory watch **with diff**, type overlays on memory, **anti-debug detect/bypass** (PEB,
  NtGlobalFlag, heap flags), API call logging) + WinDbg kernel (33 tools); **background jobs (4 tools)** to outlive
  client timeouts; persistent analysis sessions (create/save/load/summarise/relate) + analyst notes.
  **Security model**: file-access quarantine allow-list (`BINARY_MCP_ALLOWED_DIRS`; advisory on Windows);
  **fail-closed allowlists for raw debugger commands at both tool layer and inside the C++ plugin**, each
  `;`-segment validated; raw WinDbg off unless `BINARY_MCP_ENABLE_RAW_WINDBG=1`; **"Nothing in src/tools/ starts a
  process from a file on disk"** (attach only, malware-safety stance); HTTP requires token always, refuses wildcard
  binds; "token is equivalent to a debugger session on that host". Output tagging with categories/facets
  (`code-output`) so clients can gate.
- **GhostMCP** (§7.2) also integrates r2/IDA/Ghidra backends.
- **debugmcp/mcp-debugger** (DAP-based, 28 tools, many languages incl. C/C++ via CodeLLDB): `get_output` with
  cursor; session transcript as **subscribable MCP resource**; `expose_session` to mirror into IDE (human
  observability). Windows C/C++: MinGW/DWARF best, MSVC PDB "partial".
- **mcp-emulate / MCPEmulate** (DIRECTORY): Unicorn + Capstone + Keystone + LIEF, 41 tools, stdio/SSE/HTTP.
  **Unidbg MCP** (DIRECTORY): `emulate`, `call_function` for ARM/x86 via Unicorn (Android .so focus).
  No Qiling MCP found.

---

## 11. Academic & industry work on LLM agents doing dynamic analysis

| Work | What | Dynamic tooling | Lesson for BEA |
|---|---|---|---|
| **EnIGMA** (Abramovich et al., ICML 2025, arXiv 2409.16165) | SWE-agent for CTFs | Interactive **gdb** session tool + pwntools remote tool ("IATs"); one interactive session at a time | Interactive (not scripted) debugger use matters; SOTA on NYU CTF / InterCode-CTF / CyBench. Documents **"soliloquizing"** — model hallucinating tool observations. → BEA must make observations verifiable (evidence IDs) |
| **CTF-Dojo** (built on EnIGMA+) | CTF training env | GDB `break`, `continue`, `stepi`, `debug_exec` + Ghidra | Small GDB verb set suffices for CTF |
| **Project Naptime / Big Sleep** (Google P0, 2024) | Vuln research agent | **Debugger tool**: set breakpoints and evaluate expressions at them; ASan builds; Reporter tool; Python sandbox | "interfaces must balance power and usability to avoid overwhelming the LLMs"; breakpoint+expression = high value primitive (≈ BEA hook w/ structured capture) |
| **Project Ire** (Microsoft Research, Aug 2025) | Autonomous malware classifier | Freta memory-analysis sandboxes, angr, Ghidra, decompilers, docs search | **Chain of evidence** log + **validator tool** that checks report claims against evidence (caught an unsupported anti-debug claim). Strong precedent for REA/BEA evidence discipline |
| **ADI — Agent-centric Debugging Interface** (arXiv 2604.24212, FSE 2026) | Debugging for SWE-bench | **Function-level** interaction; **"Frame Lifetime Trace"** = function's stateful execution trace over its lifetime; few navigation commands | 63.8% SWE-bench Verified w/ Sonnet 3.7 at $1.28/task; +6.2–18.5% as plug-in. Line stepping is too expensive → BEA hooks should capture per-call frames (args, return, side effects) not single-steps |
| **InspectCoder** (arXiv 2510.18327) | LLM–debugger collaboration for self-repair | Interactive debugger | Same direction (DIRECTORY) |
| **FORGE** (arXiv 2604.15136) | Firmware binary vuln analysis | Feedback-driven execution loop (reason → tool → observe), "Dynamic Forest of Agents" with bounded per-agent context | 3,457 firmware binaries, 1,274 vulns, 72.3% precision. Bounded context per sub-agent |
| **CrackMeBench** (arXiv 2605.10597) | RE benchmark w/ executable oracles | No-network Docker, standard RE tools; scores *submissions*, records command traces/tokens/cost | GPT-5.5 11/12, Opus 4.7 7/12, Kimi K2 5/12 (pass@3, generated split). Oracles > explanations → BEA "call target function as oracle" fits |
| **Agentic RE survey** (Radey/West/Fawaz, arXiv 2604.14317) | Survey | Finds **no dynamic-only agents**; dynamic only in hybrids | Challenges: no guardrails (malicious binary can hijack host), **timeouts — slow LLM reasoning misses timing-sensitive behavior; anti-analysis timing checks**, emulation reliance, never-ending automation traps. Suggests **clock-control tools** |
| **Agentic Interpretation** (arXiv 2605.12694) | Lattice-structured evidence | — | Claims tracked in a finite-height lattice (supported/disputed/open) with worklist → model for BEA's observation/derivation/inference/unknown states |
| **Veritas** (arXiv 2605.15097) | Grounding agents for vuln reasoning over stripped binaries | (couldn't read body) | Grounding theme |
| Anti-dynamic-analysis in malware w/ LLM (arXiv 2411.05982) | LLM locates anti-debug code | static | Anti-debug detection is LLM-assistable |

---

## 12. Synthesis

### 12.1 The common tool set (what "everyone" exposes)
1. Discovery: list devices/processes/apps; spawn (suspended) / attach / resume / detach / kill.
2. Session mgmt: open → `session_id`; list; status; close. (Better ones: worker process per target.)
3. Modules: enumerate modules/exports/imports/symbols; resolve address↔symbol; module base.
4. Memory: read (hex/typed), write (gated), protect, regions/maps, AOB pattern scan.
5. Breakpoints: set/list/delete/enable; conditional; (sometimes HW/memory).
6. Execution control: continue, step into/over/out, run-to, interrupt/break-in.
7. State: registers, backtrace, threads, disassemble, evaluate expression.
8. Hooks (Frida): onEnter/onLeave JS, replace return value; message buffer + `get_messages`.
9. Escape hatch: raw `execute_command` / `execute_script`.
10. Crash: dump triage (`!analyze -v`).

### 12.2 Best ideas worth borrowing (with source)
- **Worker-process-per-target isolation** so target crashes / wedged engines don't take down the server
  (glslang/windbg-mcp, ida-pro-mcp idalib workers, Undo replay processes, GhostMCP "agent small, host heavy").
- **Async execution protocol**: `continue_async` → handle; `wait_for_stop(handle, timeout)` where timeout is a
  *poll not a failure*; "**a stop is read, not taken**"; stop reasons enum (`breakpoint|exception|interrupted|
  timed_out|target_gone`); target-reading tools refused with `target_running` while running; `max_run_ms`
  (glslang). Plus `trigger_and_wait` (frida-mobile-mcp) and `wait` seconds (frida-mcp.ts).
- **`debug_batch`**: ordered steps + assertions + rollback in one call (glslang) — cuts round trips.
- **Counts-first, results-by-handle**: scans return `count`, results paged by `offset/limit` (CE bridge,
  PyMemoryEditor "40,000 hits for a few tokens"), named persistent scans (CE bridge), stability scores for pointer
  rescans (GhostMCP).
- **Non-breaking HW breakpoints that log hits** (`capture_registers`, `capture_stack`, `stack_depth`) and
  `get_breakpoint_hits(id, clear)` (CE bridge) — exactly "what writes this address".
- **Walk-back recipe** as a documented workflow: watch writes → analyze accessing instruction → derive struct
  base → scan for pointers → validate chains (CE bridge).
- **Ring-buffer event pipeline with explicit backpressure policy** (drop-oldest / block / sample), server-side
  filters, per-API stats (GhostMCP API tracing). Report drops in coverage/limitations.
- **Evidence envelope** w/ `evidence_id`, `coverage{status, truncated, next_offset}`, `limitations[]`,
  `raw_result`, `provenance` untrusted, `effects` flags, `suggested_next`, persisted evidence store + export
  bundle, `details.partial_observation` on error (frida-mobile-mcp — already REA-aligned).
- **Effect flags & opt-in gates** (`executesForeignCode`, `mutatesTarget`, `writesFilesystem`; memory write,
  custom scripts, native injection, shell all default-off) — frida-mobile-mcp, r2mcp (`readonly`, `sandbox`,
  `yolo`, `approve`), Ipiano `gdb_call_function` as its own permissionable tool, GhostMCP scopes + TTL tokens +
  `patch_preview/undo`, sarks0 fail-closed raw-command allowlists, WinDbg Secure Mode.
- **Token budget as CI-tested contract** (glslang): per-tool result ceilings, surface size golden file, strip
  prose from `outputSchema`, `structuredContent ≤ 20× text`, default-trim vector registers.
- **Tool-surface profiles**: `--tools group,...` (glslang), `FRIDA_MCP_TOOL_PROFILE=core` +
  `FRIDA_MCP_SCHEMA_PROFILE=compact` (17% of full), lazy `load_tool_group` (bethington), mega-tools with `action`
  enum (bromoket), split into multiple servers (GhostMCP). REA itself has profiles (BELIEVED from task context).
- **Token-dense output formats**: TOON (frida-mobile-mcp default, pwndbg-mcp).
- **Address convention `module+0xOFFSET`** + "hook by evidence" `{module, address, image_base}` →
  automatic rebasing (frida-mobile-mcp); `debugger_static_to_dynamic` / `_dynamic_to_static` (bethington).
- **Run analysis scripts next to the data and return only results** (Undo Python API) — e.g., BEA hook/stalker
  reducers run in-agent (Frida JS) and send aggregates, not raw events.
- **Human observability**: WinDbg logs all AI actions in UI; mcp-debugger `expose_session` + transcript resource;
  glslang `server_log` + JSONL transcript; pwndbg-mcp's complaint that user "can not observe gdb status".
- **Redaction filter hook** (`--filter-script`, svnscha) and transcript masking (glslang).
- **Prompt-injection stance**: target-derived strings are untrusted; WinDbg classifies output via sampling.
- **Honest limitations docs** with sound vs best-effort verdicts (glslang).
- **Skills/prompts as workflow carriers** (Diagnostician skill, karellen `/rr-debug`, ya-frida prompts,
  frida-stalker-skills) rather than more tools.

### 12.3 Gaps nobody fills well (BEA opportunity)
| Gap | State of the art | BEA angle |
|---|---|---|
| **Evidence/provenance for dynamic facts** | frida-mobile-mcp envelope (mobile); glslang "evidence not verdicts"; Project Ire chain-of-evidence (closed research) | Use REA's exact envelope; every runtime fact carries pid, process start time, module path+hash+base, thread id, timestamp, capture method, sampling/truncation, and observation vs derivation tags |
| **Iterative CE-style scans** | CE bridge (needs Cheat Engine + Lua), GhostMCP (injected DLL, experimental), frida-game-hacking (single global scan) | Native Frida-based scan *handles*, all value types incl. float-epsilon, unknown-initial, relative ops, results server-side, snapshots persisted as artifacts |
| **Hardware watchpoints ("what writes")** | CE bridge (CE debugger/DBVM), GhostMCP, bromoket x64dbg (HW BPs) | Frida-based or native debug-register watch with non-breaking hit log + writer instruction disasm + module+offset + static address mapping |
| **Coverage export (drcov)** | none via MCP; `stalker-coverage` library | Stalker block coverage → drcov v2 file + summary (blocks/functions hit per module), loadable into Lighthouse/Cartographer/REA |
| **Static↔runtime mapping** | bethington GUI-only; ida-pro-mcp #449 rejected; frida-mobile `module+offset` | First-class rebasing against REA/Ghidra project image base; bidirectional; batch; returns both forms on *every* address output |
| **Emulation-based differential testing** | Unicorn MCP (raw), Ghidra `emulate_function` (P-code) | Run function in Unicorn (from static bytes or live dump) and in-process via `NativeFunction` with identical inputs; diff outputs/memory side effects; report divergences as evidence |
| **Calling target functions as oracles** | GhostMCP (calling conventions), CE `execute_method`, Ipiano `gdb_call_function` | Structured `call_function(address|module+off, abi, args typed, buffers)` with side-effect capture, thread choice, timeout, gated by effect flag |
| **Behavior summaries** | GhostMCP "AI-oriented summaries", WinDbg Diagnostician | Aggregate hook/trace evidence into per-function behavior profiles (arg ranges, call counts, callers, return distribution), clearly marked as derivations |
| **Recording then query** | TTD/Undo/rr (not on BEA host) | Bounded recordings (hook logs, stalker traces) saved as artifacts with query tools (first/last write, calls with predicate), so analysis is re-queryable and citable |
| **Desktop Windows Frida with structure** | All rich Frida MCPs are mobile; desktop ones are thin | BEA = the structured *desktop* Frida server |
| **Binary Ninja debugger via MCP** | none | out of scope (but BEA's address model should be tool-agnostic) |

### 12.4 Pitfalls (observed in the wild) and mitigations
- **Context bloat** — raw debugger text (pwndbg-mcp author gave up and recommends tmux; x64dbgMCP suggests a
  compression proxy; glslang measured `execute lm` = 19 KB). *Mitigate*: bounded structured results, counts +
  pages, artifacts on disk for bulk (dumps, traces, drcov), TOON/compact rendering, CI token ceilings.
- **Tool-count limits** — Gemini rejects 209 tools; clients cap ~90–100 (GhostMCP); frida-mobile full surface
  247 KB. *Mitigate*: profiles, action-enum mega-tools where cohesive, lazy groups.
- **Blocking calls** — GDB busy while running (Ipiano), LLDB async-mode surprises, CE `generate_signature` blocks
  the pipe for minutes, ida-pro-mcp #217 main-thread deadlock, GhidraMCP modal dialogs hang requests, SSE
  "context deadline exceeded" (AgentSmithers). *Mitigate*: async handles + poll waits, per-call deadlines that
  abandon the wait not the job, cancellation, progress notifications, MCP Tasks extension
  (`io.modelcontextprotocol/tasks`, now an *extension* in spec 2026-07-28, client support varies — design so
  polling tools work without it).
- **Target crashes taking down server** — `SESSION_LOST` (frida-mobile), x64dbg crashing on blocked DLLs or
  malformed HTTP (fixed in bromoket v2.3.0), "a killed debugger can take its attached processes with it"
  (glslang). *Mitigate*: Frida runs in-target but BEA host must survive `detached` events (Frida `session.on
  ('detached', reason, crash)` gives crash report — BELIEVED), record crash as evidence, `recent_detaches` in
  status, auto-reattach option only for spawned targets.
- **Ctrl-C / interrupt killing target** (pwndbg-mcp). *Mitigate*: never use console signals; use API break-in.
- **Bool success that means "submitted"** (AgentSmithers). *Mitigate*: every mutating tool returns verified
  post-state (read-back).
- **Persistent breakpoints confusing LLM** (Undo). *Mitigate*: hooks/watches have explicit lifetimes (duration_ms,
  max_hits) and results arrive in the same call or by handle; list active instrumentation in every status.
- **Event floods** — Stalker/hook storms. *Mitigate*: in-agent aggregation, sampling, max_events, ring buffer w/
  declared policy, report `dropped` counts in coverage.
- **Anti-debug / anti-Frida** — crashes after hooking (frida-mobile), WinDbg/x64dbg detection; CE uses DBVM to
  be invisible; sarks0 & bromoket have anti-debug hiding tools; survey notes timing checks vs slow LLM reasoning.
  *Mitigate*: detect & report (PEB.BeingDebugged, NtGlobalFlag, timing) as evidence; don't promise stealth;
  keep instrumentation short-lived; hooks that run without LLM round-trips.
- **Port collisions** — bromoket uses 127.0.0.1:27042 = Frida's default port. Avoid fixed ports.
- **Version skew** — frida-server/frida-node major/minor mismatch (frida-mobile, dnakov), Ghidra exact version
  lock. *Mitigate*: doctor/check_installation tool; pin frida.
- **Device pinning bugs** — dnakov #1 enumerated the wrong device. *Mitigate*: explicit target identity in every
  response.
- **Prompt injection via target memory** (Microsoft cross-prompt-injection protection; glslang escapes rendered
  names). *Mitigate*: mark target-derived strings untrusted; escape in text rendering.
- **Admin/kernel temptations & BSOD** (CE DBK/DBVM, kernel attach). *Mitigate*: user-mode only for BEA v1.
- **Unsafe defaults** — listening on 0.0.0.0 (AgentSmithers), no auth HTTP (bethington, svnscha).
  *Mitigate*: stdio default; HTTP loopback + token.

---

## 13. Concrete recommendations for BEA's surface (derived)

(Names are suggestions; reconcile with REA naming conventions — REA tools are snake_case verbs, e.g.
`start_frida_session`, `instrument_with_frida` in `src/contracts/fridaToolContracts.ts:118,256` — VERIFIED-LOCAL.)

1. **Session**: `spawn_process(path,args,suspended)`, `attach_process(pid)` (only to pids the user names; record
   that BEA did not start it), `resume`, `detach`, `kill_spawned` (refuse to kill non-spawned), `session_status`
   (instrumentation inventory, recent detaches/crashes, budgets).
2. **Inspect**: `list_modules` (with path, base, size, sha256, image_base_static from PE header → rebase delta),
   `list_exports/imports`, `memory_map`, `read_memory` (typed views, ≤N bytes, hexdump + ascii), `disassemble`.
3. **Address mapping**: `map_address({static: {project/module, va}} | {runtime: addr} | "module+0xoff")` →
   returns all three forms + provenance of the base used. Every other tool echoes both forms.
4. **Scan**: `scan_start(type, value|unknown, region filter)` → `{scan_id, count}`; `scan_next(scan_id, op)`;
   `scan_results(scan_id, offset, limit)`; `scan_close`. Snapshots stored on disk.
5. **Watch**: `watch_memory(address, size, access=w|rw|x, duration_ms, max_hits)` → hits with thread, pc,
   module+off, static addr, disasm, regs subset, value before/after.
6. **Hook**: `hook_function(target, abi, arg_specs (typed, deref rules), capture_return, duration_ms,
   max_calls, sample)` → per-call frame records (ADI "frame lifetime trace" idea) + aggregate summary.
7. **Trace/coverage**: `trace_calls(thread|all, duration_ms, filters)` and `coverage_capture(modules,
   duration_ms)` → drcov file artifact + per-function hit summary; async via handle.
8. **Call**: `call_function(target, abi, args, buffers, timeout_ms)` gated as `executesForeignCode`.
9. **Emulate**: `emulate_function(source: static bytes | live dump, inputs)` and `diff_emulation_vs_runtime`.
10. **Crash**: exception/crash capture as evidence (Frida `Process.setExceptionHandler` + detach crash report).
11. **Dump**: `dump_module` / `dump_region` to artifact with hashes.
12. **Async plumbing**: every long op returns a handle; `wait(handle, timeout_ms)` is a poll; `cancel(handle)`.

---

## 14. Source list (fetched this session)
- https://github.com/dnakov/frida-mcp , https://github.com/dnakov/frida-mcp/issues
- https://mcp.directory/blog/frida-mcp-complete-guide-2026
- https://github.com/nonsleepr/frida-mcp.ts
- https://github.com/monkeywave/frida-mobile-mcp (+ docs/rea.md, docs/interop.md)
- https://github.com/0xhackerfren/frida-game-hacking-mcp
- https://github.com/1shin-7/ya-frida-mcp
- https://glama.ai/mcp/servers/dryfryce/frida-mcp (directory)
- https://github.com/Wasdubya/x64dbgMCP , https://github.com/AgentSmithers/x64DbgMCPServer , https://github.com/bromoket/x64dbg_mcp
- https://github.com/svnscha/mcp-windbg
- https://devblogs.microsoft.com/performance-diagnostics/?p=935 (Microsoft WinDbg MCP, 2026-10-06)
- https://glama.ai/mcp/servers/mjpdckr94z + https://github.com/glslang/windbg-mcp docs/token-budget.md, docs/limitations.md, docs/sessions.md
- https://github.com/tonyredondo/debugger-mcp-server
- https://github.com/Ipiano/gdb-mcp , https://github.com/RocketMaDev/pwndbg-mcp , https://github.com/pwno-io/pwno-mcp
- https://lldb.llvm.org/use/mcp.html
- https://github.com/mrexodia/ida-pro-mcp (+ issues #441, #449, search "debugger")
- https://github.com/fosdickio/binary_ninja_mcp
- https://github.com/bethington/ghidra-mcp , https://github.com/themixednuts/GhidraMCP
- https://github.com/radareorg/radare2-mcp
- https://github.com/miscusi-peek/cheatengine-mcp-bridge (+ AI_Context/MCP_Bridge_Command_Reference.md)
- https://github.com/mq1n/GhostMCP
- https://github.com/jeanextreme002/PyMemoryEditor
- https://github.com/sarks0/binary-mcp (+ docs/tools.md, docs/security.md)
- https://github.com/debugmcpdev/mcp-debugger
- https://docs.undo.io/java/MCPServer.html ; https://community.mindstone.com/annotate/article_AyG7iCkEkU8X3fRGk5
- https://modelcontextprotocol.io/extensions/tasks
- arXiv: 2409.16165 (EnIGMA), 2604.14317 (survey), 2604.15136 (FORGE), 2605.10597 (CrackMeBench),
  2604.24212 (ADI), 2605.12694 (Agentic Interpretation); Project Zero Naptime post; Microsoft Research Project Ire blog.
