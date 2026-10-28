#!/usr/bin/env node
// scripts/verify-frida-windows.mjs (WP18-INT; DESIGN §10.2 "receipts", S6 §10.3, rea-testing §11.6): the real-Frida
// receipt lane. Run it through `npm run verify:frida:windows` (build and fixtures first). For each check it runs the
// same operation twice against the BUILT package (BEA_DIST_DIR when set, a snapshot from scripts/snapshot-dist.mjs;
// else the repository's dist/):
//   cli  a one-shot `node <dist>/../scripts/bea.mjs <command> … --json` in its own throwaway home (spawning its own
//        target, which the command kills when it ends)
//   mcp  the same tool over one `bea mcp` stdio server (its own home, its own target)
// and compares their POINTER-FREE projections (module+RVA, static VAs, bytes, decoded values, counts that do not depend
// on timing): the two surfaces share one invocation pipeline, so any difference is a CLI mapping bug (argv → input,
// spawn/attach target handling, output document). Checks: symbols and map offline (--pe-path); modules, read, disasm,
// call and dump of a spawned game_sim; a hook one-shot (installed before resume) and trace_api on behavior.exe; and,
// with Python + unicorn, `emulate` against emu_open + emu_call. Hygiene: the server exits 0 and no target, jobhost or
// bridge process started here outlives the run.
// One JSON receipt (schema bea.verify-frida-windows/1) goes to stdout, or to --out <file>; progress goes to stderr.
// Exit 0: every check passed. 1: a check failed. 2: nothing failed but checks were skipped (named reasons only).
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import { buildFixtures } from "./lib/fixtures.mjs";
import { parsePe } from "./lib/peParse.mjs";

const RECEIPT_SCHEMA = "bea.verify-frida-windows/1";
const CLI_TIMEOUT_MS = 180_000;

// ------------------------------------------------------------------------------------------------- arguments
const argv = process.argv.slice(2);
if (argv.includes("--help")) {
  process.stdout.write("usage: node scripts/verify-frida-windows.mjs [--out <receipt.json>]\n");
  process.exit(0);
}
const outAt = argv.indexOf("--out");
const outPath = outAt >= 0 ? argv[outAt + 1] : undefined;
if ((outAt >= 0 && (outPath === undefined || outPath.startsWith("--"))) || argv.length !== (outAt >= 0 ? 2 : 0)) {
  process.stderr.write(`verify-frida-windows: bad arguments ${JSON.stringify(argv)}; see --help\n`);
  process.exit(64);
}
const log = (line) => process.stderr.write(`[verify-frida-windows] ${line}\n`);

// ------------------------------------------------------------------------------------------------- layout
const override = process.env.BEA_DIST_DIR;
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = override !== undefined && override !== "" ? resolve(override) : join(REPO, "dist");
const dispatcher = join(dirname(distRoot), "scripts", "bea.mjs");
const jobhostExe = join(distRoot, "native", "win32-x64", "bea-jobhost.exe");
const TASKLIST = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tasklist.exe");

class CheckFailed extends Error {}
const expect = (condition, message) => {
  if (!condition) throw new CheckFailed(message);
};
const canonical = (value) => JSON.stringify(value, (_key, v) => (typeof v === "bigint" ? v.toString() : v));
const same = (cli, mcp, label) =>
  expect(
    canonical(cli) === canonical(mcp),
    `${label}: CLI ${canonical(cli).slice(0, 1500)} ≠ MCP ${canonical(mcp).slice(0, 1500)}`,
  );
const hex = (n) => `0x${BigInt(n).toString(16)}`;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// ------------------------------------------------------------------------------------------------- prerequisites
const fridaReason = () => {
  if (process.platform !== "win32" || process.arch !== "x64")
    return `FRIDA_SKIP: the receipt needs Windows x64 (host is ${process.platform}-${process.arch})`;
  try {
    let dir = dirname(createRequire(import.meta.url).resolve("frida"));
    while (!existsSync(join(dir, "package.json")) && dirname(dir) !== dir) dir = dirname(dir);
    const binding = join(dir, "build", "frida_binding.node");
    return existsSync(binding) ? false : `FRIDA_SKIP: the frida binding is missing (${binding})`;
  } catch (cause) {
    return `FRIDA_SKIP: the frida package is not installed (${String(cause)})`;
  }
};
const jobhostReason = () => {
  if (!existsSync(jobhostExe)) return `JOBHOST_SKIP: ${jobhostExe} is missing; run npm run build`;
  const probe = spawnSync(jobhostExe, ["probe"], { encoding: "utf8", windowsHide: true, timeout: 15_000 });
  return probe.status === 0 && /"ok"\s*:\s*true/u.test(probe.stdout)
    ? false
    : `JOBHOST_SKIP: ${jobhostExe} probe failed`;
};
const pythonInfo = () => {
  const command = process.env.BEA_PYTHON ?? "python";
  const probe = spawnSync(
    command,
    ["-I", "-c", "import sys, unicorn, capstone, pefile; print(sys.executable); print(unicorn.__version__)"],
    {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30_000,
    },
  );
  if (probe.status !== 0) return { skip: `EMU_SKIP: no Python with unicorn/capstone/pefile (${command})` };
  const [executable = "", unicorn = ""] = probe.stdout.trim().split(/\r?\n/u);
  return unicorn.startsWith("2.1.")
    ? { skip: false, executable: executable.trim() }
    : { skip: `EMU_SKIP: unicorn ${unicorn} is not 2.1.x` };
};

// ------------------------------------------------------------------------------------------------- receipt
const checks = [];
const startedAt = new Date().toISOString();
const has = new Set();
const reasons = new Map();
const check = async (id, needs, run) => {
  const missing = needs.find((need) => !has.has(need));
  if (missing !== undefined) {
    const reason = reasons.get(missing) ?? `PREREQUISITE: ${missing} is not available`;
    checks.push({ id, status: "skip", reason });
    log(`skip ${id}: ${reason}`);
    return;
  }
  const started = performance.now();
  try {
    const detail = await run();
    const ms = Math.round(performance.now() - started);
    checks.push({ id, status: "pass", ms, ...(detail === undefined ? {} : { projection: detail }) });
    log(`pass ${id} (${ms} ms)`);
  } catch (cause) {
    const ms = Math.round(performance.now() - started);
    const message = cause instanceof Error ? cause.message : String(cause);
    checks.push({ id, status: "fail", ms, error: message.slice(0, 4000) });
    log(`FAIL ${id}: ${message.slice(0, 600)}`);
  }
};

// ------------------------------------------------------------------------------------------------- setup
if (!existsSync(dispatcher) || !existsSync(join(distRoot, "main", "mcp.js"))) {
  process.stderr.write(
    `verify-frida-windows: no built package at ${distRoot}; run npm run build (or set BEA_DIST_DIR)\n`,
  );
  process.exit(1);
}
const manifest = await buildFixtures();
const fixtures = "unavailable" in manifest ? null : manifest.artifacts;
if (fixtures === null) reasons.set("fixtures", `GCC_SKIP: ${manifest.unavailable}`);
else has.add("fixtures");
const liveReason = fridaReason() || jobhostReason();
if (liveReason === false) has.add("live");
else reasons.set("live", liveReason);
const python = pythonInfo();
if (python.skip === false) has.add("emu");
else reasons.set("emu", python.skip);

const root = await mkdtemp(join(tmpdir(), "bea-verify-frida-"));
const passThrough = [
  "SystemRoot",
  "SystemDrive",
  "windir",
  "ComSpec",
  "PATHEXT",
  "NUMBER_OF_PROCESSORS",
  "PROCESSOR_ARCHITECTURE",
  "OS",
].filter((name) => process.env[name] !== undefined);
/** A throwaway home (HOME/APPDATA/LOCALAPPDATA/TEMP/BEA_HOME inside `root`); never the user's own BEA_HOME. */
const makeHome = async (label) => {
  const base = join(root, label);
  const dirs = {
    home: join(base, "home"),
    appData: join(base, "home", "AppData", "Roaming"),
    localAppData: join(base, "home", "AppData", "Local"),
    temp: join(base, "tmp"),
    beaHome: join(base, "bea-home"),
    work: join(base, "work"),
  };
  await Promise.all(Object.values(dirs).map((dir) => mkdir(dir, { recursive: true })));
  const env = {
    PATH: process.env.PATH ?? "",
    ...Object.fromEntries(passThrough.map((name) => [name, process.env[name]])),
    HOME: dirs.home,
    USERPROFILE: dirs.home,
    APPDATA: dirs.appData,
    LOCALAPPDATA: dirs.localAppData,
    TEMP: dirs.temp,
    TMP: dirs.temp,
    BEA_HOME: dirs.beaHome,
    BEA_LOG_LEVEL: "warn",
    PYTHON_MANAGER_AUTOMATIC_INSTALL: "false",
    ...(python.skip === false ? { BEA_PYTHON: python.executable } : {}),
  };
  return { ...dirs, env };
};

/** Process ids of every running image with one of these names (tasklist; for the hygiene check). */
const pidsNamed = (names) => {
  const pids = new Set();
  for (const name of names) {
    const run = spawnSync(TASKLIST, ["/FI", `IMAGENAME eq ${name}`, "/FO", "CSV", "/NH"], {
      encoding: "utf8",
      windowsHide: true,
    });
    for (const m of run.stdout.matchAll(/^"[^"]*","(\d+)"/gmu)) pids.add(Number(m[1]));
  }
  return pids;
};
const WATCHED = ["game_sim.exe", "behavior.exe", "bea-jobhost.exe"];
const before = pidsNamed(WATCHED);

let cliHome;
const cli = async (command, args, target = []) => {
  cliHome ??= await makeHome("cli");
  const full = [dispatcher, ...command, ...args, "--json", ...(target.length > 0 ? target : [])];
  const run = spawnSync(process.execPath, full, {
    cwd: cliHome.work,
    env: cliHome.env,
    encoding: "utf8",
    windowsHide: true,
    timeout: CLI_TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (run.error !== undefined) throw new CheckFailed(`bea ${command.join(" ")}: ${String(run.error)}`);
  let doc;
  try {
    doc = JSON.parse(run.stdout);
  } catch {
    throw new CheckFailed(
      `bea ${command.join(" ")} exit ${String(run.status)}: no JSON document\n${run.stdout.slice(0, 800)}\n${run.stderr.slice(-1500)}`,
    );
  }
  expect(
    run.status === 0,
    `bea ${command.join(" ")} exit ${String(run.status)}: ${run.stdout.slice(0, 1500)}\n${run.stderr.slice(-1500)}`,
  );
  return doc;
};

let mcp = null;
const mcpServer = async () => {
  if (mcp !== null) return mcp;
  const home = await makeHome("mcp");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [dispatcher, "mcp"],
    env: home.env,
    cwd: home.work,
    stderr: "pipe",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => (stderr += chunk.toString()));
  const client = new Client({ name: "bea-verify-frida-windows", version: "1" });
  await client.connect(transport);
  const child = transport._process;
  const exited = new Promise((done) => {
    if (child === undefined) done({ code: null });
    else child.once("exit", (code) => done({ code }));
  });
  const sessions = [];
  const call = async (name, args) => {
    const result = await client.callTool({ name, arguments: args }, { timeout: CLI_TIMEOUT_MS });
    const text = result.content?.[0]?.text ?? "";
    expect(result.isError !== true, `MCP ${name}: ${text.slice(0, 1500)}`);
    if (name === "spawn_process" || name === "emu_open") sessions.push(result.structuredContent.session_id);
    return result.structuredContent;
  };
  mcp = { client, call, sessions, exited, stderr: () => stderr, pid: transport.pid };
  return mcp;
};
/** spawn_process + resume_process + READY on the MCP side (the CLI one-shot spawns and resumes its own). */
const mcpGame = async (args = ["--no-threads", "--speed", "20", "--throttle", "0.125"]) => {
  const server = await mcpServer();
  const spawned = await server.call("spawn_process", { program: fixtures.game_sim.path, args });
  const id = spawned.session_id;
  await server.call("resume_process", { session_id: id });
  await server.call("wait", { session_id: id, until: "output", output_contains: "READY", timeout_ms: 15_000 });
  return id;
};
const closeMcp = async (id) => {
  await mcp.call("close_session", { session_id: id });
  mcp.sessions.splice(mcp.sessions.indexOf(id), 1);
};

// ------------------------------------------------------------------------------------------------- projections
const symbolRows = (doc) =>
  doc.rows
    .map((r) => ({ name: r.name ?? null, rva: r.rva ?? null, kind: r.kind ?? null, size: r.size ?? null }))
    .sort((a, b) => canonical(a).localeCompare(canonical(b)));
const mapRows = (doc) =>
  doc.rows.map((r) => ({
    input: r.input ?? null,
    status: r.status,
    module: r.address?.module ?? null,
    rva: r.address?.rva ?? null,
    static_va: r.address?.static_va ?? null,
    func: r.func ?? null,
    image_check: r.image_check ?? null,
  }));
const mainModule = (doc) => {
  const main = doc.rows.find((r) => r.main === true);
  return {
    name: main?.name,
    size: main?.size,
    preferred_base: main?.preferred_base,
    path: main?.path?.toLowerCase() ?? null,
    ntdll: doc.rows.some((r) => r.name?.toLowerCase() === "ntdll.dll"),
  };
};
const readProjection = (doc) => ({
  module: doc.address.module,
  rva: doc.address.rva,
  complete: doc.complete,
  returned: doc.returned,
  text: doc.text ?? null,
  values: doc.values ?? null,
});
const disasmRows = (doc) => doc.rows.map((r) => ({ rva: r.rva, b: r.b, t: r.t, ref: r.ref ?? null }));
/**
 * The recording digest of a CLI instrument document. Review fix ONBOARD-7: the CLI prints it once, as the
 * `query_events {view:"summary"}` result under `summary` (whose digest is its top-level `summary`); the wait result's
 * recordings no longer carry a copy. Older documents carried it on the recordings.
 */
const digestOf = (doc, kind) =>
  doc.summary?.summary ??
  (kind === undefined ? doc.wait?.recordings?.[0] : doc.wait?.recordings?.find((r) => r.kind === kind))?.summary ??
  doc.summary;

const hookProjection = (summary) => ({
  callers: (summary.callers ?? []).map((c) => c.at),
  threads: (summary.threads ?? []).length,
  dt: { min: summary.fields?.dt?.min, max: summary.fields?.dt?.max, distinct: summary.fields?.dt?.distinct },
  returns: { min: summary.returns?.min, max: summary.returns?.max, distinct: summary.returns?.distinct },
  read_failures: summary.read_failures,
});
const fileRows = (summary, outDir) =>
  (summary.file?.rows ?? [])
    .filter((r) => r.path.toLowerCase().startsWith(outDir.toLowerCase()))
    .map((r) => ({
      leaf: r.path.slice(outDir.length).replace(/^\\/u, ""),
      kind: r.kind,
      ops: [...r.ops].sort(),
      read_bytes: r.read_bytes ?? 0,
      write_bytes: r.write_bytes ?? 0,
      failed: r.failed,
      first_status: r.first_status ?? null,
    }))
    .sort((a, b) => a.leaf.localeCompare(b.leaf));
/** The code section of a PE file on disk: its rva and the bytes the loader maps from the file. */
const codeSectionOf = (bytes) => {
  const text = parsePe(bytes).sections.find((s) => (s.characteristics & 0x20000000) !== 0);
  if (text === undefined) throw new CheckFailed("no code section in the PE file");
  const length = Math.min(text.rawSize, text.virtualSize);
  return { rva: text.rva, bytes: bytes.subarray(text.rawOffset, text.rawOffset + length) };
};
/** A pe_realigned dump (file offset = rva): headers, base and the code section compared with the on-disk image. */
const dumpProjection = async (doc, onDisk) => {
  const bytes = await readFile(doc.path);
  const pe = parsePe(bytes);
  const code = codeSectionOf(onDisk);
  const dumpedCode = bytes.subarray(code.rva, code.rva + code.bytes.length);
  return {
    format: doc.format,
    layout: doc.layout,
    image_base_in_file: doc.image_base_in_file,
    module: doc.module?.name,
    rebased_to: doc.module?.rebased_to,
    pe_image_base: pe.imageBase,
    sections: pe.sections.map((s) => s.name),
    code_equals_file: dumpedCode.equals(code.bytes),
    code_sha256: sha256(dumpedCode),
  };
};

// ------------------------------------------------------------------------------------------------- checks
const GAME_ARGS = ["--no-threads", "--speed", "20", "--throttle", "0.125"];
if (fixtures !== null) {
  const game = fixtures.game_sim;
  const physics = game.pe.exportRvas.physics_step;
  const staticPhysics = hex(BigInt(game.pe.imageBase) + BigInt(physics) + 0x10n);

  await check("symbols.offline", ["fixtures"], async () => {
    const c = await cli(["symbols"], ["--pe-path", game.path, "--filter", "physics_step"]);
    const m = await (await mcpServer()).call("list_module_symbols", { pe_path: game.path, filter: "physics_step" });
    same(symbolRows(c), symbolRows(m), "list_module_symbols rows");
    expect(
      symbolRows(m).some((r) => r.name === "physics_step" && r.rva === hex(physics)),
      "physics_step export row",
    );
    return symbolRows(m);
  });

  await check("map.offline", ["fixtures"], async () => {
    const c = await cli(["map"], [`game_sim.exe:${staticPhysics}`, "--pe-path", game.path]);
    const m = await (
      await mcpServer()
    ).call("map_address", { pe_path: game.path, addresses: [`game_sim.exe:${staticPhysics}`] });
    same(mapRows(c), mapRows(m), "map_address rows");
    expect(mapRows(m)[0]?.func?.is_start === false, "the static VA maps inside physics_step");
    return mapRows(m);
  });

  await check("modules.live", ["fixtures", "live"], async () => {
    const c = await cli(["modules"], [], ["--spawn", game.path, "--", ...GAME_ARGS]);
    const id = await mcpGame();
    const m = await mcp.call("list_modules", { session_id: id });
    await closeMcp(id);
    same(mainModule(c), mainModule(m), "main module row");
    return mainModule(m);
  });

  await check("read.live", ["fixtures", "live"], async () => {
    const c = await cli(
      ["read"],
      ["game_sim.exe!g_marker", "22", "--view", "utf8"],
      ["--spawn", game.path, "--", ...GAME_ARGS],
    );
    const id = await mcpGame();
    const m = await mcp.call("read_memory", {
      session_id: id,
      address: "game_sim.exe!g_marker",
      size: 22,
      view: "utf8",
    });
    await closeMcp(id);
    same(readProjection(c), readProjection(m), "read_memory");
    expect(readProjection(m).text === "BEA_GAME_SIM_MARKER_v1", "the marker text");
    return readProjection(m);
  });

  await check("disasm.live", ["fixtures", "live"], async () => {
    const c = await cli(
      ["disasm"],
      ["game_sim.exe!physics_step", "--function"],
      ["--spawn", game.path, "--", ...GAME_ARGS],
    );
    const id = await mcpGame();
    const m = await mcp.call("disassemble", { session_id: id, address: "game_sim.exe!physics_step", function: true });
    await closeMcp(id);
    same(disasmRows(c), disasmRows(m), "disassemble rows");
    const writer = game.expectations.speedWriters[0];
    expect(
      disasmRows(m).some((r) => r.rva === hex(writer.rva)),
      "the manifest speed writer row",
    );
    return { rows: disasmRows(m).length, first: disasmRows(m)[0] };
  });

  await check("call.live", ["fixtures", "live"], async () => {
    const request = {
      signature: { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" },
      vectors: { columns: { arg0: [1, 2, -7], arg1: [10, 20, 7] } },
    };
    const requestFile = join(root, "call-request.json");
    await writeFile(requestFile, JSON.stringify(request));
    const c = await cli(
      ["call"],
      ["game_sim.exe!tiny_add", "--input", requestFile],
      ["--spawn", game.path, "--", ...GAME_ARGS],
    );
    const id = await mcpGame();
    const m = await mcp.call("call_function", { session_id: id, address: "game_sim.exe!tiny_add", ...request });
    await closeMcp(id);
    const projection = (doc) => ({ status: doc.batch.columns.status ?? null, ret: doc.batch.columns.ret });
    same(projection(c), projection(m), "call_function batch");
    return projection(m);
  });

  await check("dump.live", ["fixtures", "live"], async () => {
    const c = await cli(
      ["dump"],
      ["game_sim.exe", "--rebase-to", "preferred", "--keep-run"],
      ["--spawn", game.path, "--", ...GAME_ARGS],
    );
    const id = await mcpGame();
    const m = await mcp.call("dump_memory", { session_id: id, module: "game_sim.exe", rebase_to: "preferred" });
    await closeMcp(id);
    const onDisk = await readFile(game.path);
    const [pc, pm] = [await dumpProjection(c, onDisk), await dumpProjection(m, onDisk)];
    same(pc, pm, "dump_memory pe_realigned");
    expect(pm.code_equals_file, "the dump's code section equals the file's (original bytes restored)");
    return pm;
  });

  await check("hook.oneshot", ["fixtures", "live"], async () => {
    const c = await cli(
      ["hook"],
      ["game_sim.exe!physics_step", "--capture", "dt=arg1:f32", "--returns", "f32", "--duration-ms", "1500"],
      ["--spawn", game.path, "--", ...GAME_ARGS],
    );
    const cliSummary = digestOf(c);
    const server = await mcpServer();
    const spawned = await server.call("spawn_process", { program: game.path, args: GAME_ARGS });
    const id = spawned.session_id;
    const hooked = await server.call("hook_function", {
      session_id: id,
      address: "game_sim.exe!physics_step",
      capture: [{ name: "dt", arg: 1, type: "f32" }],
      returns: "f32",
      duration_ms: 1500,
    });
    const rec = hooked.instrument.recording_id;
    await server.call("resume_process", { session_id: id, wait_ms: 10_000, until: "instruments_done" });
    const queried = await server.call("query_events", { recording_id: rec, view: "summary" });
    await closeMcp(id);
    // review fix UX-2: query_events {view:"summary"} returns the digest once, at the top level
    const mcpSummary = queried.summary ?? queried.recording?.summary;
    same(hookProjection(cliSummary), hookProjection(mcpSummary), "hook summary (pointer-free)");
    expect(
      hookProjection(cliSummary).callers.every((at) => /^game_sim\.exe\+0x[0-9a-f]+$/u.test(at)),
      "callers are module+RVA",
    );
    return hookProjection(mcpSummary);
  });

  await check("trace_api.oneshot", ["fixtures", "live"], async () => {
    const behavior = fixtures.behavior.path;
    const cliOut = join(root, `behavior-cli-${randomBytes(3).toString("hex")}`);
    const mcpOut = join(root, `behavior-mcp-${randomBytes(3).toString("hex")}`);
    await mkdir(cliOut);
    await mkdir(mcpOut);
    const c = await cli(
      ["trace-api"],
      ["--profiles", "file", "--duration-ms", "20000"],
      ["--spawn", behavior, "--", "--out-dir", cliOut, "--steps", "file"],
    );
    const cliSummary = digestOf(c, "api");
    const server = await mcpServer();
    const spawned = await server.call("spawn_process", {
      program: behavior,
      args: ["--out-dir", mcpOut, "--steps", "file"],
    });
    const id = spawned.session_id;
    const traced = await server.call("trace_api", { session_id: id, profiles: ["file"], duration_ms: 20_000 });
    const resumed = await server.call("resume_process", { session_id: id, wait_ms: 20_000, until: "exit" });
    const api = resumed.instruments.find((i) => i.recording_id === traced.instrument.recording_id);
    await closeMcp(id);
    const [pc, pm] = [fileRows(cliSummary, cliOut), fileRows(api.summary, mcpOut)];
    same(pc, pm, "trace_api file rows (relative to --out-dir)");
    expect(
      pm.some((r) => r.leaf === "bea_behavior_a.txt" && r.write_bytes === 5),
      "bea_behavior_a.txt written",
    );
    return pm;
  });

  await check("emulate.oneshot", ["fixtures", "emu"], async () => {
    const mathlib = fixtures.mathlib.path;
    const request = {
      signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
      vectors: { columns: { arg0: [0, -1], arg1: [10, 1], arg2: [0.5, 0.25] } },
    };
    const requestFile = join(root, "emulate-request.json");
    await writeFile(requestFile, JSON.stringify(request));
    const c = await cli(["emulate"], ["--image", mathlib, "--address", "mathlib.dll!mf_lerp", "--input", requestFile]);
    const server = await mcpServer();
    const opened = await server.call("emu_open", { image_path: mathlib });
    const m = await server.call("emu_call", {
      session_id: opened.session_id,
      address: "mathlib.dll!mf_lerp",
      ...request,
    });
    await closeMcp(opened.session_id);
    const projection = (doc) => ({ ret: doc.batch.columns.ret, status: doc.batch.columns.status ?? null });
    same(projection(c), projection(m), "emu_call batch");
    return projection(m);
  });
}

// ------------------------------------------------------------------------------------------------- hygiene
await check("hygiene", [], async () => {
  if (mcp !== null) {
    for (const id of mcp.sessions.slice()) await mcp.call("close_session", { session_id: id }).catch(() => undefined);
    await mcp.client.close();
    const { code } = await mcp.exited;
    expect(code === 0, `the MCP server exited ${String(code)}\n${mcp.stderr().slice(-1500)}`);
  }
  const deadline = Date.now() + 10_000;
  let leftover = [];
  do {
    leftover = [...pidsNamed(WATCHED)].filter((pid) => !before.has(pid));
    if (leftover.length === 0) break;
    await new Promise((done) => setTimeout(done, 100));
  } while (Date.now() < deadline);
  expect(leftover.length === 0, `processes started by this run are still alive: ${leftover.join(", ")}`);
  return { server_exit: mcp === null ? null : 0, leftover: [] };
});

await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(() => undefined);
const failed = checks.filter((c) => c.status === "fail").length;
const skipped = checks.filter((c) => c.status === "skip").length;
const receipt = {
  schema: RECEIPT_SCHEMA,
  started_at: startedAt,
  finished_at: new Date().toISOString(),
  host: { platform: process.platform, arch: process.arch, node: process.versions.node },
  dist: distRoot,
  status: failed > 0 ? "fail" : skipped > 0 ? "skipped" : "pass",
  totals: { checks: checks.length, passed: checks.filter((c) => c.status === "pass").length, failed, skipped },
  checks,
};
const text = `${JSON.stringify(receipt, null, 2)}\n`;
if (outPath === undefined) process.stdout.write(text);
else await writeFile(outPath, text);
process.exit(failed > 0 ? 1 : skipped > 0 ? 2 : 0);
