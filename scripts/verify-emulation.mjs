#!/usr/bin/env node
// scripts/verify-emulation.mjs (WP14; S5 §14.1 `verify:emulation`, DESIGN §8.4): the serial emulation receipt lane.
// Run it through `npm run verify:emulation` (build and fixtures first). It starts the BUILT server over stdio
// (BEA_DIST_DIR when set, a snapshot from scripts/snapshot-dist.mjs; else the repository's dist/) with a throwaway
// home, the real bridge and the real Python (BEA_PYTHON, else `python` on PATH), and checks:
//   emulator  emu_open on mathlib.dll (identity, ISA report, FP defaults, the ISA cache on a second open) and on
//             bea_emu_fixture.dll; the bits-only goldens (tests/golden/emu/mathlib.json); bea_spring_damper over 64
//             vectors against a JS reference; #DE, the first VEX instruction, the instruction budget and the
//             CPUID-dispatched path; diff_function emulation vs expected (equivalent / differ + unknown / unknown)
//   live      (Frida, bea-jobhost and the live tools) the E6 parity set through diff_function live vs emulation:
//             four_floats under RN, FTZ+DAZ and RZ, mix_args, car_energy; bea_dispatch (differs with the
//             cpuid_dispatch hint and an unknown when the host has AVX2); dump-backed physics_step on the runtime g_car
//             (dump_memory -> emu_open {dump_path}) and the capture under a hook (emu_open {live_session_id}), each
//             equal to the live call
//   hygiene   the server exits 0; no bridge launcher or interpreter and no spawned target outlives it
// One JSON receipt (schema bea.verify-emulation/1) goes to stdout, or to --out <file>; progress goes to stderr.
// --no-live skips the live section by request. Exit 0: every check passed. 1: a check failed. 2: nothing failed but
// checks were skipped (named reasons only: a missing toolchain, a tool this build does not register, --no-live).
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";

import { buildFixtures } from "./lib/fixtures.mjs";

const RECEIPT_SCHEMA = "bea.verify-emulation/1";
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CALL_TIMEOUT_MS = 180_000;

// ------------------------------------------------------------------------------------------------- arguments
const argv = process.argv.slice(2);
if (argv.includes("--help")) {
  process.stdout.write("usage: node scripts/verify-emulation.mjs [--out <receipt.json>] [--no-live]\n");
  process.exit(0);
}
const outAt = argv.indexOf("--out");
const outPath = outAt >= 0 ? argv[outAt + 1] : undefined;
const unknownArgs = argv.filter((a, i) => a !== "--no-live" && a !== "--out" && !(outAt >= 0 && i === outAt + 1));
if ((outAt >= 0 && (outPath === undefined || outPath.startsWith("--"))) || unknownArgs.length > 0) {
  process.stderr.write(`verify-emulation: bad arguments ${JSON.stringify(argv)}; see --help\n`);
  process.exit(64);
}
const noLive = argv.includes("--no-live");
const log = (line) => process.stderr.write(`[verify-emulation] ${line}\n`);

// ------------------------------------------------------------------------------------------------- helpers
const override = process.env.BEA_DIST_DIR;
const distRoot = override !== undefined && override !== "" ? resolve(override) : join(REPO, "dist");
const dispatcher = join(dirname(distRoot), "scripts", "bea.mjs");
const jobhostExe = join(distRoot, "native", "win32-x64", "bea-jobhost.exe");

const f32 = (v) => {
  const view = new DataView(new ArrayBuffer(4));
  view.setFloat32(0, v, true);
  return `0x${view.getUint32(0, true).toString(16)}`;
};
const fromF32Bits = (hex) => {
  const view = new DataView(new ArrayBuffer(4));
  view.setUint32(0, Number.parseInt(hex, 16), true);
  return view.getFloat32(0, true);
};
const delay = (ms) => new Promise((done) => setTimeout(done, ms));
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    return cause?.code === "EPERM";
  }
};
const survivors = async (pids, withinMs) => {
  const until = Date.now() + withinMs;
  while (Date.now() < until && pids.some(alive)) await delay(50);
  return pids.filter(alive);
};

class CheckFailed extends Error {}
const expect = (condition, message) => {
  if (!condition) throw new CheckFailed(message);
};
const same = (actual, expected, label) =>
  expect(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
  );

// ------------------------------------------------------------------------------------------------- prerequisites
/** Named skips: a missing toolchain only (S6 §10.3), never a failing behavior. */
const pythonInfo = () => {
  const command = process.env.BEA_PYTHON ?? "python";
  const probe = spawnSync(
    command,
    ["-I", "-c", "import sys, unicorn, capstone, pefile; print(sys.executable); print(unicorn.__version__)"],
    { encoding: "utf8", windowsHide: true, timeout: 30_000 },
  );
  if (probe.status !== 0)
    return {
      skip: `EMU_SKIP: no Python with unicorn/capstone/pefile (${command}: ${(probe.stderr || String(probe.error)).trim().slice(0, 200)})`,
    };
  const [executable = "", unicorn = ""] = probe.stdout.trim().split(/\r?\n/u);
  if (!unicorn.startsWith("2.1.")) return { skip: `EMU_SKIP: unicorn ${unicorn} is not 2.1.x` };
  return { skip: false, executable: executable.trim(), unicorn: unicorn.trim() };
};

const fridaReason = () => {
  if (process.platform !== "win32" || process.arch !== "x64")
    return `FRIDA_SKIP: the live lane needs Windows x64 (host is ${process.platform}-${process.arch})`;
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
  if (process.platform !== "win32") return `JOBHOST_SKIP: bea-jobhost is Windows-only`;
  if (!existsSync(jobhostExe)) return `JOBHOST_SKIP: ${jobhostExe} is missing; run npm run build`;
  const probe = spawnSync(jobhostExe, ["probe"], { encoding: "utf8", windowsHide: true, timeout: 15_000 });
  return probe.status === 0 && /"ok"\s*:\s*true/u.test(probe.stdout)
    ? false
    : `JOBHOST_SKIP: ${jobhostExe} probe failed`;
};

// ------------------------------------------------------------------------------------------------- receipt
const checks = [];
const startedAt = new Date().toISOString();
const reasons = new Map([
  ["session:mathlib", "DEPENDS: emu_open.mathlib did not pass"],
  ["session:fixture", "DEPENDS: emu_open.bea_emu_fixture did not pass"],
  ["session:live", "DEPENDS: live.spawn_live_fixture did not pass"],
]);
const reasonOf = (need) => reasons.get(need) ?? `PREREQUISITE: ${need} is not available`;
const has = new Set();

/** Runs one check unless a prerequisite is missing; a check that throws is a failure with its message. */
const check = async (id, needs, run) => {
  const missing = needs.find((need) => !has.has(need));
  if (missing !== undefined) {
    checks.push({ id, status: "skip", reason: reasonOf(missing) });
    log(`skip ${id}: ${reasonOf(missing)}`);
    return undefined;
  }
  const started = performance.now();
  try {
    const detail = await run();
    const ms = Math.round(performance.now() - started);
    checks.push({ id, status: "pass", ms, ...(detail === undefined ? {} : { detail }) });
    log(`pass ${id} (${ms} ms)`);
    return detail;
  } catch (cause) {
    const ms = Math.round(performance.now() - started);
    const message = cause instanceof Error ? cause.message : String(cause);
    checks.push({ id, status: "fail", ms, error: message.slice(0, 4000) });
    log(`FAIL ${id}: ${message.slice(0, 400)}`);
    return undefined;
  }
};

// ------------------------------------------------------------------------------------------------- setup
const python = pythonInfo();
if (python.skip === false) has.add("emu");
else reasons.set("emu", python.skip);

const manifest = await buildFixtures();
const fixtures = "unavailable" in manifest ? null : manifest.artifacts;
if (fixtures === null) reasons.set("fixtures", `GCC_SKIP: ${manifest.unavailable}`);
else has.add("fixtures");

const liveReason = noLive ? "LIVE_SKIP: --no-live" : fridaReason() || jobhostReason();
if (liveReason === false) has.add("live");
else reasons.set("live", liveReason);

if (!existsSync(dispatcher) || !existsSync(join(distRoot, "main", "mcp.js"))) {
  process.stderr.write(`verify-emulation: no built server at ${distRoot}; run npm run build (or set BEA_DIST_DIR)\n`);
  process.exit(1);
}

const root = await mkdtemp(join(tmpdir(), "bea-verify-emu-"));
const dirs = {
  home: join(root, "home"),
  appData: join(root, "home", "AppData", "Roaming"),
  localAppData: join(root, "home", "AppData", "Local"),
  temp: join(root, "tmp"),
  beaHome: join(root, "bea-home"),
  work: join(root, "work"),
};
await Promise.all(Object.values(dirs).map((dir) => mkdir(dir, { recursive: true })));
const passThrough = ["SystemRoot", "SystemDrive", "windir", "ComSpec", "PATHEXT", "NUMBER_OF_PROCESSORS"]
  .concat(["PROCESSOR_ARCHITECTURE", "OS"])
  .filter((name) => process.env[name] !== undefined);
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
  BEA_LOG_LEVEL: "info",
  ...(python.skip === false && python.executable !== "" ? { BEA_PYTHON: python.executable } : {}),
};

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [dispatcher, "mcp"],
  env,
  cwd: dirs.work,
  stderr: "pipe",
});
let serverStderr = "";
transport.stderr?.on("data", (chunk) => {
  serverStderr = `${serverStderr}${chunk}`.slice(-200_000);
});
const client = new Client({ name: "bea-verify-emulation", version: "1" });
await client.connect(transport);
const serverPid = transport.pid;
const child = transport._process;
const serverExit = new Promise((done) => {
  if (child === undefined) done({ code: null, signal: null });
  else if (child.exitCode !== null || child.signalCode !== null)
    done({ code: child.exitCode, signal: child.signalCode });
  else child.once("exit", (code, signal) => done({ code, signal }));
});

const tools = new Map((await client.listTools()).tools.map((tool) => [tool.name, tool]));
for (const name of ["emu_open", "emu_call", "diff_function", "close_session", "spawn_process", "resume_process"].concat(
  ["call_function", "dump_memory", "hook_function"],
))
  if (tools.has(name)) has.add(`tool:${name}`);
  else reasons.set(`tool:${name}`, `TOOL_SKIP: ${name} is not registered by this build`);

const ajv = new Ajv2020({ strict: false, validateFormats: false, allErrors: true });
const validators = new Map();
const bridgePids = new Set();
const targetPids = new Set();

/** A tool call; a success is validated against the tool's advertised output schema. */
const callTool = async (name, args) => {
  const result = await client.callTool({ name, arguments: args }, { timeout: CALL_TIMEOUT_MS });
  const schema = tools.get(name)?.outputSchema;
  if (result.isError !== true && schema !== undefined && result.structuredContent !== undefined) {
    let validate = validators.get(name);
    if (validate === undefined) {
      validate = ajv.compile(schema);
      validators.set(name, validate);
    }
    if (!validate(result.structuredContent))
      throw new CheckFailed(`${name} output violates its advertised schema: ${ajv.errorsText(validate.errors)}`);
  }
  return result;
};
const ok = async (name, args) => {
  const result = await callTool(name, args);
  if (result.isError === true)
    throw new CheckFailed(
      `${name} failed: ${String(result.content?.[0]?.text ?? JSON.stringify(result)).slice(0, 1500)}`,
    );
  expect(
    typeof result.structuredContent === "object" && result.structuredContent !== null,
    `${name}: no structuredContent`,
  );
  return result.structuredContent;
};
const noteBridge = (opened) => {
  for (const pid of [opened.bridge?.pid, opened.bridge?.child_pid]) if (typeof pid === "number") bridgePids.add(pid);
};
const closeQuietly = async (sessionId) => {
  if (sessionId !== undefined) await callTool("close_session", { session_id: sessionId }).catch(() => undefined);
};

// ------------------------------------------------------------------------------------------------- emulator
const state = {};
const EMU = ["emu", "fixtures", "tool:emu_open", "tool:emu_call"];
const sig = (args, returns) => ({ args: args.map((type) => ({ type })), returns });

try {
  await check("emu_open.mathlib", EMU, async () => {
    const mathlib = fixtures.mathlib;
    const opened = await ok("emu_open", { image_path: mathlib.path });
    noteBridge(opened);
    state.mathlib = String(opened.session_id);
    has.add("session:mathlib");
    same(opened.bridge.protocol, "bea-emu/0.1", "bridge.protocol");
    expect(String(opened.bridge.engines.unicorn).startsWith("2.1."), `unicorn ${opened.bridge.engines.unicorn}`);
    same(opened.primary.sha256, mathlib.artifactSha256, "primary.sha256");
    same(opened.primary.mapped_base, "0x180000000", "primary.mapped_base");
    same([opened.fp.mxcsr, opened.fp.fpcw], ["0x1f80", "0x27f"], "fp defaults");
    const vex = `0x${mathlib.pe.exportRvas.mf_avx_dot.toString(16)}`;
    expect(opened.isa.functions_with_vex_sample.includes(vex), `ISA report lacks mf_avx_dot (${vex})`);
    expect((opened.isa.sites.x87_inexact ?? 0) >= 1, "no x87_inexact site reported");
    return {
      sha256: opened.primary.sha256,
      bridge: { version: opened.bridge.version, engines: opened.bridge.engines, python: opened.bridge.python },
      isa: { cache: opened.isa.cache, sites: opened.isa.sites },
      timings_ms: opened.timings_ms,
    };
  });

  await check("emu_open.isa_cache_hit", [...EMU, "session:mathlib", "tool:close_session"], async () => {
    const again = await ok("emu_open", { image_path: fixtures.mathlib.path });
    noteBridge(again);
    await closeQuietly(String(again.session_id));
    same(again.isa.cache, "hit", "second open isa.cache");
    return { scan_ms: again.isa.scan_ms };
  });

  await check("golden.mathlib", [...EMU, "session:mathlib"], async () => {
    const golden = JSON.parse(readFileSync(join(REPO, "tests", "golden", "emu", "mathlib.json"), "utf8"));
    const results = [];
    for (const c of golden.cases) {
      const done = await ok("emu_call", {
        session_id: state.mathlib,
        address: `mathlib.dll!${c.export}`,
        signature: c.signature,
        args: c.args,
        ...(c.max_instructions === undefined ? {} : { budget: { max_instructions: c.max_instructions } }),
      });
      const label = `${c.export}(${JSON.stringify(c.args)})`;
      same(done.call.status, c.status, `${label} status`);
      same(done.call.ret?.bits ?? null, c.ret_bits, `${label} ret bits`);
      results.push({ case: label, status: done.call.status, bits: done.call.ret?.bits ?? null });
    }
    return { cases: results.length };
  });

  await check("emu_open.bea_emu_fixture", EMU, async () => {
    const fixture = fixtures.bea_emu_fixture;
    const opened = await ok("emu_open", { image_path: fixture.path });
    noteBridge(opened);
    state.fixture = String(opened.session_id);
    has.add("session:fixture");
    same(opened.primary.sha256, fixture.artifactSha256, "primary.sha256");
    const vex = `0x${fixture.pe.exportRvas.bea_avx_dot.toString(16)}`;
    expect(opened.isa.functions_with_vex_sample.includes(vex), `ISA report lacks bea_avx_dot (${vex})`);
    return { imports: opened.imports.models, unhandled: opened.imports.unhandled_sample.length };
  });

  await check("emu_call.spring_damper_reference", [...EMU, "session:fixture"], async () => {
    const xs = Array.from({ length: 64 }, (_, i) => Math.fround((i - 32) * 0.913));
    const vs = Array.from({ length: 64 }, (_, i) => Math.fround(5 - i * 0.37));
    const k = Math.fround(40);
    const c = Math.fround(2.5);
    const batch = await ok("emu_call", {
      session_id: state.fixture,
      address: "bea_emu_fixture.dll!bea_spring_damper",
      signature: sig(["f32", "f32", "f32", "f32"], "f32"),
      vectors: { columns: { arg0: xs.map(f32), arg1: vs.map(f32), arg2: xs.map(() => k), arg3: xs.map(() => c) } },
      inline_limit: 64,
    });
    const reference = xs.map((x, i) => {
      let f = Math.fround(Math.fround(-k * x) - Math.fround(c * (vs[i] ?? 0)));
      if (f > 1000) f = 1000;
      if (f < -1000) f = -1000;
      return f32(f);
    });
    same(batch.batch.columns.ret.bits, reference, "bea_spring_damper ret bits");
    return { vectors: reference.length };
  });

  await check("emu_call.statuses", [...EMU, "session:fixture"], async () => {
    const at = (name) => `bea_emu_fixture.dll!${name}`;
    const div = await ok("emu_call", {
      session_id: state.fixture,
      address: at("bea_div"),
      signature: sig(["i32", "i32"], "i32"),
      args: [7, 0],
    });
    same([div.call.status, div.call.attribution], ["cpu_exception", "target"], "bea_div(7, 0)");
    const avx = await ok("emu_call", {
      session_id: state.fixture,
      address: at("bea_avx_dot"),
      signature: sig(["ptr", "ptr", "i32"], "f32"),
      args: [0, 0, 0],
    });
    same([avx.call.status, avx.call.attribution], ["unsupported_instruction", "harness"], "bea_avx_dot");
    const spin = await ok("emu_call", {
      session_id: state.fixture,
      address: at("bea_spin"),
      signature: sig(["i32"], "i32"),
      args: [1],
      budget: { max_instructions: 50_000 },
    });
    same([spin.call.status, spin.call.attribution], ["budget_exhausted", "harness"], "bea_spin");
    const dispatch = await ok("emu_call", {
      session_id: state.fixture,
      address: at("bea_dispatch"),
      signature: sig(["f32"], "f32"),
      args: [1],
    });
    // the emulated CPUID reports no AVX2, so the dispatcher takes the x*3.0f path whatever the host CPU has
    same([dispatch.call.status, dispatch.call.ret.bits], ["returned", f32(3)], "bea_dispatch(1) emulated");
    return { div: div.call.status, avx: avx.call.status, spin: spin.call.status, dispatch: dispatch.call.ret.bits };
  });

  await check("diff.emulation_vs_expected", [...EMU, "session:fixture", "tool:diff_function"], async () => {
    const base = {
      emu_session_id: state.fixture,
      address: "bea_emu_fixture.dll!bea_spring_damper",
      signature: sig(["f32", "f32", "f32", "f32"], "f32"),
      vectors: { columns: { arg0: [1, -2, 100], arg1: [0.5, 3, -40], arg2: [40, 40, 40], arg3: [2, 2, 2] } },
    };
    const right = [-41, 74, -1000];
    const same3 = await ok("diff_function", { ...base, expected: { columns: { ret: right } } });
    same(same3.verdict, "equivalent-on-tested-inputs", "equal expected values");
    same(same3.unknown_id, null, "no unknown on equivalence");
    const wrong = await ok("diff_function", { ...base, expected: { columns: { ret: [-41, 74.5, -1000] } } });
    same(wrong.verdict, "differ", "one wrong expected value");
    expect(String(wrong.unknown_id).startsWith("unk_"), `no unknown recorded: ${wrong.unknown_id}`);
    const avx = await ok("diff_function", {
      emu_session_id: state.fixture,
      address: "bea_emu_fixture.dll!bea_avx_dot",
      signature: sig(["ptr", "ptr", "i32"], "f32"),
      vectors: { columns: { arg0: [0], arg1: [0], arg2: [0] } },
      expected: { columns: { ret: [0] } },
    });
    same(avx.verdict, "unknown", "bea_avx_dot (emulation stops at the first VEX instruction)");
    return { differ_unknown: wrong.unknown_id, avx_inconclusive: avx.pairs[0]?.inconclusive ?? null };
  });

  // ----------------------------------------------------------------------------------------------- live
  const LIVE = [...EMU, "live", "tool:spawn_process", "tool:resume_process", "tool:call_function"];
  const CAR_FIELDS = [
    { name: "speed", offset: 0, type: "f32" },
    { name: "counter", offset: 4, type: "i32" },
    { name: "pos", offset: 8, type: "f64[]", count: 3 },
  ];
  const physicsCall = (session) =>
    ok("call_function", {
      session_id: session,
      address: "live_fixture.exe!physics_step",
      signature: { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f32" }], returns: "f32" },
      buffers: [{ name: "car", size: 32, init_from: "live_fixture.exe!g_car", out: true, fields: CAR_FIELDS }],
      args: [null, 0.016],
    });
  const emulatedPhysics = (session) =>
    ok("emu_call", {
      session_id: session,
      address: "live_fixture.exe!physics_step",
      signature: { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f32" }], returns: "f32" },
      buffers: [{ name: "car", size: 32, init_from: "live_fixture.exe!g_car", out: true, fields: CAR_FIELDS }],
      args: [null, 0.016],
    });

  await check("live.spawn_live_fixture", LIVE, async () => {
    const spawned = await ok("spawn_process", { program: fixtures.live_fixture.path, args: ["--sleep", "600000"] });
    state.live = String(spawned.session_id);
    if (typeof spawned.identity?.pid === "number") targetPids.add(spawned.identity.pid);
    await ok("resume_process", { session_id: state.live });
    // one frame, then a long sleep: g_car holds its RUNTIME state while the checks run
    const until = Date.now() + 15_000;
    let energy = 0;
    while (Date.now() < until && !(energy > 0)) {
      const read = await callTool("call_function", {
        session_id: state.live,
        address: "live_fixture.exe!car_energy",
        signature: { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f64" }], returns: "f64" },
        buffers: [{ name: "car", size: 32, init_from: "live_fixture.exe!g_car", fields: CAR_FIELDS }],
        args: [null, 2],
      });
      if (read.isError !== true) energy = Number(read.structuredContent?.call?.ret?.value ?? 0);
      if (!(energy > 0)) await delay(50);
    }
    expect(energy > 0, "g_car never reached its runtime state (car_energy stayed 0)");
    const opened = await ok("emu_open", { image_path: fixtures.live_fixture.path });
    noteBridge(opened);
    state.liveEmu = String(opened.session_id);
    has.add("session:live");
    return { pid: spawned.identity?.pid ?? null, car_energy: energy };
  });

  const PARITY = [...LIVE, "session:live", "tool:diff_function"];
  const liveDiff = (address, signature, columns, extra = {}) =>
    ok("diff_function", {
      live_session_id: state.live,
      emu_session_id: state.liveEmu,
      address,
      signature,
      vectors: { columns },
      ...extra,
    });
  const legBits = (result, leg) => (result.rows ?? []).map((row) => row.legs.find((l) => l.leg === leg)?.r ?? null);
  const FOUR = sig(["f32", "f32", "f32", "f32"], "f32");
  const fourRef = (a, b, c, d) =>
    f32(Math.fround(Math.fround(Math.fround(Math.fround(a * 1000) + Math.fround(b * 100)) + Math.fround(c * 10)) + d));

  await check("parity.four_floats_rn", PARITY, async () => {
    const columns = {
      arg0: [f32(1), "0x7fc12345", "0x7fa00001", "0x80000000", "0x00000001"],
      arg1: [f32(2), f32(2), f32(2), "0x80000000", "0x00400000"],
      arg2: [f32(3), f32(3), f32(3), "0x80000000", "0x00000003"],
      arg3: [f32(4), f32(4), f32(4), "0x80000000", "0x00000005"],
    };
    const result = await liveDiff("live_fixture.exe!four_floats", FOUR, columns, {
      fp: { mxcsr: "0x1f80", fpcw: "0x27f" },
    });
    same(result.verdict, "equivalent-on-tested-inputs", "verdict");
    const denormal = fourRef(fromF32Bits("0x1"), fromF32Bits("0x400000"), fromF32Bits("0x3"), fromF32Bits("0x5"));
    same(
      legBits(result, "live"),
      [fourRef(1, 2, 3, 4), "0x7fc12345", "0x7fe00001", "0x80000000", denormal],
      "live bits",
    );
    same(legBits(result, "emulation"), legBits(result, "live"), "emulation bits");
    return { live: legBits(result, "live") };
  });

  await check("parity.four_floats_ftz_daz_rz", PARITY, async () => {
    const columns = {
      arg0: ["0x00000001", f32(1.0000001)],
      arg1: ["0x00400000", f32(0.1)],
      arg2: ["0x00000003", f32(0.3)],
      arg3: ["0x00000005", f32(1e-8)],
    };
    const seen = {};
    for (const mxcsr of ["0x9fc0", "0x7f80"]) {
      const result = await liveDiff("live_fixture.exe!four_floats", FOUR, columns, { fp: { mxcsr, fpcw: "0x27f" } });
      same(result.verdict, "equivalent-on-tested-inputs", `verdict under MXCSR ${mxcsr}`);
      seen[mxcsr] = legBits(result, "live");
    }
    expect(seen["0x9fc0"]?.[0] === "0x0", `FTZ/DAZ did not flush the denormal sum: ${seen["0x9fc0"]?.[0]}`);
    return seen;
  });

  await check("parity.mix_args_car_energy", PARITY, async () => {
    const mix = await liveDiff("live_fixture.exe!mix_args", sig(["i32", "f32", "f64", "f32", "i32", "f64"], "f64"), {
      arg0: [7, -3],
      arg1: [1.5, 0.1],
      arg2: [2.25, -1e300],
      arg3: [3.125, 2.5],
      arg4: [11, 0],
      arg5: [0.5, 1e-310],
    });
    same(mix.verdict, "equivalent-on-tested-inputs", "mix_args verdict");
    const energy = await ok("diff_function", {
      live_session_id: state.live,
      emu_session_id: state.liveEmu,
      address: "live_fixture.exe!car_energy",
      signature: { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f64" }], returns: "f64" },
      buffers: [
        {
          name: "car",
          size: 32,
          fields: [
            { name: "speed", offset: 0, type: "f32", default: "60" },
            { name: "pos", offset: 8, type: "f64[]", count: 3, default: "1,0,4" },
          ],
        },
      ],
      vectors: { columns: { arg1: [1200, 0.5, 3] } },
    });
    same(energy.verdict, "equivalent-on-tested-inputs", "car_energy verdict");
    return { mix_args: legBits(mix, "live"), car_energy: legBits(energy, "live") };
  });

  await check("parity.bea_dispatch_cpuid", PARITY, async () => {
    const result = await liveDiff("live_fixture.exe!bea_dispatch", sig(["f32"], "f32"), { arg0: [1, 2.5] });
    const live = legBits(result, "live");
    const hostAvx2 = live[0] === f32(Math.fround(1 * Math.fround(3.0001)));
    same(legBits(result, "emulation"), [f32(3), f32(7.5)], "emulated bea_dispatch takes the x*3.0f path");
    if (hostAvx2) {
      same(result.verdict, "differ", "verdict with host AVX2");
      expect(
        result.hints.some((h) => h.code === "cpuid_dispatch"),
        `no cpuid_dispatch hint: ${JSON.stringify(result.hints.map((h) => h.code))}`,
      );
      expect(String(result.unknown_id).startsWith("unk_"), `no unknown recorded: ${result.unknown_id}`);
    } else same(result.verdict, "equivalent-on-tested-inputs", "verdict without host AVX2");
    return { host_avx2: hostAvx2, live, verdict: result.verdict, unknown_id: result.unknown_id };
  });

  await check("dump.physics_step_runtime_state", [...PARITY, "tool:dump_memory", "tool:close_session"], async () => {
    const dumped = await ok("dump_memory", {
      session_id: state.live,
      format: "bundle",
      bundle: { modules: ["$main"], regions: [{ address: "live_fixture.exe!g_car", size: 4096 }] },
    });
    const opened = await ok("emu_open", { dump_path: dumped.path });
    noteBridge(opened);
    const session = String(opened.session_id);
    try {
      same(opened.source, "dump", "emu_open source");
      const emulated = await emulatedPhysics(session);
      const live = await physicsCall(state.live);
      same(emulated.call.ret.bits, live.call.ret.bits, "physics_step ret bits");
      same(emulated.call.outputs["car.speed"], live.call.outputs["car.speed"], "car.speed");
      same(emulated.call.outputs["car.counter"], live.call.outputs["car.counter"], "car.counter");
      expect(Number(emulated.call.outputs["car.counter"]?.value) >= 2, "the dump did not carry the runtime g_car");
      return { ret: emulated.call.ret.bits, counter: emulated.call.outputs["car.counter"]?.value ?? null };
    } finally {
      await closeQuietly(session);
    }
  });

  await check("capture.hooked_physics_step", [...PARITY, "tool:hook_function", "tool:close_session"], async () => {
    await ok("hook_function", {
      session_id: state.live,
      address: "live_fixture.exe!physics_step",
      duration_ms: 60_000,
    });
    const opened = await ok("emu_open", {
      live_session_id: state.live,
      capture_regions: [{ address: "live_fixture.exe!g_car", size: 4096 }],
    });
    noteBridge(opened);
    const session = String(opened.session_id);
    try {
      same(opened.source, "dump", "emu_open source");
      expect(String(opened.capture?.evidence_id).startsWith("ev_"), "no capture evidence id");
      const emulated = await emulatedPhysics(session);
      const live = await physicsCall(state.live);
      same(emulated.call.status, "returned", "emulated status (the original bytes, not the hook)");
      same(emulated.call.ret.bits, live.call.ret.bits, "physics_step ret bits");
      return { ret: emulated.call.ret.bits };
    } finally {
      await closeQuietly(session);
    }
  });
} finally {
  // ----------------------------------------------------------------------------------------------- teardown
  for (const id of [state.liveEmu, state.fixture, state.mathlib, state.live]) await closeQuietly(id);
  await client.close().catch(() => undefined);
  const exit = await Promise.race([serverExit, delay(10_000).then(() => ({ code: null, signal: "timeout" }))]);
  const leftBridges = await survivors([...bridgePids], 3_000);
  const leftTargets = await survivors([...targetPids], 3_000);
  const leftServer = serverPid === null || serverPid === undefined ? [] : await survivors([serverPid], 3_000);
  // kill only what this run started (the server, its bridges, its spawned target), and report it as a failure
  for (const pid of [...leftBridges, ...leftTargets, ...leftServer])
    try {
      process.kill(pid);
    } catch {
      // already gone
    }
  checks.push({
    id: "hygiene.no_leftover_processes",
    status:
      exit.code === 0 && leftBridges.length === 0 && leftTargets.length === 0 && leftServer.length === 0
        ? "pass"
        : "fail",
    detail: {
      server_exit: exit,
      bridge_pids: [...bridgePids],
      target_pids: [...targetPids],
      survivors: { bridges: leftBridges, targets: leftTargets, server: leftServer },
    },
  });
  await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => undefined);
}

// ------------------------------------------------------------------------------------------------- verdict
const count = (status) => checks.filter((c) => c.status === status).length;
const summary = { passed: count("pass"), failed: count("fail"), skipped: count("skip") };
const status = summary.failed > 0 ? "fail" : summary.skipped > 0 ? "incomplete" : "pass";
const receipt = {
  schema: RECEIPT_SCHEMA,
  status,
  summary,
  started_at: startedAt,
  finished_at: new Date().toISOString(),
  host: { platform: process.platform, arch: process.arch, node: process.version },
  dist: { root: distRoot, snapshot: override !== undefined && override !== "" },
  python: python.skip === false ? { executable: python.executable, unicorn: python.unicorn } : { skip: python.skip },
  fixtures:
    fixtures === null
      ? null
      : Object.fromEntries(
          ["mathlib", "bea_emu_fixture", "live_fixture"].map((id) => [id, fixtures[id].artifactSha256]),
        ),
  checks,
  ...(summary.failed > 0 ? { server_stderr_tail: serverStderr.split(/\r?\n/u).filter(Boolean).slice(-20) } : {}),
};
const text = `${JSON.stringify(receipt, null, 1)}\n`;
if (outPath === undefined) process.stdout.write(text);
else {
  await writeFile(resolve(outPath), text, "utf8");
  log(`receipt: ${resolve(outPath)}`);
}
log(`${status}: ${summary.passed} passed, ${summary.failed} failed, ${summary.skipped} skipped`);
process.exitCode = status === "pass" ? 0 : status === "fail" ? 1 : 2;
