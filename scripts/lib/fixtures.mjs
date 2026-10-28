// scripts/lib/fixtures.mjs (WP0; DESIGN §8.1, S6 §10.2, S5 §14.2): builds the native and emulator test fixtures with
// gcc, derives a manifest from the PE headers and `objdump -d -M intel`, and enforces the fixture invariants, so a
// compiler change can never silently weaken a test. Tests read RVAs from the manifest, never from documents.
//
// Cache: .cache/fixtures/<key>/ where key = sha256(builder version, every source, compiler version lines, args). All
// fixtures share one directory, so game_sim.exe and behavior.exe find mathlib.dll next to them. Builds compile from a
// staging directory with relative names (MinGW ld derives a DLL's automatic image base from the output path; relative
// names keep the bytes identical wherever the staging directory is), then publish the directory by rename.
// Missing toolchain -> { unavailable: reason } (tests turn it into a named skip).
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, readFile, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

import { makeStagingDir, publishDir, removeStagingDir } from "./atomic.mjs";
import { REPO_ROOT, withBuildLock } from "./lock.mjs";
import { exportedFunctions, exportRvas, parsePe } from "./peParse.mjs";

/** Bump when the manifest shape or the invariants change: it is part of the cache key. */
const BUILDER_VERSION = "bea.fixtures/1+wp0.1";

const C_COMMON = ["-Wl,--no-insert-timestamp"];
/** DESIGN §8.1 build lines. The emulator DLLs add -static (the verified ext-backends/critic labs did) so they import
 *  only KERNEL32/msvcrt and load in any process; every artifact is checked for MinGW runtime imports below. */
export const FIXTURE_SPECS = [
  {
    id: "game_sim",
    source: "fixtures/native/game_sim.c",
    file: "game_sim.exe",
    tool: "cc",
    args: ["-O2", "-fno-math-errno", "-Wall", ...C_COMMON],
  },
  {
    id: "crashy",
    source: "fixtures/native/crashy.c",
    file: "crashy.exe",
    tool: "cc",
    args: ["-O2", "-fno-optimize-sibling-calls", "-Wno-infinite-recursion", ...C_COMMON],
  },
  {
    id: "behavior",
    source: "fixtures/native/behavior.c",
    file: "behavior.exe",
    tool: "cc",
    args: ["-O2", ...C_COMMON],
    libs: ["-lws2_32"],
  },
  {
    id: "mathlib",
    source: "fixtures/native/mathlib.c",
    file: "mathlib.dll",
    tool: "cc",
    args: ["-O2", "-fno-math-errno", "-shared", ...C_COMMON, "-Wl,--image-base,0x180000000"],
  },
  {
    id: "pidcheck",
    source: "fixtures/native/pidcheck.c",
    file: "pidcheck.exe",
    tool: "cc",
    args: ["-O2", ...C_COMMON],
  },
  {
    id: "vehcommit",
    source: "fixtures/native/vehcommit.c",
    file: "vehcommit.exe",
    tool: "cc",
    args: ["-O2", ...C_COMMON],
  },
  {
    id: "waiters",
    source: "fixtures/native/waiters.c",
    file: "waiters.exe",
    tool: "cc",
    args: ["-O2", ...C_COMMON],
  },
  {
    id: "mitigated",
    source: "fixtures/native/mitigated.c",
    file: "mitigated.exe",
    tool: "cc",
    args: ["-O2", ...C_COMMON],
  },
  {
    id: "bea_emu_fixture",
    source: "fixtures/emu/bea_emu_fixture.c",
    file: "bea_emu_fixture.dll",
    tool: "cc",
    args: ["-O2", "-shared", "-static", "-fno-builtin-sqrtf", "-fno-builtin-memcpy", ...C_COMMON],
  },
  {
    id: "live_fixture",
    source: "fixtures/emu/live_fixture.c",
    file: "live_fixture.exe",
    tool: "cc",
    args: ["-O2", ...C_COMMON],
  },
  {
    id: "cxx_catch",
    source: "fixtures/emu/cxx_catch.cpp",
    file: "cxx_catch.dll",
    tool: "cxx",
    args: ["-O2", "-shared", "-static", ...C_COMMON],
  },
];

/** S5 §14.2 / ext-backends §2.1 exports the emulator lanes rely on. */
const EMU_FIXTURE_EXPORTS = [
  "bea_spring_damper",
  "bea_poly_d",
  "bea_stack_args",
  "bea_norm_copy",
  "bea_body_step",
  "g_gain",
  "g_calls",
  "bea_global_gain",
  "bea_big_frame",
  "bea_tls_counter",
  "bea_avx_dot",
  "bea_div",
  "bea_apply",
  "bea_trig",
  "bea_spin",
  "bea_read_teb_self",
  "bea_dispatch",
  "bea_struct_ret",
  "bea_byval12",
  "bea_variadic_sum",
  "bea_mxcsr_read",
  "bea_rdtsc",
  "bea_syscall_stub",
  "bea_codec_get",
  "bea_vec_sum",
];
const LIVE_FIXTURE_EXPORTS = [
  "physics_step",
  "mix_args",
  "four_floats",
  "add_ints",
  "hot_fn",
  "touch_counter",
  "car_energy",
  "g_car",
  "g_marker",
  "bea_dispatch",
  "bea_vec_sum",
];
const CRASHY_EXIT_CODES = {
  "av-write": 0xc0000005,
  "av-read": 0xc0000005,
  "av-exec": 0xc0000005,
  div0: 0xc0000094,
  illegal: 0xc000001d,
  fastfail: 0xc0000409,
  "stack-overflow": 0xc00000fd,
  handled: 0,
  abort: 3,
};
const MINGW_RUNTIME_DLL = /^(?:libgcc_s|libstdc\+\+|libwinpthread|libgomp|libssp)/iu;

export class FixtureInvariantError extends Error {
  name = "FixtureInvariantError";
}

const sha256 = (data) => createHash("sha256").update(data).digest("hex");

function probeTool(command, args = ["--version"]) {
  const run = spawnSync(command, args, { encoding: "utf8", windowsHide: true });
  if (run.error !== undefined || run.status !== 0) return null;
  const where = spawnSync(process.platform === "win32" ? "where" : "which", [command], {
    encoding: "utf8",
    windowsHide: true,
  });
  return {
    command,
    path: where.status === 0 ? (where.stdout.split(/\r?\n/u)[0] ?? command).trim() : command,
    version: (run.stdout.split(/\r?\n/u)[0] ?? "").trim(),
  };
}

/** The toolchain, or the reason fixtures cannot be built here. */
export function fixtureToolchain() {
  if (process.platform !== "win32" || process.arch !== "x64")
    return { unavailable: `fixtures are Windows x64 PE images (host is ${process.platform}-${process.arch})` };
  const cc = probeTool(process.env.CC ?? "gcc");
  if (cc === null)
    return { unavailable: `${process.env.CC ?? "gcc"} not found on PATH (install WinLibs MinGW-w64 or set CC)` };
  const cxx = probeTool(process.env.CXX ?? "g++");
  if (cxx === null)
    return { unavailable: `${process.env.CXX ?? "g++"} not found on PATH (install WinLibs MinGW-w64 or set CXX)` };
  const objdump = probeTool(process.env.OBJDUMP ?? "objdump");
  if (objdump === null) return { unavailable: `${process.env.OBJDUMP ?? "objdump"} not found on PATH (binutils)` };
  return { cc, cxx, objdump };
}

function run(command, args, cwd) {
  return new Promise((done, fail) => {
    const child = spawn(command, args, { cwd, windowsHide: true });
    let out = "";
    let err = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => (out += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk) => (err += chunk));
    child.on("error", fail);
    child.on("close", (code) => done({ code, out, err }));
  });
}

/**
 * objdump -d -M intel -> { functionName: [{ rva, size, mnemonic, operands, text }] }. Raw bytes give exact
 * instruction sizes; continuation lines (long instructions) add to the previous instruction.
 */
function parseDisassembly(text, imageBase) {
  const functions = {};
  let current = null;
  let last = null;
  for (const line of text.split(/\r?\n/u)) {
    const header = /^([0-9a-f]+) <(.+)>:$/u.exec(line);
    if (header !== null) {
      current = functions[header[2]] ??= [];
      last = null;
      continue;
    }
    const insn = /^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*(?:\t(.*))?$/u.exec(line);
    if (insn === null || current === null) continue;
    const size = insn[2].trim().split(" ").length;
    if (insn[3] === undefined) {
      if (last !== null) last.size += size;
      continue;
    }
    const body = insn[3].trim();
    const space = body.search(/\s/u);
    const mnemonic = space < 0 ? body : body.slice(0, space);
    const operands = space < 0 ? "" : body.slice(space).trim();
    last = {
      rva: Number(BigInt(`0x${insn[1]}`) - imageBase),
      size,
      mnemonic,
      operands,
      text: `${mnemonic} ${operands}`.trim(),
    };
    current.push(last);
  }
  return functions;
}

const WIDTH = { BYTE: 1, WORD: 2, DWORD: 4, QWORD: 8, TBYTE: 10, XMMWORD: 16, YMMWORD: 32 };
const NOT_STORES = new Set([
  "cmp",
  "test",
  "ucomiss",
  "ucomisd",
  "comiss",
  "comisd",
  "bt",
  "push",
  "nop",
  "prefetcht0",
  "prefetchnta",
]);
/** Memory operands of one instruction: {width, base, disp, store}. */
function memoryOperands(insn) {
  const out = [];
  for (const m of insn.operands.matchAll(
    /(BYTE|WORD|DWORD|QWORD|TBYTE|XMMWORD|YMMWORD) PTR \[([a-z0-9]+)(?:\+(0x[0-9a-f]+))?\]/gu,
  )) {
    if (m[2] === "rip") continue;
    const first = insn.operands.startsWith(m[0]);
    out.push({
      width: WIDTH[m[1]],
      base: m[2],
      disp: m[3] === undefined ? 0 : Number(m[3]),
      store: first && !NOT_STORES.has(insn.mnemonic),
    });
  }
  return out;
}
const covers = (op, start, size) => op.disp < start + size && op.disp + op.width > start;

const fail = (artifact, why) => {
  throw new FixtureInvariantError(`fixture invariant (${artifact}): ${why}`);
};

function requireExports(id, exportsByName, names) {
  const missing = names.filter((name) => exportsByName[name] === undefined);
  if (missing.length > 0) fail(id, `missing exports ${missing.join(", ")}`);
}

const vexFunctionsOf = (functions, prefix) =>
  Object.entries(functions)
    .filter(([name, list]) => name.startsWith(prefix) && list.some((insn) => insn.mnemonic.startsWith("v")))
    .map(([name]) => name)
    .sort();

/** Per-fixture expectations and the invariant checks of DESIGN §8.1 / S6 §10.2. `ctx` = {id, pe, functions, ...}. */
const EXPECTATIONS = {
  game_sim: ({ id, pe, exportsByName, insns }) => {
    // Every memory access of the Car functions; main's one-time initialisation of the calloc'd car is not a writer.
    const carFunctions = ["physics_step", "input_update", "engine_update", "telemetry_sample", "car_energy"];
    const accesses = carFunctions.flatMap((fn) =>
      insns(fn).flatMap((insn) => memoryOperands(insn).map((op) => ({ fn, insn, op }))),
    );
    const speedWriters = accesses
      .filter(({ op }) => op.store && covers(op, 0x8, 4))
      .map(({ fn, insn, op }) => ({
        fn,
        rva: insn.rva,
        text: insn.text,
        base: op.base,
        disp: `0x${op.disp.toString(16)}`,
      }));
    const rpmWriters = accesses
      .filter(({ op }) => op.store && covers(op, 0x14, 4))
      .map(({ fn, insn, op }) => ({ fn, rva: insn.rva, width: op.width, text: insn.text }));
    const speedReaders = accesses
      .filter(({ op }) => !op.store && covers(op, 0x8, 4))
      .map(({ fn, insn }) => ({ fn, rva: insn.rva, text: insn.text }));
    if (speedWriters.length !== 1 || speedWriters[0].fn !== "physics_step")
      fail(id, `expected exactly one speed (+0x8) store, in physics_step; found ${JSON.stringify(speedWriters)}`);
    const rpmFns = [...new Set(rpmWriters.map((w) => w.fn))].sort();
    if (JSON.stringify(rpmFns) !== JSON.stringify(["engine_update", "physics_step"]))
      fail(id, `rpm (+0x14) writers must be {physics_step, engine_update}; found ${rpmFns.join(", ")}`);
    // .pdata size when gcc emitted unwind data for the leaf; else the bytes up to and including the first ret.
    const tinyList = insns("tiny_add");
    const tinyEnd = tinyList.findIndex((insn) => insn.mnemonic === "ret");
    const tinySize =
      exportedFunctions(pe).tiny_add?.size ?? tinyList.slice(0, tinyEnd + 1).reduce((n, insn) => n + insn.size, 0);
    if (tinySize > 5) fail(id, `tiny_add must be <= 5 bytes (found ${tinySize})`);
    requireExports(id, exportsByName, [
      "physics_step",
      "mix_args",
      "tiny_add",
      "telemetry_sample",
      "hot_hash",
      "car_energy",
      "g_world",
      "g_marker",
      "g_wmarker",
      "g_ballast",
    ]);
    return {
      speedWriters,
      rpmWriters,
      speedReaders,
      tinyAdd: { rva: exportsByName.tiny_add, size: tinySize },
      structOffsets: { speed: 0x8, throttle: 0xc, rpm: 0x14, odometer: 0x30, frame: 0x38, tyres: 0x40, size: 0x80 },
      chain: { root: "g_world", offsets: [0x8, 0x8] },
      markers: { ascii: "BEA_GAME_SIM_MARKER_v1", wide: "BEA_GAME_SIM_WIDE_v1" },
      equilibrium: { args: ["--no-threads", "--speed", "20", "--throttle", "0.125"], speed: 20 },
    };
  },
  crashy: ({ id, exportsByName, insns }) => {
    requireExports(id, exportsByName, [
      "crash_write",
      "crash_read",
      "crash_exec",
      "crash_div0",
      "crash_illegal",
      "crash_recurse",
      "level1",
      "level2",
    ]);
    const store =
      insns("crash_write").find((insn) => memoryOperands(insn).some((op) => op.store)) ??
      fail(id, "crash_write has no store instruction");
    const returnSite = (caller, callee) => {
      const list = insns(caller);
      const at = list.findIndex((insn) => insn.mnemonic === "call" && insn.operands.includes(`<${callee}>`));
      return at < 0 || at + 1 >= list.length
        ? fail(id, `no return site after ${caller} -> ${callee}`)
        : list[at + 1].rva;
    };
    const div = insns("crash_div0").find((insn) => insn.mnemonic === "idiv") ?? fail(id, "crash_div0 has no idiv");
    const ud2 = insns("crash_illegal").find((insn) => insn.mnemonic === "ud2") ?? fail(id, "crash_illegal has no ud2");
    return {
      crashWrite: { rva: store.rva, text: store.text },
      returnSites: { level1: returnSite("level1", "crash_write"), level2: returnSite("level2", "level1") },
      divInsn: { rva: div.rva, text: div.text },
      illegalInsn: { rva: ud2.rva },
      exitCodes: CRASHY_EXIT_CODES,
    };
  },
  mathlib: ({ id, pe, functions, exportsByName, insns }) => {
    if (pe.imageBase !== "0x180000000") fail(id, `ImageBase must be 0x180000000 (found ${pe.imageBase})`);
    requireExports(id, exportsByName, [
      "mf_spring",
      "mf_poly",
      "mf_stack",
      "mf_lerp",
      "mf_vec3_len",
      "mf_body_step",
      "mf_gain",
      "mf_div",
      "mf_avx_dot",
      "mf_x87_sin",
      "mf_spin",
      "g_gain",
      "g_calls",
    ]);
    const all = Object.values(functions).flat();
    const gGain = pe.readRva(exportsByName.g_gain, 4).readFloatLE(0);
    if (gGain !== 1.5) fail(id, `g_gain must read 1.5 from the image (found ${gGain})`);
    return {
      vexFunctions: vexFunctionsOf(functions, "mf_"),
      vexInstructions: insns("mf_avx_dot").filter((insn) => insn.mnemonic.startsWith("v")).length,
      x87Count: all.filter((insn) => /^f[a-z0-9]+$/u.test(insn.mnemonic) && !insn.mnemonic.startsWith("fx")).length,
      x87Transcendental: all.filter((insn) =>
        /^(?:fsin|fcos|fsincos|fptan|fpatan|f2xm1|fyl2x|fyl2xp1|fprem1?|fscale)$/u.test(insn.mnemonic),
      ).length,
      gGain,
    };
  },
  bea_emu_fixture: ({ id, functions, exportsByName, insns }) => {
    requireExports(id, exportsByName, EMU_FIXTURE_EXPORTS);
    const syscall =
      insns("bea_syscall_stub").find((insn) => insn.mnemonic === "syscall") ??
      fail(id, "bea_syscall_stub has no syscall");
    return {
      requiredExports: EMU_FIXTURE_EXPORTS,
      vexFunctions: vexFunctionsOf(functions, "bea_"),
      syscallInsn: { rva: syscall.rva },
      codec: { kind: "mul", key: "0x9e3779b1", inverse: "0x0e8b2f51" },
    };
  },
  live_fixture: ({ id, exportsByName }) => {
    requireExports(id, exportsByName, LIVE_FIXTURE_EXPORTS);
    return { requiredExports: LIVE_FIXTURE_EXPORTS, carOffsets: { speed: 0x0, counter: 0x4, pos: 0x8, size: 0x20 } };
  },
  cxx_catch: ({ id, exportsByName }) => {
    requireExports(id, exportsByName, ["cxx_catcher"]);
    return { catcher: { export: "cxx_catcher", argument: 1, expected: 43 } };
  },
  pidcheck: () => ({}),
  behavior: () => ({}),
  vehcommit: () => ({}),
  waiters: () => ({}),
  mitigated: () => ({}),
};

function expectationsFor(id, pe, functions) {
  const build = EXPECTATIONS[id] ?? fail(id, "no expectations defined");
  const insns = (name) => functions[name] ?? fail(id, `function ${name} not found in the disassembly`);
  return build({ id, pe, functions, exportsByName: exportRvas(pe), insns });
}

async function buildInto(stage, toolchain, sources, log) {
  for (const spec of FIXTURE_SPECS)
    await copyFile(join(REPO_ROOT, spec.source), join(stage, spec.source.split("/").pop()));
  const artifacts = {};
  await Promise.all(
    FIXTURE_SPECS.map(async (spec) => {
      const tool = toolchain[spec.tool];
      const sourceName = spec.source.split("/").pop();
      const args = [...spec.args, "-o", spec.file, sourceName, ...(spec.libs ?? [])];
      const result = await run(tool.command, args, stage);
      if (result.code !== 0)
        throw new Error(`fixture ${spec.id}: ${tool.command} failed (exit ${result.code})\n${result.err}`);
      if (result.err.trim() !== "") log(`fixture ${spec.id}: ${tool.command} diagnostics:\n${result.err.trim()}`);
      const bytes = await readFile(join(stage, spec.file));
      const pe = parsePe(bytes);
      const dump = await run(toolchain.objdump.command, ["-d", "-M", "intel", spec.file], stage);
      if (dump.code !== 0) throw new Error(`fixture ${spec.id}: objdump failed (exit ${dump.code})\n${dump.err}`);
      const functions = parseDisassembly(dump.out, BigInt(pe.imageBase));
      const runtimeImports = pe.imports.filter((dll) => MINGW_RUNTIME_DLL.test(dll));
      if (runtimeImports.length > 0)
        fail(
          spec.id,
          `imports MinGW runtime DLLs (${runtimeImports.join(", ")}); fixtures must load without the toolchain on PATH`,
        );
      artifacts[spec.id] = {
        id: spec.id,
        file: spec.file,
        source: spec.source,
        sourceSha256: sources[spec.id],
        artifactSha256: sha256(bytes),
        bytes: bytes.length,
        compiler: { command: tool.command, path: tool.path, version: tool.version, args },
        pe: {
          machine: pe.machine,
          imageBase: pe.imageBase,
          dynamicBase: pe.dynamicBase,
          highEntropyVa: pe.highEntropyVa,
          nxCompat: pe.nxCompat,
          sizeOfImage: pe.sizeOfImage,
          imports: pe.imports,
          exportRvas: exportRvas(pe),
          pdata: exportedFunctions(pe),
          sections: pe.sections.map(({ name, rva, virtualSize, characteristics }) => ({
            name,
            rva,
            virtualSize,
            characteristics,
          })),
        },
        expectations: expectationsFor(spec.id, pe, functions),
      };
    }),
  );
  return Object.fromEntries(FIXTURE_SPECS.map((spec) => [spec.id, artifacts[spec.id]]));
}

/** Attach absolute paths to a manifest read from (or written to) `dir`. */
const withPaths = (manifest, dir) => ({
  ...manifest,
  dir,
  artifacts: Object.fromEntries(
    Object.entries(manifest.artifacts).map(([id, artifact]) => [id, { ...artifact, path: join(dir, artifact.file) }]),
  ),
});

const readManifest = async (dir) => {
  try {
    const manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8"));
    for (const artifact of Object.values(manifest.artifacts)) await stat(join(dir, artifact.file));
    return manifest;
  } catch {
    return null;
  }
};

/**
 * Build (or reuse) every fixture. Returns the manifest with absolute paths, or { unavailable } when the toolchain is
 * missing. Throws FixtureInvariantError when an invariant fails.
 */
export async function buildFixtures(options = {}) {
  const log = options.log ?? ((line) => process.stderr.write(`${line}\n`));
  const toolchain = fixtureToolchain();
  if ("unavailable" in toolchain) return toolchain;
  const sources = {};
  const key = createHash("sha256").update(BUILDER_VERSION).update("\0");
  for (const spec of FIXTURE_SPECS) {
    const source = await readFile(join(REPO_ROOT, spec.source));
    sources[spec.id] = sha256(source);
    const tool = toolchain[spec.tool];
    key
      .update(spec.id)
      .update("\0")
      .update(source)
      .update("\0")
      .update(tool.version)
      .update("\0")
      .update(JSON.stringify([spec.args, spec.libs ?? []]))
      .update("\0");
  }
  key.update(toolchain.objdump.version);
  const cacheKey = key.digest("hex").slice(0, 32);
  const dir = resolve(REPO_ROOT, ".cache", "fixtures", cacheKey);
  if (options.force !== true) {
    const cached = await readManifest(dir);
    if (cached !== null) return withPaths(cached, dir);
  }
  return withBuildLock(async () => {
    if (options.force !== true) {
      const cached = await readManifest(dir);
      if (cached !== null) return withPaths(cached, dir);
    }
    const stage = await makeStagingDir("fixtures", REPO_ROOT);
    try {
      const artifacts = await buildInto(stage, toolchain, sources, log);
      const manifest = {
        schema: "bea.fixtures/1",
        builder: BUILDER_VERSION,
        key: cacheKey,
        toolchain: { cc: toolchain.cc, cxx: toolchain.cxx, objdump: toolchain.objdump },
        artifacts,
      };
      await writeFile(join(stage, "manifest.json"), `${JSON.stringify(manifest, null, 1)}\n`);
      await publishDir(stage, dir);
      return withPaths(manifest, dir);
    } finally {
      await removeStagingDir(stage);
    }
  });
}
