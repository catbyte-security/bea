#!/usr/bin/env node
// tests/support/emu/fakeBridge.mjs (WP14-EMU): a protocol-faithful bea-emu/0.1 bridge in Node (S5 §14.1 test:fast),
// so the TypeScript client, runtime, adapter and services are tested without Python. Launched exactly like the real
// bridge — `<node> fakeBridge.mjs -I -X utf8 <scenario.json> --mem-limit N [--cache-dir D] [--probe|--selftest]` — the
// "bridge path" argument is a JSON scenario that scripts its behaviour:
//   { sha256, version, protocol, ready: "ok"|"fatal"|"none"|"garbage"|"exit", readyDelayMs, ignoreCancel,
//     crash: { method, marker? } (exit 70 on that method; with `marker`, only while the marker file is absent),
//     functions: { "<target va>": behaviour }, deviations: { "<target va>": Deviation[] },
//     open: Partial<OpenResult>, openError: BridgeErrorBody, probe: object, selftest: object, spinMs, memory: hex }
// Behaviours: "sum_f32" (f32 sum of the xmm argument lanes), "add_i32", "first" (default: echoes the first slot),
// "fault_if_zero" (first lane 0 -> target fault read_unmapped), "spin" (spinMs per vector, honours cancel/deadline),
// "harness" (unsupported_instruction vex), "budget" (budget_exhausted), "uncaptured" (harness fault on a dump hole),
// "heap_full" (a chain batch stops before vector `heapFullAt`, default 2, with summary.stopped; review fix EMU-6).
// Queued methods run one at a time; bridge.cancel / bridge.ping are answered out of band, like the real reader thread.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const value = (name) => {
  const i = argv.indexOf(name);
  return i === -1 ? null : (argv[i + 1] ?? null);
};
// the bridge path follows "-X utf8" (exactly where the real bridge's own file name sits)
const utf8 = argv.indexOf("utf8");
const scenarioPath = utf8 === -1 ? null : (argv[utf8 + 1] ?? null);
const scenarioBytes = scenarioPath === null ? Buffer.from("{}") : readFileSync(scenarioPath);
const scenario = JSON.parse(scenarioBytes.toString("utf8"));
const PROTOCOL = scenario.protocol ?? "bea-emu/0.1";
// like BRIDGE_SHA256 = sha256(__file__) of the real bridge, unless the scenario forces a (wrong) value
const SHA = scenario.sha256 ?? createHash("sha256").update(scenarioBytes).digest("hex");
const VERSION = scenario.version ?? "0.1.0";
const memLimit = Number(value("--mem-limit") ?? "0");
const engines = {
  python: "3.14.6",
  unicorn: "2.1.4",
  unicornCore: "2.1",
  capstone: "5.0.9",
  pefile: "2024.8.26",
  ...scenario.engines,
};

const write = (frame) => process.stdout.write(`${JSON.stringify(frame)}\n`);

if (flag("--probe")) {
  write(
    scenario.probe ?? {
      probe: "bea-emu/0.1",
      ok: true,
      bridge: { version: VERSION, sha256: SHA },
      python: {
        version: engines.python,
        implementation: "CPython",
        executable: process.execPath,
        inVenv: false,
        bits: 64,
        platform: process.platform,
      },
      engines: {
        unicorn: engines.unicorn,
        unicornCore: engines.unicornCore,
        capstone: engines.capstone,
        pefile: engines.pefile,
      },
      missing: [],
      errors: {},
    },
  );
  process.exit(scenario.probeExit ?? 0);
}
if (flag("--selftest")) {
  const ok = (name, okValue = true) => [name, { ok: okValue, observed: okValue, expected: true }];
  write(
    scenario.selftest ?? {
      selftest: "bea-emu/0.1",
      engines,
      ms: 5,
      results: Object.fromEntries([
        ...[
          "fp_reset",
          "vex128_misexecutes",
          "vex256_rejected",
          "bmi_ok",
          "tb_hook_gotcha",
          "count_budget_gotcha",
          "cow_lifo_ok",
          "context_mode_toggle",
          "int3_rip",
          "x87_reset",
          "insn_hooks",
          "gs_base",
          "memory_limit",
        ].map((n) => ok(n)),
        ["mxcsr_flags_modeled", { ok: true, observed: false, expected: false }],
      ]),
    },
  );
  process.exit(0);
}

// ------------------------------------------------------------------ server mode
const ready = scenario.ready ?? "ok";
if (ready === "exit") process.exit(3);

const MAIN_BASE = BigInt(scenario.mainBase ?? "0x180000000");
const openResult = () => ({
  session: "s1",
  primary: {
    name: "mathlib.dll",
    path: scenario.imagePath ?? "C:\\lab\\mathlib.dll",
    sha256: scenario.imageSha256 ?? "ab".repeat(32),
    preferredBase: "0x180000000",
    mappedBase: `0x${MAIN_BASE.toString(16)}`,
    size: 0x10000,
    relocated: false,
    captured: "image",
    sections: [{ name: ".text", rva: "0x1000", size: 0x2000, perms: "r-x" }],
    exports: 12,
    pdataFunctions: 14,
    tlsCallbacks: [],
    tlsCallbacksExecuted: false,
    delayImports: 0,
  },
  modules: [],
  imports: {
    total: 3,
    models: { builtin: 2, "builtin-inexact": 0, override: 0, unhandled: 1, lle: 0, stop: 0 },
    unhandled: ["kernel32.dll!CreateEventA"],
  },
  isa: {
    scanSource: "pdata+gaps",
    cache: "miss",
    scanMs: 1.5,
    instructionsScanned: 900,
    sites: { vex: 8, evex: 0, x87_inexact: 1, fp_status: 0, cpuid: 0, syscall: 0, tsc: 0, rng: 0 },
    guarded: { int3: 8, hooks: 0, unguarded: 0 },
    functionsWithVex: ["0x1200"],
    guard: "stop",
  },
  layout: { syntheticBase: "0x7ff000000000", regions: 6, mappedBytes: 0x300000 },
  cpu: { mxcsr: "0x1f80", fpcw: "0x27f", model: "qemu64" },
  snapshots: "cow",
  thread: null,
  loaderDeviations: [{ kind: "entry_point_not_run", note: "DllMain not run" }],
  timings: { loadMs: 3, isaMs: 1.5, bindMs: 0.5, snapshotMs: 0.2, totalMs: 5.2 },
  ...scenario.open,
});

const pid = process.pid;
const readyFrame = () => ({
  event: {
    type: "ready",
    protocol: PROTOCOL,
    bridge: { version: VERSION, sha256: SHA },
    pid,
    engines,
    python: { version: engines.python, executable: process.execPath, inVenv: false },
    memoryLimit: { applied: true, bytes: memLimit, mechanism: "win32-job" },
  },
});

const startup = () => {
  if (ready === "ok") write(readyFrame());
  else if (ready === "fatal")
    write({
      event: {
        type: "fatal",
        code: "engine_unavailable",
        message: "no unicorn",
        data: { missing: ["unicorn"], errors: {} },
      },
    });
  else if (ready === "garbage") process.stdout.write("this is not json\n");
  // "none": never announce (startup timeout)
  if (ready === "fatal") process.exit(3);
};
if ((scenario.readyDelayMs ?? 0) > 0) setTimeout(startup, scenario.readyDelayMs);
else startup();

// ------------------------------------------------------------------ helpers
const f32 = new DataView(new ArrayBuffer(8));
const f32OfBits = (hex) => {
  f32.setUint32(0, Number(BigInt(hex) & 0xffffffffn), true);
  return f32.getFloat32(0, true);
};
const bitsOfF32 = (v) => {
  f32.setFloat32(0, v, true);
  return `0x${f32.getUint32(0, true).toString(16)}`;
};
const lanes = (plan, vectors, i) =>
  plan.slots.map((slot) => {
    const src = slot.source;
    if (src.kind === "column") {
      const cell = vectors.columns[src.column]?.[i];
      return typeof cell === "string" ? cell : "0x0";
    }
    if (src.kind === "const") return src.bits;
    return "0x0";
  });
const materialize = (plan, vectors, i) => {
  const out = {};
  for (const buffer of plan.buffers) {
    if (!buffer.out) continue;
    const bytes = Buffer.from(buffer.template, "hex");
    for (const c of buffer.columns) {
      const cell = vectors.columns[c.column]?.[i];
      const cells = Array.isArray(cell) ? cell : [cell];
      cells.forEach((bits, k) => {
        let v = BigInt(bits ?? "0x0");
        for (let b = 0; b < c.width; b++) {
          bytes[c.offset + k * c.width + b] = Number(v & 0xffn);
          v >>= 8n;
        }
      });
    }
    out[buffer.name] = bytes.toString("hex");
  }
  return out;
};
const behaviourOf = (plan) => scenario.functions?.[plan.target] ?? "first";

/** One vector -> {code, status, attribution, cause, rax, xmm0lo, out} */
const runVector = (plan, vectors, i) => {
  const lane = lanes(plan, vectors, i);
  const out = materialize(plan, vectors, i);
  const behaviour = behaviourOf(plan);
  const returned = (rax, xmm0lo) => ({
    code: "ok",
    status: "returned",
    attribution: null,
    cause: null,
    rax,
    xmm0lo,
    out,
  });
  switch (behaviour) {
    case "sum_f32": {
      const xmm = plan.slots.map((s, k) => (s.reg.startsWith("xmm") ? f32OfBits(lane[k]) : 0));
      const sum = Math.fround(xmm.reduce((a, b) => Math.fround(a + b), 0));
      return returned("0x0", bitsOfF32(sum));
    }
    case "add_i32": {
      const v = (BigInt(lane[0] ?? "0x0") + BigInt(lane[1] ?? "0x0")) & 0xffffffffn;
      return returned(`0x${v.toString(16)}`, "0x0");
    }
    case "fault_if_zero":
      if ((BigInt(lane[0] ?? "0x0") & 0xffffffffffffffffn) === 0n)
        return {
          code: "fault",
          status: "fault",
          attribution: "target",
          cause: "read_unmapped",
          rax: "",
          xmm0lo: "",
          out,
        };
      return returned(lane[0] ?? "0x0", lane[0] ?? "0x0");
    case "harness":
      return {
        code: "unsup",
        status: "unsupported_instruction",
        attribution: "harness",
        cause: "vex",
        rax: "",
        xmm0lo: "",
        out,
      };
    case "budget":
      return {
        code: "budget",
        status: "budget_exhausted",
        attribution: "harness",
        cause: "max_instructions",
        rax: "",
        xmm0lo: "",
        out,
      };
    case "uncaptured":
      return {
        code: "fault",
        status: "fault",
        attribution: "harness",
        cause: "read_unmapped",
        rax: "",
        xmm0lo: "",
        out,
      };
    default:
      return returned(lane[0] ?? "0x0", lane[0] ?? "0x0");
  }
};
const stopOf = (v, target) =>
  v.status === "returned"
    ? null
    : {
        status: v.status,
        attribution: v.attribution,
        cause: v.cause,
        pc: `0x${(MAIN_BASE + 0x1010n).toString(16)}`,
        pcRegion: { region: "mathlib.dll .text", kind: "image", module: "mathlib.dll", rva: "0x1010" },
        pcFunction: { module: "mathlib.dll", beginRva: "0x1000", endRva: "0x1040", source: "pdata", offset: "0x10" },
        instruction: [
          {
            va: `0x${(MAIN_BASE + 0x1010n).toString(16)}`,
            rva: "0x1010",
            module: "mathlib.dll",
            bytes: "8b01",
            text: "mov eax, dword ptr [rcx]",
          },
        ],
        ...(v.status === "fault"
          ? {
              fault: {
                access: "read",
                kind: "unmapped",
                address: "0x0",
                size: 4,
                value: null,
                addressRegion: {
                  region: "null page",
                  kind: "unmapped",
                  capture: "unmapped-live",
                  hint: "likely NULL pointer dereference",
                },
              },
            }
          : {}),
        ...(v.status === "unsupported_instruction"
          ? { isa: { mnemonic: "vaddss", encoding: "vex", rva: "0x1010", reason: "VEX" } }
          : {}),
        stackScan: [{ stackOffset: "0x0", va: "0xdead0000", module: null, rva: null, note: "harness return sentinel" }],
        ...(target === "complete" ? { registers: { rax: "0x0", rip: "0x1010" } } : {}),
      };
const provenance = (plan) => ({
  evidence: "emulation",
  engine: "unicorn",
  engines,
  bridge: { version: VERSION, sha256: SHA },
  protocol: PROTOCOL,
  source: "image",
  bundleId: null,
  primary: {
    name: "mathlib.dll",
    sha256: scenario.imageSha256 ?? "ab".repeat(32),
    mappedBase: `0x${MAIN_BASE.toString(16)}`,
    preferredBase: "0x180000000",
  },
  target: { va: plan.target, module: "mathlib.dll", rva: null, export: null },
  abi: "win64",
  mxcsr: "0x1f80",
  fpcw: "0x27f",
  isaGuard: "stop",
});
const deviationsOf = (plan) => scenario.deviations?.[plan.target] ?? [];

// ------------------------------------------------------------------ dispatch
const queue = [];
let busy = null;
const cancelled = new Set();
const named = new Map();
let sessions = 0;
const shouldCrash = (method) => {
  const crash = scenario.crash;
  if (crash === undefined || crash.method !== method) return false;
  if (crash.marker === undefined) return true;
  if (existsSync(crash.marker)) return false;
  writeFileSync(crash.marker, "crashed");
  return true;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const runBatch = async (id, params) => {
  const { plan, vectors, options } = params;
  const started = Date.now();
  const deadline = options.deadlineMs === undefined ? Infinity : started + options.deadlineMs;
  const status = [];
  const rax = [];
  const xmm0lo = [];
  const out = {};
  const faults = [];
  let deadlineReached = false;
  let wasCancelled = false;
  let stopped = null;
  for (let i = 0; i < vectors.count; i++) {
    if (behaviourOf(plan) === "heap_full" && options.isolation === "chain" && i === (scenario.heapFullAt ?? 2)) {
      stopped = {
        code: "resource_exhausted",
        message: "the HLE heap cannot hold buffer 'b'",
        index: vectors.offset + i,
        data: { resource: "heap", buffer: "b", bytes: 4096, heapBytes: 1048576 },
      };
      break;
    }
    if (cancelled.has(id) && !scenario.ignoreCancel) {
      wasCancelled = true;
      break;
    }
    if (Date.now() >= deadline) {
      deadlineReached = true;
      break;
    }
    if (behaviourOf(plan) === "spin") await sleep(scenario.spinMs ?? 50);
    else if (i % 64 === 63) await sleep(0);
    const v = runVector(plan, vectors, i);
    status.push(v.code);
    rax.push(v.rax);
    xmm0lo.push(v.xmm0lo);
    for (const [name, hex] of Object.entries(v.out)) (out[name] ??= []).push(hex);
    if (v.status !== "returned") {
      faults.push({
        index: vectors.offset + i,
        status: v.status,
        attribution: v.attribution,
        cause: v.cause,
        pc: `0x${(MAIN_BASE + 0x1010n).toString(16)}`,
        pcRva: "0x1010",
        ...(faults.length < 8 ? { detail: stopOf(v, "summary") } : {}),
      });
      if (options.stopOnFault) break;
    }
    if (i % 100 === 99)
      write({ id, event: { type: "progress", phase: "batch", completed: i + 1, total: vectors.count } });
  }
  const completed = status.length;
  const byStatus = {};
  for (const s of status) byStatus[s] = (byStatus[s] ?? 0) + 1;
  const harness = faults.filter((f) => f.attribution === "harness").length;
  const deviations = {};
  for (const d of deviationsOf(plan)) deviations[d.kind] = { vectors: completed };
  return {
    summary: {
      offset: vectors.offset,
      vectors: vectors.count,
      completed,
      returned: byStatus.ok ?? 0,
      byStatus,
      byAttribution: { target: faults.length - harness, harness },
      elapsedMs: Date.now() - started,
      callsPerSecond: null,
      isolation: options.isolation,
      from: params.state.from,
      path: "fast",
      deterministic: !wasCancelled,
      deadlineReached,
      cancelled: wasCancelled,
      ...(stopped === null ? {} : { stopped }),
    },
    columns: { status, rax, xmm0lo, out },
    faults,
    aggregates: {
      imports: scenario.imports ?? {},
      deviations,
      ...(options.trace?.coverage ? { coverage: coverageWire() } : {}),
    },
    provenance: provenance(plan),
  };
};
const coverageWire = () => ({
  granularity: "tb",
  blocks: [
    [`0x${(MAIN_BASE + 0x1000n).toString(16)}`, 16, 3],
    [`0x${(MAIN_BASE + 0x1020n).toString(16)}`, 8, 1],
    ["0x7ff000000100", 4, 2],
  ],
  distinct: 3,
  truncated: false,
});

/**
 * emu.call on a "spin" target, like the real bridge: the per-call watchdog (options.timeoutMs > 0) stops the call as
 * `timeout` (harness, cause "watchdog", not deterministic); otherwise it runs until a cancel.
 */
const spinCall = async (id, plan, options) => {
  const watchdogAt = (options.timeoutMs ?? 0) > 0 ? Date.now() + options.timeoutMs : Number.POSITIVE_INFINITY;
  while ((!cancelled.has(id) || scenario.ignoreCancel) && Date.now() < watchdogAt) await sleep(5);
  const timedOut = !cancelled.has(id) || scenario.ignoreCancel;
  return {
    result: {
      status: timedOut ? "timeout" : "cancelled",
      attribution: "harness",
      raw: { rax: "0x0", xmm0: "0x0", mxcsr: "0x1f80", fpcw: "0x27f", fpsw: "0x0" },
      buffers: {},
      out: {},
      stop: timedOut ? stopOf({ status: "timeout", attribution: "harness", cause: "watchdog" }, "summary") : null,
      metrics: { wallUs: timedOut ? options.timeoutMs * 1000 : 1, tbFlushes: 0 },
      events: [],
      deviations: [],
      deterministic: false,
      provenance: provenance(plan),
    },
  };
};

const handlers = {
  "bridge.hello": () => ({
    protocol: PROTOCOL,
    bridge: { version: VERSION, sha256: SHA },
    engines,
    python: { version: engines.python, executable: process.execPath, inVenv: false },
    memoryLimit: { applied: true, bytes: memLimit, mechanism: "win32-job" },
    capabilities: {
      arch: ["x86_64"],
      formats: ["pe64", "bea.dump/1"],
      abi: ["win64"],
      snapshots: ["cow", "manual"],
      trace: ["imports", "blocks", "coverage", "memory", "instructions"],
      hle: [],
      insnHooks: { cpuid: true, syscall: true, rdtsc: false },
      sweepKnown: ["sinf", "sqrtf"],
    },
    limits: {
      maxFrameBytes: 67108864,
      maxMemRead: 16777216,
      maxVectorsPerBatch: 1000000,
      maxSweepTargets: 20000,
      maxSweepVectors: 16,
      maxNamedSnapshots: 16,
      maxTraceEvents: 100000,
      maxPatches: 256,
      maxOverrides: 256,
    },
  }),
  "session.open": async (id, params) => {
    if (scenario.openError !== undefined) return { error: scenario.openError };
    write({ id, event: { type: "progress", phase: "load", completed: 1, total: 2 } });
    if ((scenario.openDelayMs ?? 0) > 0) await sleep(scenario.openDelayMs);
    sessions += 1;
    return {
      result: { ...openResult(), ...(params.source?.kind === "dump" ? { thread: { tid: 4242, teb: "0x9a000" } } : {}) },
    };
  },
  "session.info": () => ({
    ...openResult(),
    state: {
      poisoned: false,
      named: [...named].map(([name, bytes]) => ({ name, bytes })),
      heapHigh: "0x0",
      calls: 0,
      vectors: 0,
    },
  }),
  "session.close": () => {
    sessions = Math.max(0, sessions - 1);
    return { closed: true };
  },
  "state.save": (id, p) => {
    named.set(p.name, 4096);
    return { name: p.name, bytes: 4096 };
  },
  "state.restore": (id, p) =>
    named.has(p.name) || p.name === "baseline"
      ? { result: { restored: p.name } }
      : { error: { code: "unknown_snapshot", message: "no such snapshot" } },
  "state.list": () => ({
    snapshots: [...named].map(([name, bytes]) => ({ name, bytes })),
    totalBytes: named.size * 4096,
    limitBytes: 512 * 1048576,
  }),
  "state.drop": (id, p) => ({ dropped: named.delete(p.name) }),
  "mem.read": (id, p) => {
    if (BigInt(p.address) < 0x10000n) return { error: { code: "unmapped", message: "unmapped" } };
    const memory = scenario.memory ?? "";
    const hex = (memory + "00".repeat(p.size)).slice(0, p.size * 2);
    return {
      result: {
        address: p.address,
        size: p.size,
        region: { region: "heap", kind: "heap" },
        data: hex,
        encoding: "hex",
        overlayRestored: 0,
      },
    };
  },
  "mem.disassemble": (id, p) => ({
    instructions: [{ va: p.address, rva: null, module: null, bytes: "c3", text: "ret" }],
    function: null,
  }),
  "mem.regions": () => ({
    regions: [
      {
        start: "0x180000000",
        end: "0x180010000",
        name: "mathlib.dll",
        kind: "image",
        perms: "r-x",
        module: "mathlib.dll",
      },
    ],
    syntheticBase: "0x7ff000000000",
  }),
  "emu.call": async (id, params) => {
    const { plan, vectors, options } = params;
    if (behaviourOf(plan) === "spin") return spinCall(id, plan, options);
    const v = runVector(plan, vectors, 0);
    return {
      result: {
        status: v.status,
        attribution: v.attribution,
        raw: {
          rax: v.rax === "" ? "0x0" : v.rax,
          xmm0: v.xmm0lo === "" ? "0x0" : v.xmm0lo,
          mxcsr: `0x${(options.mxcsr ?? 0x1f80).toString(16)}`,
          fpcw: `0x${(options.fpcw ?? 0x27f).toString(16)}`,
          fpsw: "0x0",
        },
        buffers: Object.fromEntries(
          Object.keys(v.out).map((name, k) => [name, `0x${(0x7ff000100000 + k * 0x1000).toString(16)}`]),
        ),
        out: v.out,
        stop: stopOf(v, "summary"),
        metrics: { wallUs: 12.5, instructions: 42, tbFlushes: 0 },
        ...(options.trace?.coverage || options.trace?.imports === "full"
          ? {
              trace: {
                ...(options.trace?.imports === "full" ? { imports: [] } : {}),
                ...(options.trace?.coverage ? { coverage: coverageWire() } : {}),
                truncated: {},
              },
            }
          : {}),
        events: [],
        deviations: deviationsOf(plan),
        deterministic: true,
        provenance: provenance(plan),
      },
    };
  },
  "emu.batch": async (id, params) => ({ result: await runBatch(id, params) }),
  "emu.sweep": (id, params) => ({
    summary: {
      functions: 2,
      completed: 2,
      byOutcomeProfile: { ok: 1, fault: 1 },
      matched: 1,
      deadlineReached: false,
      cancelled: false,
      nextOffset: null,
    },
    rows: [
      {
        rva: "0x1000",
        module: "mathlib.dll",
        statuses: ["ok"],
        rax: ["0x0"],
        xmm0lo: ["0x3f800000"],
        matches: ["sqrtf"],
      },
      { rva: "0x1040", module: "mathlib.dll", statuses: ["fault"], rax: [""], xmm0lo: [""], matches: [] },
    ],
    provenance: provenance(params.plan),
  }),
};

const finish = (id, outcome) => {
  if (outcome !== null && typeof outcome === "object" && ("result" in outcome || "error" in outcome))
    write({ id, ...outcome });
  else write({ id, result: outcome });
};

const pump = async () => {
  if (busy !== null) return;
  const next = queue.shift();
  if (next === undefined) return;
  if (next.eof === true) process.exit(0); // EOF is queued like the real reader's None sentinel
  busy = next.id;
  try {
    if (shouldCrash(next.method)) process.exit(70);
    if ((scenario.delays?.[next.method] ?? 0) > 0) await sleep(scenario.delays[next.method]);
    if (next.method === "bridge.shutdown") {
      write({ id: next.id, result: { shutdown: true } });
      process.exit(0);
    }
    const handler = handlers[next.method];
    if (handler === undefined) write({ id: next.id, error: { code: "unknown_method", message: next.method } });
    else if (cancelled.has(next.id) && !next.method.startsWith("emu.") && !scenario.ignoreCancel)
      write({ id: next.id, error: { code: "cancelled", message: "cancelled" } });
    else finish(next.id, await handler(next.id, next.params ?? {}));
  } finally {
    busy = null;
    setImmediate(pump);
  }
};

let pending = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  pending += chunk;
  let lf;
  while ((lf = pending.indexOf("\n")) !== -1) {
    const line = pending.slice(0, lf).replace(/\r$/u, "");
    pending = pending.slice(lf + 1);
    if (line.length === 0) continue;
    let frame;
    try {
      frame = JSON.parse(line);
    } catch {
      write({ id: null, error: { code: "parse_error", message: "bad json" } });
      continue;
    }
    if (frame.method === "bridge.ping") {
      write({ id: frame.id, result: { pong: true, busy, sessions } });
      continue;
    }
    if (frame.method === "bridge.cancel") {
      const target = frame.params?.requestId;
      const state = busy === target ? "running" : queue.some((q) => q.id === target) ? "queued" : "unknown";
      if (!scenario.ignoreCancel) cancelled.add(target);
      write({ id: frame.id, result: { cancelled: state !== "unknown", state } });
      continue;
    }
    queue.push(frame);
    void pump();
  }
});
process.stdin.on("end", () => {
  queue.push({ eof: true });
  void pump();
});
