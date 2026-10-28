import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { EXCEPTIONS_KIND } from "../../../src/application/instruments/kinds/exceptions.js";
import { MODULES_KIND } from "../../../src/application/instruments/kinds/modules.js";
import { OUTPUT_KIND } from "../../../src/application/instruments/kinds/output.js";
import { RECORDING_KINDS } from "../../../src/application/instruments/kinds/index.js";
import { Deadline } from "../../../src/domain/deadline.js";
import { silentLogger } from "../../../src/domain/logger.js";
import { ok } from "../../../src/domain/result.js";
import type { DecodeContext, EventRecord, RecordingKindSpec } from "../../../src/ports/recordings.js";
import { loadAgentBundle } from "../../../src/providers/frida/agentBundle.js";
import { FridaHost } from "../../../src/providers/frida/FridaHost.js";
import { readPeHeader } from "../../../src/providers/frida/peHeader.js";
import { FakeFrida } from "../../support/frida/fakeFrida.js";

const hostWith = (
  fake: FakeFrida,
  options: { loadModule?: () => Promise<ReturnType<FakeFrida["module"]>>; now?: () => number } = {},
) =>
  new FridaHost({
    logger: silentLogger,
    loadModule: options.loadModule ?? (async () => fake.module()),
    loadAgentBundle: async () =>
      ok({
        source: "",
        sha256: "",
        bytes: 0,
        protocol: "bea-agent/1",
        protocolMinor: 0,
        agentVersion: "0.1.0",
        buildId: "b",
        fridaVersion: "17.23.2",
        runtime: "qjs",
      }),
    now: options.now ?? (() => performance.now()),
    orphanOutputBytes: 16,
    orphanOutputTtlMs: 5000,
  });
const never = { signal: new AbortController().signal };

describe("FridaHost (S3 §4.2)", () => {
  it("loads once (single flight), never at availability(), and closes the device manager last", async () => {
    const fake = new FakeFrida();
    let loads = 0;
    const host = hostWith(fake, { loadModule: async () => ((loads += 1), fake.module()) });
    expect(host.availability().binding.state).toBe("not-loaded");
    expect(loads).toBe(0);
    const [a, b] = await Promise.all([host.device(never), host.device(never)]);
    expect(a.ok && b.ok).toBe(true);
    expect(loads).toBe(1);
    expect(host.availability()).toMatchObject({ binding: { state: "ready", version: "17.23.2" }, device: "ready" });
    expect(fake.signals.connected).toBe(1);
    const closed = await host.close(Deadline.after(250));
    expect(closed.ok).toBe(true);
    expect(fake.signals.disconnected).toBe(1);
    expect(fake.log.at(-1)).toBe("dm.close");
    expect((await host.device(never)).ok).toBe(false);
  });

  it("a failed import or a wrong version is permanent; a device failure retries after 5 s", async () => {
    const fake = new FakeFrida();
    const broken = hostWith(fake, { loadModule: async () => Promise.reject(new Error("addon missing")) });
    const first = await broken.device(never);
    expect(!first.ok && first.error._tag === "CapabilityUnavailable" && first.error.reason).toBe("import-failed");
    expect(broken.availability().binding).toMatchObject({ state: "failed", permanent: true });
    const wrong = hostWith(fake, { loadModule: async () => fake.module("16.0.0") });
    const version = await wrong.device(never);
    expect(!version.ok && version.error._tag === "CapabilityUnavailable" && version.error.reason).toBe(
      "version-failed",
    );
    let now = 0;
    fake.fail("getDevice", new Error("Device not found"));
    const flaky = hostWith(fake, { now: () => now });
    expect((await flaky.device(never)).ok).toBe(false);
    fake.failures.delete("getDevice");
    now = 1000;
    const soon = await flaky.device(never);
    expect(!soon.ok && soon.error._tag === "CapabilityUnavailable" && soon.error.retryable).toBe(true);
    now = 6000;
    expect((await flaky.device(never)).ok).toBe(true);
  });

  it("routes output by pid and buffers a little orphan output for a pid routed later", async () => {
    const fake = new FakeFrida();
    const host = hostWith(fake);
    await host.device(never);
    fake.output.emit(42, 1, Buffer.from("early"));
    fake.output.emit(43, 1, Buffer.from("x".repeat(64)));
    const got: string[] = [];
    const off = host.routeOutput(42, (fd, data) => got.push(`${String(fd)}:${data.toString()}`));
    fake.output.emit(42, 2, Buffer.from("late"));
    expect(got).toEqual(["1:early", "2:late"]);
    expect(host.orphanOutputBytes).toBe(69);
    off();
    fake.output.emit(42, 1, Buffer.from("after"));
    expect(got).toHaveLength(2);
  });
});

describe("agent bundle (D-INT-25)", () => {
  let dir = "";
  afterEach(async () => {
    if (dir !== "") await rm(dir, { recursive: true, force: true });
  });
  it("checks the manifest's protocol, frida version and sha256", async () => {
    dir = await mkdtemp(join(tmpdir(), "bea-bundle-"));
    const bundlePath = join(dir, "bea-agent.js");
    const manifestPath = join(dir, "bea-agent.json");
    await writeFile(bundlePath, "export {};\n");
    const manifest = {
      schema: "bea.agent-build/1",
      file: "bea-agent.js",
      sha256: "f9eff9a2c3f1f0b5b5b0d0a8e0e5c1e7a1a5d8b2e0f3a5b7c9d1e3f5a7b9c1d3",
      bytes: 11,
      runtime: "qjs",
      frida_version: "17.23.2",
      protocol: "bea-agent/1",
      protocol_minor: 0,
      agent_version: "0.1.0",
      build_id: "abc",
    };
    await writeFile(manifestPath, JSON.stringify(manifest));
    const files = {
      bundlePath,
      manifestPath,
      readText: (p: string) => import("node:fs/promises").then((fs) => fs.readFile(p, "utf8")),
    };
    const mismatch = await loadAgentBundle(files);
    expect(!mismatch.ok && mismatch.error.reason).toBe("hash-mismatch");
    const { createHash } = await import("node:crypto");
    await writeFile(
      manifestPath,
      JSON.stringify({ ...manifest, sha256: createHash("sha256").update("export {};\n").digest("hex") }),
    );
    const loaded = await loadAgentBundle(files);
    expect(loaded.ok && loaded.value.buildId).toBe("abc");
    await writeFile(manifestPath, JSON.stringify({ ...manifest, protocol: "bea-agent/2" }));
    const skew = await loadAgentBundle(files);
    expect(!skew.ok && skew.error.reason).toBe("protocol-mismatch");
    const missing = await loadAgentBundle({ ...files, bundlePath: join(dir, "nope.js") });
    expect(!missing.ok && missing.error.reason).toBe("bundle-missing");
  });
});

describe("PE preflight (S3 §8.1 step 1)", () => {
  let dir = "";
  afterEach(async () => {
    if (dir !== "") await rm(dir, { recursive: true, force: true });
  });
  it("refuses the committed PE32 fixture as wow64 and a non-PE as not-pe64; reports a missing file", async () => {
    const pe32 = join(import.meta.dirname, "..", "..", "..", "fixtures", "golden", "pe32-minimal.bin");
    const result = await readPeHeader(pe32, "spawn_process");
    expect(!result.ok && result.error._tag === "UnsupportedTarget" && result.error.reason).toBe("wow64");
    dir = await mkdtemp(join(tmpdir(), "bea-pe-"));
    await writeFile(
      join(dir, "text.exe"),
      "not a pe at all, just text with enough bytes to read the header area...........",
    );
    const text = await readPeHeader(join(dir, "text.exe"), "spawn_process");
    expect(!text.ok && text.error._tag === "UnsupportedTarget" && text.error.reason).toBe("not-pe64");
    const missing = await readPeHeader(join(dir, "missing.exe"), "spawn_process");
    expect(!missing.ok && missing.error._tag === "FileOperationFailed" && missing.error.reason).toBe("missing");
  });

  it("reads machine, ImageBase and the import DLL names of a PE32+ image", async () => {
    dir = await mkdtemp(join(tmpdir(), "bea-pe-"));
    const image = Buffer.alloc(0x400);
    image.write("MZ", 0, "latin1");
    image.writeUInt32LE(0x80, 0x3c);
    image.writeUInt32LE(0x4550, 0x80);
    image.writeUInt16LE(0x8664, 0x84);
    image.writeUInt16LE(1, 0x86); // one section
    image.writeUInt32LE(0x1234, 0x88);
    image.writeUInt16LE(240, 0x94); // optional header size
    const opt = 0x98;
    image.writeUInt16LE(0x20b, opt);
    image.writeBigUInt64LE(0x140000000n, opt + 24);
    image.writeUInt32LE(0x2000, opt + 56);
    image.writeUInt32LE(16, opt + 108);
    image.writeUInt32LE(0x1000, opt + 112 + 8); // import directory rva
    image.writeUInt32LE(40, opt + 112 + 12);
    const section = opt + 240;
    image.writeUInt32LE(0x1000, section + 8); // vsize
    image.writeUInt32LE(0x1000, section + 12); // va
    image.writeUInt32LE(0x200, section + 16); // raw size
    image.writeUInt32LE(0x200, section + 20); // raw ptr
    image.writeUInt32LE(0x1100, 0x200 + 12); // descriptor 0 name rva
    image.write("EasyAntiCheat_x64.dll\0", 0x300, "latin1");
    await writeFile(join(dir, "game.exe"), image);
    const parsed = await readPeHeader(join(dir, "game.exe"), "spawn_process");
    expect(parsed.ok && parsed.value).toMatchObject({
      machine: 0x8664,
      imageBase: "0x140000000",
      sizeOfImage: 0x2000,
      timeDateStamp: 0x1234,
      imports: ["EasyAntiCheat_x64.dll"],
      versionNames: [],
    });
  });

  it("reads VERSIONINFO OriginalFilename and InternalName (SEC-1: renamed interpreter copies)", async () => {
    dir = await mkdtemp(join(tmpdir(), "bea-pe-"));
    const image = Buffer.alloc(0x600);
    image.write("MZ", 0, "latin1");
    image.writeUInt32LE(0x80, 0x3c);
    image.writeUInt32LE(0x4550, 0x80);
    image.writeUInt16LE(0x8664, 0x84);
    image.writeUInt16LE(1, 0x86);
    image.writeUInt16LE(240, 0x94);
    const opt = 0x98;
    image.writeUInt16LE(0x20b, opt);
    image.writeBigUInt64LE(0x140000000n, opt + 24);
    image.writeUInt32LE(0x3000, opt + 56);
    image.writeUInt32LE(16, opt + 108);
    image.writeUInt32LE(0x2000, opt + 112 + 16); // resource directory rva
    image.writeUInt32LE(0x400, opt + 112 + 20);
    const section = opt + 240;
    image.writeUInt32LE(0x1000, section + 8);
    image.writeUInt32LE(0x2000, section + 12);
    image.writeUInt32LE(0x400, section + 16);
    image.writeUInt32LE(0x200, section + 20);
    const rsrc = 0x200; // file offset of rva 0x2000
    // root → RT_VERSION (16) → name 1 → language 0x409 → data entry → VS_VERSIONINFO strings
    image.writeUInt16LE(1, rsrc + 14);
    image.writeUInt32LE(16, rsrc + 16);
    image.writeUInt32LE(0x8000_0018, rsrc + 20);
    image.writeUInt16LE(1, rsrc + 0x18 + 14);
    image.writeUInt32LE(1, rsrc + 0x18 + 16);
    image.writeUInt32LE(0x8000_0030, rsrc + 0x18 + 20);
    image.writeUInt16LE(1, rsrc + 0x30 + 14);
    image.writeUInt32LE(0x409, rsrc + 0x30 + 16);
    image.writeUInt32LE(0x48, rsrc + 0x30 + 20);
    const at = 0x58;
    const strings: Buffer[] = [];
    for (const [key, value] of [
      ["OriginalFilename", "Cmd.Exe.MUI"],
      ["InternalName", "cmd"],
    ] as const) {
      const keyBytes = Buffer.from(`${key}\0`, "utf16le");
      const valueAt = (6 + keyBytes.length + 3) & ~3;
      const valueBytes = Buffer.from(`${value}\0`, "utf16le");
      const entry = Buffer.alloc((valueAt + valueBytes.length + 3) & ~3);
      entry.writeUInt16LE(valueAt + valueBytes.length, 0);
      entry.writeUInt16LE(value.length + 1, 2);
      entry.writeUInt16LE(1, 4);
      keyBytes.copy(entry, 6);
      valueBytes.copy(entry, valueAt);
      strings.push(entry);
    }
    const blob = Buffer.concat(strings);
    image.writeUInt32LE(0x2000 + at, rsrc + 0x48); // data entry: rva, size
    image.writeUInt32LE(blob.length, rsrc + 0x48 + 4);
    blob.copy(image, rsrc + at);
    await writeFile(join(dir, "x.exe"), image);
    const parsed = await readPeHeader(join(dir, "x.exe"), "spawn_process");
    expect(parsed.ok && parsed.value.versionNames).toEqual(["Cmd.Exe.MUI", "cmd"]);
  });
});

const ctx: DecodeContext = {
  sessionId: "s",
  decoders: null,
  startedAtUs: 1000,
  frame: (ref) => ({ at: ref === "0x7ff6a0001650" ? "game.exe+0x1650" : null, static: null }),
};
const run = <S>(spec: RecordingKindSpec<S>, rows: unknown[]) => {
  const events: EventRecord[] = rows.flatMap((fields, i) => [
    ...spec.decode({ seq: i + 1, module_map_epoch: 1, fields: fields as never }, ctx),
  ]);
  const state = spec.summary.init();
  for (const event of events) spec.summary.add(state, event);
  return { events, summary: spec.summary.finish(state) };
};

describe("built-in recording kinds (S6 §5.3, §5.4)", () => {
  it("are registered in the pre-wired kinds index", () => {
    expect(RECORDING_KINDS.exceptions).toBe(EXCEPTIONS_KIND);
    expect(RECORDING_KINDS.modules).toBe(MODULES_KIND);
    expect(RECORDING_KINDS.output).toBe(OUTPUT_KIND);
  });

  it("exceptions: rows → events with Loc text; summary counts repeats by type", () => {
    const { events, summary } = run(EXCEPTIONS_KIND, [
      [1, 3000, 7, "access-violation", "0x7ff6a0001650", "write", "0x0", "reported", 1],
      [2, 4000, 7, "breakpoint", "0x1", null, null, "passed", 3],
      ["garbage"],
    ]);
    expect(events[0]).toMatchObject({
      seq: 1,
      t_ms: 2,
      tid: 7,
      type: "access-violation",
      address: "game.exe+0x1650",
      memory_op: "write",
      memory_address: "0x0",
    });
    expect(events).toHaveLength(2);
    expect(summary).toEqual({
      count: 4,
      by_type: { "access-violation": 1, breakpoint: 3 },
      last: {
        seq: 2,
        type: "breakpoint",
        address: "0x1",
        memory_op: null,
        memory_address: null,
        disposition: "passed",
      },
    });
  });

  it("modules: load/unload events and a bounded summary", () => {
    const { events, summary } = run(MODULES_KIND, [
      [1, 2000, "L", "mathlib.dll", "C:\\g\\mathlib.dll", "0x180000000", 4096, 2],
      [2, 3000, "U", "mathlib.dll", "C:\\g\\mathlib.dll", "0x180000000", 4096, 3],
    ]);
    expect(events.map((e) => [e["event"], e["epoch"]])).toEqual([
      ["load", 2],
      ["unload", 3],
    ]);
    expect(summary).toEqual({
      loaded: 1,
      unloaded: 1,
      rows: [
        { event: "load", path: "C:\\g\\mathlib.dll", base: "0x180000000" },
        { event: "unload", path: "C:\\g\\mathlib.dll", base: "0x180000000" },
      ],
      truncated: false,
    });
  });

  it("output: host rows → fd/text events; summary with byte counts and a tail", () => {
    const { events, summary } = run(OUTPUT_KIND, [
      [5, 1, "READY\n", 0],
      [9, 2, "warn\n", 1],
    ]);
    expect(events[1]).toMatchObject({ seq: 2, t_ms: 9, fd: 2, text: "warn\n", invalid_utf8: true });
    expect(summary).toEqual({
      stdout_bytes: 6,
      stderr_bytes: 5,
      retained_bytes: 11,
      truncated: false,
      tail: "READY\nwarn\n",
      invalid_utf8: true,
    });
  });
});
