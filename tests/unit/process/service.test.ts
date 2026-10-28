import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Deadline } from "../../../src/domain/deadline.js";
import { HelperLocator } from "../../../src/providers/process/HelperLocator.js";
import { createJobHostFactory } from "../../../src/providers/process/createJobHostFactory.js";
import { JobHostService } from "../../../src/providers/process/JobHostService.js";
import { testCore, writeFakeBinary } from "./support/core.js";
import { createFakeLauncher, scriptAdopt, type FakeHelperChild } from "./support/fakeHelper.js";

let dir: string;
let binary: { exePath: string; manifestPath: string; sha256: string };

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "bea-wp2-service-"));
  binary = await writeFakeBinary(join(dir, "ok"));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

const probeLine = (ok: boolean) => ({
  event: "probe",
  ok,
  jobPolicyVerified: true,
  jobListAttribute: true,
  assignedBeforeFirstInstruction: ok,
  adoptAssign: true,
  terminateJob: true,
  helperInJob: true,
  statusFd3: true,
});

/** One-shot modes the way bea-jobhost runs them: hello, the decisive line, exit. */
const oneShots =
  (probeOk = true) =>
  (c: FakeHelperChild): void =>
    void setImmediate(() => {
      c.hello();
      if (c.mode === "probe") c.line(probeLine(probeOk));
      if (c.mode === "inspect")
        c.line({
          event: "inspect",
          pid: Number(c.args[1]),
          access: "limited+synchronize",
          exited: false,
          exitCode: null,
          creationTime100ns: "133000000000000001",
          imagePath: "C:\\node\\node.exe",
          parentPid: 10,
          sessionId: 1,
          critical: false,
          protectionLevel: 0xfffffffe,
          protected: false,
          wow64: false,
          processMachine: 0,
          nativeMachine: 0x8664,
          inJob: true,
          elevated: false,
          integrityRid: 0x2000,
          sameUser: true,
        });
      c.exit(c.mode === "probe" && !probeOk ? 0xbea9 : 0);
    });

describe("HelperLocator (S3 §5.6)", () => {
  it("accepts a binary whose sha256 matches the manifest and memoizes it", async () => {
    const locator = new HelperLocator({ ...binary, platform: "win32" });
    const first = await locator.locate();
    expect(first).toMatchObject({ ok: true, value: { path: binary.exePath, sha256: binary.sha256, protocol: 1 } });
    expect(await locator.locate()).toEqual(first);
  });

  it("refuses missing files, digest mismatches, bad manifests, other protocols and other platforms", async () => {
    const reason = async (opts: { exePath: string; manifestPath: string; platform?: "win32" | "linux" }) => {
      const r = await new HelperLocator({ platform: "win32", ...opts }).locate();
      return r.ok ? null : r.error._tag === "CapabilityUnavailable" ? r.error.reason : r.error._tag;
    };
    expect(await reason({ ...binary, exePath: join(dir, "nope.exe") })).toBe("binary-missing");
    expect(await reason({ ...binary, manifestPath: join(dir, "nope.json") })).toBe("manifest-missing");
    expect(await reason({ ...binary, platform: "linux" })).toBe("unsupported-platform");
    const drift = await writeFakeBinary(join(dir, "drift"), { sha256: "0".repeat(64) });
    expect(await reason(drift)).toBe("binary-digest-mismatch");
    const proto = await writeFakeBinary(join(dir, "proto"), { protocol: 2 });
    expect(await reason(proto)).toBe("protocol-mismatch");
    const broken = await writeFakeBinary(join(dir, "broken"));
    await writeFile(broken.manifestPath, "{not json");
    expect(await reason(broken)).toBe("manifest-invalid");
  });
});

describe("createJobHostFactory registrations", () => {
  it("is construction-cheap and registers status, doctor checks (win32) and the shutdown closer", async () => {
    const core = await testCore("win32");
    const launcher = createFakeLauncher(oneShots());
    const factory = createJobHostFactory(core, { ...binary, launch: launcher.launch });
    expect(launcher.children).toHaveLength(0);
    expect(factory.availability()).toEqual({ state: "not-checked", sha256: null, reason: null, probe: null });
    expect(core.doctor.list().map((c) => [c.name, c.scope])).toEqual([
      ["jobhost:binary", "backend:frida"],
      ["jobhost:probe", "backend:frida"],
      ["host:elevation", "informational"],
    ]);
    const status = await core.status.collect();
    expect(status.backends).toEqual([{ id: "jobhost", state: "available", version: "0.1.0", detail: "probe ok" }]);
    expect(factory.availability()).toMatchObject({ state: "available", sha256: binary.sha256, probe: { ok: true } });
    const report = await core.lifecycle.closeAll("test");
    expect(report.ok).toBe(true);
  });

  it("doctor checks report binary, probe and elevation from the helper", async () => {
    const core = await testCore("win32");
    const launcher = createFakeLauncher(oneShots());
    createJobHostFactory(core, { ...binary, launch: launcher.launch });
    const signal = new AbortController().signal;
    const results = await Promise.all(core.doctor.list().map((c) => c.run(signal)));
    expect(results.map((r) => [r.name, r.ok, r.classification])).toEqual([
      ["jobhost:binary", true, "healthy"],
      ["jobhost:probe", true, "healthy"],
      ["host:elevation", true, "healthy"],
    ]);
    expect(results[2]?.detail).toContain("integrity: medium");
    expect(launcher.children.find((c) => c.mode === "inspect")?.args).toEqual(["inspect", String(process.pid)]);
  });

  it("doctor reports a missing binary as missing_dependency with build remediation", async () => {
    const core = await testCore("win32");
    createJobHostFactory(core, {
      exePath: join(dir, "missing.exe"),
      manifestPath: join(dir, "missing.json"),
      launch: createFakeLauncher().launch,
    });
    const binaryCheck = core.doctor.list().find((c) => c.name === "jobhost:binary");
    const result = await binaryCheck?.run(new AbortController().signal);
    expect(result).toMatchObject({ ok: false, classification: "missing_dependency" });
    expect(result?.remediation).toContain("npm run build");
    const status = await core.status.collect();
    expect(status.backends[0]).toMatchObject({ id: "jobhost", state: "unavailable", detail: "binary-missing" });
  });

  it("a failed probe is not memoized and shows as failed; a later success is", async () => {
    const core = await testCore("win32");
    let probeOk = false;
    const launcher = createFakeLauncher((c) => oneShots(probeOk)(c));
    const factory = createJobHostFactory(core, { ...binary, launch: launcher.launch });
    expect(await factory.probe(Deadline.after(1000))).toMatchObject({ ok: true, value: { ok: false } });
    expect(factory.availability()).toMatchObject({ state: "unavailable", reason: "probe-failed" });
    expect((await core.status.collect()).backends[0]).toMatchObject({
      state: "failed",
      detail: "probe failed: assigned-before-first-instruction",
    });
    probeOk = true;
    expect(await factory.probe(Deadline.after(1000))).toMatchObject({ ok: true, value: { ok: true } });
    const launched = launcher.children.length;
    expect(await factory.probe(Deadline.after(1000))).toMatchObject({ ok: true, value: { ok: true } });
    expect(launcher.children.length).toBe(launched);
  });

  it("linux: no doctor checks, an unavailable status row and /proc-free availability", async () => {
    const core = await testCore("linux");
    const factory = createJobHostFactory(core, { ...binary, launch: createFakeLauncher().launch });
    expect(core.doctor.list()).toEqual([]);
    expect(factory.availability()).toMatchObject({ state: "unavailable", reason: "unsupported-platform" });
    expect((await core.status.collect()).backends[0]).toMatchObject({ id: "jobhost", state: "unavailable" });
    expect(
      await factory.adopt({
        pid: 1,
        creationTime100ns: 1n,
        tolerance100ns: 0n,
        expectImage: "C:\\a.exe",
        expectParentPid: 1,
        deadline: Deadline.after(100),
      }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "CapabilityUnavailable", reason: "unsupported-platform" },
    });
  });

  it("inspect maps the wire event to ProcessInspection", async () => {
    const core = await testCore("win32");
    const factory = createJobHostFactory(core, { ...binary, launch: createFakeLauncher(oneShots()).launch });
    const result = await factory.inspect(4321, Deadline.after(1000));
    expect(result).toMatchObject({
      ok: true,
      value: {
        pid: 4321,
        osSessionId: 1,
        creationTime100ns: 133000000000000001n,
        nativeMachine: 0x8664,
        integrityRid: 0x2000,
      },
    });
    expect(await factory.inspect(2 ** 32, Deadline.after(1000))).toMatchObject({
      ok: false,
      error: { _tag: "InputError" },
    });
  });
});

describe("shutdown backstop", () => {
  it("kills helpers their owners left alive and refuses new owned helpers while closing", async () => {
    const core = await testCore("win32");
    const launcher = createFakeLauncher((c) => scriptAdopt(c));
    const service = new JobHostService(core, { ...binary, launch: launcher.launch });
    core.lifecycle.register({ name: "jobhost", phase: "teardown-targets", close: (s) => service.closeAll(s) });
    const adopted = await service.adopt({
      pid: 1,
      creationTime100ns: 1n,
      tolerance100ns: 0n,
      expectImage: "C:\\a.exe",
      expectParentPid: 1,
      deadline: Deadline.after(1000),
    });
    if (!adopted.ok) throw new Error("adopt failed");
    const report = await core.lifecycle.closeAll("test");
    expect(report.ok).toBe(true);
    expect(launcher.last().control).toEqual(["kill", "<eof>"]);
    expect(await adopted.value.settled).toMatchObject({ method: "control-kill" });
    expect(service.live).toEqual({ owned: 0, watchers: 0 });
    expect(
      await service.adopt({
        pid: 1,
        creationTime100ns: 1n,
        tolerance100ns: 0n,
        expectImage: "C:\\a.exe",
        expectParentPid: 1,
        deadline: Deadline.after(100),
      }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "CapabilityUnavailable", reason: "shutting-down" },
    });
  });

  it("terminates unresponsive helpers when the phase budget aborts", async () => {
    const core = await testCore("win32");
    const launcher = createFakeLauncher((c) => scriptAdopt(c, { respond: false }));
    const service = new JobHostService(core, { ...binary, launch: launcher.launch });
    const adopted = await service.adopt({
      pid: 1,
      creationTime100ns: 1n,
      tolerance100ns: 0n,
      expectImage: "C:\\a.exe",
      expectParentPid: 1,
      deadline: Deadline.after(1000),
    });
    if (!adopted.ok) throw new Error("adopt failed");
    const budget = new AbortController();
    const closing = service.closeAll(budget.signal);
    budget.abort({ kind: "deadline", ms: 0 });
    await closing;
    expect(launcher.last().killed).toBe(true);
    expect(await adopted.value.settled).toMatchObject({ method: "helper-terminated" });
  });
});
