import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Deadline } from "../../../src/domain/deadline.js";
import { jobHostEventSchema, type MitigationsWire } from "../../../src/domain/jobhostProtocol.js";
import { createJobHostFactory } from "../../../src/providers/process/createJobHostFactory.js";
import { decodeMitigations } from "../../../src/providers/process/ProcessInspector.js";
import { testCore, writeFakeBinary } from "./support/core.js";
import { createFakeLauncher, type FakeHelperChild } from "./support/fakeHelper.js";

/**
 * BEA-FEEDBACK item 1: `inspect.mitigations` (raw policy flags from GetProcessMitigationPolicy) → the decoded facts the
 * attach policy reads. Bit layouts are winnt.h's; a failed read is unknown (null + its Win32 error), never inferred.
 */
const read = (flags: number | null, win32 = 0) => ({ flags, win32 });
const wire = (over: Partial<MitigationsWire> = {}): MitigationsWire => ({
  access: "limited",
  signature: read(0),
  dynamicCode: read(0),
  userShadowStack: read(0),
  imageLoad: read(0),
  ...over,
});

const inspectLine = (mitigations?: unknown) => ({
  event: "inspect",
  pid: 4321,
  access: "limited+synchronize",
  exited: false,
  exitCode: null,
  creationTime100ns: "133000000000000001",
  imagePath: "C:\\chrome\\chrome.exe",
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
  integrityRid: 0x1000,
  sameUser: true,
  ...(mitigations === undefined ? {} : { mitigations }),
});

describe("decodeMitigations (winnt.h PROCESS_MITIGATION_*_POLICY bit layouts)", () => {
  it("decodes every named bit of the four policies and keeps the raw flags", () => {
    const m = decodeMitigations(
      wire({
        // MicrosoftSignedOnly | MitigationOptIn: what a runtime SetProcessMitigationPolicy opt-in reads back (lab)
        signature: read(0x5),
        dynamicCode: read(0b1111),
        // EnableUserShadowStack | CetDynamicApisOutOfProcOnly (Chrome's compat mode reads 0x101 on this host class)
        userShadowStack: read(0x101),
        imageLoad: read(0b11111),
      }),
    );
    expect(m.signature).toEqual({
      flags: 5,
      microsoftSignedOnly: true,
      storeSignedOnly: false,
      mitigationOptIn: true,
      auditMicrosoftSignedOnly: false,
      auditStoreSignedOnly: false,
    });
    expect(m.dynamicCode).toEqual({
      flags: 15,
      prohibitDynamicCode: true,
      allowThreadOptOut: true,
      allowRemoteDowngrade: true,
      auditProhibitDynamicCode: true,
    });
    expect(m.userShadowStack).toEqual({
      flags: 0x101,
      enableUserShadowStack: true,
      auditUserShadowStack: false,
      setContextIpValidation: false,
      auditSetContextIpValidation: false,
      enableUserShadowStackStrictMode: false,
      blockNonCetBinaries: false,
      blockNonCetBinariesNonEhcont: false,
      auditBlockNonCetBinaries: false,
      cetDynamicApisOutOfProcOnly: true,
      setContextIpValidationRelaxedMode: false,
    });
    expect(m.imageLoad).toEqual({
      flags: 31,
      noRemoteImages: true,
      noLowMandatoryLabelImages: true,
      preferSystem32Images: true,
      auditNoRemoteImages: true,
      auditNoLowMandatoryLabelImages: true,
    });
    expect(m.unreadable).toEqual([]);
    expect(m.access).toBe("limited");
  });

  it("each single bit maps to exactly one field (no shifted layout)", () => {
    for (let n = 0; n < 5; n += 1) {
      const sig = decodeMitigations(wire({ signature: read(1 << n) })).signature;
      const set = Object.entries(sig ?? {}).filter(([key, value]) => key !== "flags" && value === true);
      expect(set.map(([key]) => key)).toEqual([
        [
          "microsoftSignedOnly",
          "storeSignedOnly",
          "mitigationOptIn",
          "auditMicrosoftSignedOnly",
          "auditStoreSignedOnly",
        ][n],
      ]);
    }
    const strict = decodeMitigations(wire({ userShadowStack: read(1 << 4) })).userShadowStack;
    expect(strict?.enableUserShadowStackStrictMode).toBe(true);
    expect(strict?.enableUserShadowStack).toBe(false);
    expect(decodeMitigations(wire({ userShadowStack: read(1 << 5) })).userShadowStack?.blockNonCetBinaries).toBe(true);
    // unnamed (reserved) bits stay visible in flags only
    expect(decodeMitigations(wire({ signature: read(1 << 20) })).signature).toMatchObject({
      flags: 1 << 20,
      microsoftSignedOnly: false,
      storeSignedOnly: false,
    });
  });

  it("a policy that could not be read is null (unknown) and listed with its Win32 error; the others still decode", () => {
    const m = decodeMitigations(
      wire({ access: "query", signature: read(null, 5), userShadowStack: read(null, 87), dynamicCode: read(1) }),
    );
    expect(m.signature).toBeNull();
    expect(m.userShadowStack).toBeNull();
    expect(m.dynamicCode?.prohibitDynamicCode).toBe(true);
    expect(m.imageLoad?.flags).toBe(0);
    expect(m.unreadable).toEqual([
      { policy: "signature", win32: 5 },
      { policy: "userShadowStack", win32: 87 },
    ]);
    expect(m.access).toBe("query");
  });
});

describe("inspect line schema (protocol 1, additive mitigations)", () => {
  it("accepts the line with and without mitigations and rejects malformed policy reads", () => {
    expect(jobHostEventSchema.safeParse(inspectLine(wire())).success).toBe(true);
    // a helper built before the field: still a valid line (mitigations unknown)
    expect(jobHostEventSchema.safeParse(inspectLine()).success).toBe(true);
    for (const bad of [
      { ...wire(), access: "full" },
      { ...wire(), signature: { flags: -1, win32: 0 } },
      { ...wire(), signature: { flags: 1 } },
      { ...wire(), dynamicCode: { flags: 1, win32: 0, extra: true } },
      { access: "limited", signature: read(0), dynamicCode: read(0), userShadowStack: read(0) },
      null,
    ])
      expect(jobHostEventSchema.safeParse(inspectLine(bad)).success, JSON.stringify(bad)).toBe(false);
  });
});

describe("JobHostFactory.inspect (fake helper)", () => {
  let dir: string;
  let binary: { exePath: string; manifestPath: string; sha256: string };
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "bea-mitigations-"));
    binary = await writeFakeBinary(join(dir, "ok"));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  const inspectWith = (mitigations?: unknown) => async () => {
    const launcher = createFakeLauncher(
      (c: FakeHelperChild) =>
        void setImmediate(() => {
          c.hello();
          c.line(inspectLine(mitigations));
          c.exit(0);
        }),
    );
    const factory = createJobHostFactory(await testCore("win32"), { ...binary, launch: launcher.launch });
    return factory.inspect(4321, Deadline.after(1000));
  };

  it("maps the wire policies to ProcessInspection.mitigations", async () => {
    const result = await inspectWith(
      wire({ signature: read(5), dynamicCode: read(1), userShadowStack: read(null, 87) }),
    )();
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(result.value.mitigations).toMatchObject({
      access: "limited",
      signature: { microsoftSignedOnly: true, mitigationOptIn: true },
      dynamicCode: { prohibitDynamicCode: true },
      userShadowStack: null,
      unreadable: [{ policy: "userShadowStack", win32: 87 }],
    });
  });

  it("a line without mitigations gives null (unknown), not a guess", async () => {
    const result = await inspectWith()();
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(result.value.mitigations).toBeNull();
  });
});
