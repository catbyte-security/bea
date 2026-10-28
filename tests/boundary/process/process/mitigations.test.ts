import { spawn, type ChildProcess } from "node:child_process";
import { dirname } from "node:path";

import { afterAll, beforeAll, expect, it, vi } from "vitest";

import { resolveDistLayout } from "../../../../src/application/distLayout.js";
import { Deadline } from "../../../../src/domain/deadline.js";
import type { ProcessMitigations } from "../../../../src/domain/jobhostProtocol.js";
import { JobHostService } from "../../../../src/providers/process/JobHostService.js";
import {
  fixtureArtifact,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureId,
} from "../../../support/acceptance/fixtures.js";
import { pidStatus } from "../../../support/process/ownedPidLedger.js";
import { testCore } from "../../../unit/process/support/core.js";

/**
 * Process lane, BEA-FEEDBACK item 1: `bea-jobhost inspect` reads a target's mitigation policies through the BUILT
 * helper (BEA_DIST_DIR snapshot or dist/). mitigated.exe turns Code Integrity Guard (--cig) and Arbitrary Code Guard
 * (--acg) on for itself and prints its own GetProcessMitigationPolicy readback; inspect must agree with it, report the
 * policies off for a plain instance, and never guess. Targets are this file's own children, killed in afterAll.
 */
const SKIP = jobhostSkip() || gccSkip();
/** Registered in scripts/lib/fixtures.mjs; the FixtureId union in fixtures.d.mts does not list it yet. */
const MITIGATED: FixtureId = "mitigated";

let service: JobHostService;
let exe = "";
const children: ChildProcess[] = [];

beforeAll(async () => {
  if (SKIP !== false) return;
  const layout = resolveDistLayout();
  service = new JobHostService(await testCore("win32"), {
    exePath: layout.jobhostExe,
    manifestPath: layout.jobhostManifest,
  });
  const artifact = fixtureArtifact(await loadFixtures(), MITIGATED);
  if (artifact === null) throw new Error("fixtures unavailable");
  exe = artifact.path;
}, 120_000);

afterAll(() => {
  for (const child of children) if (child.exitCode === null) child.kill();
});

/** mitigated.exe with `flags`; resolves with its pid and READY line once the mitigations are on. */
const start = async (flags: readonly string[]): Promise<{ readonly pid: number; readonly ready: string }> => {
  const child = spawn(exe, [...flags, "--lifetime-ms", "120000"], {
    cwd: dirname(exe),
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  });
  children.push(child);
  let out = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    out += chunk.toString();
  });
  // a whole line (msvcrt text mode ends it with \r\n)
  await vi.waitFor(() => expect(out).toMatch(/^(READY|ERROR) [^\r\n]*\r?\n/mu), { interval: 20, timeout: 10_000 });
  const ready = /^READY .*$/mu.exec(out)?.[0];
  if (ready === undefined) throw new Error(`mitigated.exe ${flags.join(" ")}: ${out}`);
  return { pid: child.pid ?? 0, ready };
};

const mitigationsOf = async (pid: number): Promise<ProcessMitigations> => {
  const inspected = await service.inspect(pid, Deadline.after(5000));
  if (!inspected.ok) throw new Error(JSON.stringify(inspected.error));
  if (inspected.value.mitigations === null || inspected.value.mitigations === undefined)
    throw new Error("inspect reported no mitigations (helper older than the field?)");
  return inspected.value.mitigations;
};

const readyFlags = (ready: string, key: string): number =>
  Number.parseInt(new RegExp(`${key}=0x([0-9a-f]+)`, "u").exec(ready)?.[1] ?? "x", 16);

/** Named skip (missing toolchain or build only). */
const lane = (title: string, body: () => Promise<void>) => it.skipIf(SKIP !== false)(`${title}${skipNote(SKIP)}`, body);

lane("inspect reports Code Integrity Guard and Arbitrary Code Guard a process turned on for itself", async () => {
  const { pid, ready } = await start(["--cig", "--acg"]);
  expect(ready).toContain("cig=1 acg=1");
  const m = await mitigationsOf(pid);
  expect(m).toMatchObject({
    access: "limited",
    signature: { microsoftSignedOnly: true, storeSignedOnly: false },
    dynamicCode: { prohibitDynamicCode: true, allowThreadOptOut: false, allowRemoteDowngrade: false },
    imageLoad: { noRemoteImages: false, noLowMandatoryLabelImages: false },
    unreadable: [],
  });
  // the helper's view equals the process's own readback, bit for bit
  expect(m.signature?.flags).toBe(readyFlags(ready, "signature_flags"));
  expect(m.dynamicCode?.flags).toBe(readyFlags(ready, "dynamic_code_flags"));
  expect(m.userShadowStack).not.toBeNull();
  expect(pidStatus(null, pid).alive).toBe(true);
});

lane("one mitigation at a time, a plain instance, and the test's own node.exe", async () => {
  const cig = await mitigationsOf((await start(["--cig"])).pid);
  expect(cig.signature?.microsoftSignedOnly).toBe(true);
  expect(cig.dynamicCode?.prohibitDynamicCode).toBe(false);
  const acg = await mitigationsOf((await start(["--acg"])).pid);
  expect(acg.signature?.microsoftSignedOnly).toBe(false);
  expect(acg.dynamicCode?.prohibitDynamicCode).toBe(true);
  const plain = await mitigationsOf((await start([])).pid);
  expect(plain).toMatchObject({
    signature: { flags: 0, microsoftSignedOnly: false },
    dynamicCode: { flags: 0, prohibitDynamicCode: false },
    unreadable: [],
  });
  const self = await mitigationsOf(process.pid);
  expect(self.signature?.microsoftSignedOnly).toBe(false);
  expect(self.dynamicCode?.prohibitDynamicCode).toBe(false);
  expect(self.unreadable).toEqual([]);
});
