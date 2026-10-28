import { mkdir, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { BeaCore } from "../../../src/application/BeaApplication.js";
import type { DistLayout } from "../../../src/application/distLayout.js";
import type { DoctorCheckDefinition } from "../../../src/application/doctor.js";
import type { DoctorReport } from "../../../src/cli/doctor/runDoctor.js";
import { composeServices } from "../../../src/main/composeServices.js";
import { fakeServices } from "../../support/fakes/fakeServices.js";
import { runCliInProcess, type CliHarnessOptions } from "../../support/cli/harness.js";
import { createPackageLayout } from "../../support/cli/packageLayout.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

let home: TempHome;
let layout: DistLayout;
beforeEach(async () => {
  home = await createTempHome("cli-doctor");
  layout = await createPackageLayout(join(home.root, "pkg"));
});
afterEach(async () => {
  await home.cleanup();
});

const listing = async (dir: string) => (await readdir(dir, { recursive: true })).sort();
const doctor = async (argv: readonly string[], extra: Partial<CliHarnessOptions> = {}) => {
  const r = await runCliInProcess(["doctor", "--json", ...argv], { home, layout, ...extra });
  return { ...r, report: r.doc() as unknown as DoctorReport };
};

/** A services factory that registers doctor checks like SESS/PROC/EMU factories do. */
const withChecks = (checks: readonly DoctorCheckDefinition[], ran: string[]) => async (core: BeaCore) => {
  for (const check of checks)
    core.doctor.add({
      ...check,
      run: async (signal) => {
        ran.push(check.name);
        return check.run(signal);
      },
    });
  return fakeServices()(core);
};
const passing = (name: string, scope: DoctorCheckDefinition["scope"]): DoctorCheckDefinition => ({
  name,
  scope,
  run: async () => ({ name, ok: true, classification: "healthy" }),
});

describe("bea doctor (S1 §7.8)", () => {
  it("is read-only: a missing BEA_HOME is not created and nothing under the temp root changes", async () => {
    const fresh = join(home.root, "fresh-home");
    const before = await listing(home.root);
    const r = await doctor([], { env: { BEA_HOME: fresh } });
    expect(r.report.schema).toBe("bea.doctor/1");
    expect(r.report.scope.mode).toBe("audit-wide");
    expect(r.report.scope_checks.find((c) => c.name === "home")).toMatchObject({ ok: true });
    expect(r.report.scope_checks.find((c) => c.name === "home")?.detail).toContain("does not exist yet");
    await expect(stat(fresh)).rejects.toThrow();
    expect(await listing(home.root)).toEqual(before);
  });
  it("production service factories construct without writing anything (CI-M20)", async () => {
    const fresh = join(home.root, "fresh-home");
    const before = await listing(home.root);
    const r = await doctor(["--client", "cursor"], { env: { BEA_HOME: fresh }, services: composeServices });
    expect(r.report.scope.mode).toBe("explicit");
    await expect(stat(fresh)).rejects.toThrow();
    expect(await listing(home.root)).toEqual(before);
  });
  it("audit-wide: a detected client without a registration makes it unhealthy (exit 1)", async () => {
    await mkdir(join(home.home, ".claude"));
    const r = await doctor([]);
    expect(r.code).toBe(1);
    expect(r.report.healthy).toBe(false);
    expect(r.report.scope_checks.find((c) => c.name === "registration:claude_code")).toMatchObject({
      ok: false,
      classification: "missing_dependency",
    });
    expect(r.report.scope_checks.find((c) => c.name === "skill")).toMatchObject({ ok: false });
    expect(r.report.identity.registrations.find((reg) => reg.client === "claude_code")).toMatchObject({
      detected: true,
      state: "missing",
    });
  });
  it("without Claude Code a missing skill is informational and never makes the environment unhealthy (ONBOARD-10)", async () => {
    await mkdir(join(home.home, ".cursor"));
    expect((await runCliInProcess(["setup", "--client", "cursor", "--yes"], { home, layout })).code).toBe(0);
    const r = await doctor([]);
    expect(r.code).toBe(0);
    expect(r.report.healthy).toBe(true);
    expect(r.report.identity.registrations.find((reg) => reg.client === "claude_code")).toMatchObject({
      detected: false,
    });
    expect(r.report.informational_checks.find((c) => c.name === "skill")).toMatchObject({ ok: false });
    expect(r.report.environment_healthy).toBe(true);
  });
  it("explicit scope: only scoped checks decide healthy; other detected clients become informational", async () => {
    await mkdir(join(home.home, ".claude"));
    await mkdir(join(home.home, ".cursor"));
    expect((await runCliInProcess(["setup", "--client", "cursor", "--yes"], { home, layout })).code).toBe(0);
    const r = await doctor(["--client", "cursor"]);
    expect(r.code).toBe(0);
    expect(r.report.healthy).toBe(true);
    expect(r.report.environment_healthy).toBe(false);
    expect(r.report.scope_checks.map((c) => c.name)).toEqual(
      expect.arrayContaining(["node", "platform", "config", "home", "registration:cursor"]),
    );
    expect(r.report.informational_checks.map((c) => c.name)).toEqual(
      expect.arrayContaining(["registration:claude_code", "skill"]),
    );
    const skill = await doctor(["--skill"]);
    expect(skill.code).toBe(1);
    expect(skill.report.scope_checks.find((c) => c.name === "skill")).toMatchObject({
      classification: "missing_dependency",
    });
    expect((await runCliInProcess(["setup", "--skill", "--yes"], { home, layout })).code).toBe(0);
    expect((await doctor(["--skill"])).code).toBe(0);
  });
  it("registered checks: backend checks only with --backend, probes only with --probe, throws become runtime_failure", async () => {
    const ran: string[] = [];
    const services = withChecks(
      [
        passing("jobhost:binary", "always"),
        passing("host:elevation", "informational"),
        {
          name: "frida:binding",
          scope: "backend:frida",
          run: async () => ({ name: "frida:binding", ok: true, classification: "healthy", detail: "frida 17.23.2" }),
        },
        {
          name: "emulator:python",
          scope: "backend:emulation",
          run: async () => {
            throw new Error("python missing");
          },
        },
        passing("frida:inject-probe", "probe"),
      ],
      ran,
    );
    const plain = await doctor([], { services });
    expect(ran).toEqual(["jobhost:binary", "host:elevation"]);
    expect(plain.report.identity.frida_version).toBeNull();
    expect(plain.report.informational_checks.map((c) => c.name)).toContain("host:elevation");
    ran.length = 0;
    const frida = await doctor(["--backend", "frida"], { services });
    expect(ran).toEqual(["jobhost:binary", "host:elevation", "frida:binding"]);
    expect(frida.code).toBe(0);
    expect(frida.report.identity.frida_version).toBe("17.23.2");
    ran.length = 0;
    const emu = await doctor(["--backend", "emulation", "--probe"], { services });
    expect(ran).toEqual(["jobhost:binary", "host:elevation", "emulator:python", "frida:inject-probe"]);
    expect(emu.code).toBe(1);
    expect(emu.report.scope_checks.find((c) => c.name === "emulator:python")).toMatchObject({
      ok: false,
      classification: "runtime_failure",
      detail: "python missing",
    });
    expect((await doctor(["--backend", "gpu"])).doc()).toMatchObject({ error: { code: "invalid_request" } });
  });
  it("an invalid configuration fails the config check and skips registered checks; unknown BEA_* is informational", async () => {
    const ran: string[] = [];
    const services = withChecks([passing("jobhost:binary", "always")], ran);
    const bad = await doctor([], { services, env: { BEA_LOG_LEVEL: "loud" } });
    expect(bad.code).toBe(1);
    expect(bad.report.scope_checks.find((c) => c.name === "config")).toMatchObject({
      ok: false,
      classification: "configuration_invalid",
    });
    expect(ran).toEqual([]);
    const typo = await doctor([], { services, env: { BEA_LOG_LEVLE: "info" } });
    expect(typo.code).toBe(0);
    expect(typo.report.informational_checks.find((c) => c.name === "config:unknown-env")).toMatchObject({ ok: false });
    // advisory: the typo does not change environment_healthy (the uninstalled skill alone decides it here)
    expect(typo.report.environment_healthy).toBe((await doctor([], { services })).report.environment_healthy);
  });
});

describe("bea doctor probes (S1 §7.8)", () => {
  it("emulator probes need --backend emulation as well (S1 §7.8); frida:inject-probe needs only --probe", async () => {
    const ran: string[] = [];
    const services = withChecks(
      [
        passing("frida:inject-probe", "probe"),
        passing("emulation:start", "probe"),
        passing("emulator:bridge", "probe"),
      ],
      ran,
    );
    expect((await doctor(["--backend", "frida", "--probe"], { services })).code).toBe(0);
    expect(ran).toEqual(["frida:inject-probe"]);
    ran.length = 0;
    expect((await doctor(["--probe"], { services })).code).toBe(0);
    expect(ran).toEqual(["frida:inject-probe"]);
    ran.length = 0;
    expect((await doctor(["--backend", "emulation", "--probe"], { services })).code).toBe(0);
    expect(ran).toEqual(["frida:inject-probe", "emulation:start", "emulator:bridge"]);
  });
  it("a probe leaves nothing behind: its CLI run, and runs/, emu/ and BEA_HOME when doctor created them", async () => {
    const fresh = join(home.root, "fresh-home");
    const before = await listing(home.root);
    let runDir = "";
    const services = async (core: BeaCore) => {
      core.doctor.add({
        name: "frida:inject-probe",
        scope: "probe",
        run: async () => {
          // What the real probe's session does through the evidence runtime (instances, streams, run.json).
          runDir = core.config.layout.runDir(core.run.runId);
          await mkdir(join(runDir, "streams"), { recursive: true });
          await writeFile(join(runDir, "run.json"), "{}");
          // and what emulation:start does: the bridge's working directory is BEA_HOME/emu
          await mkdir(core.config.layout.emuDir, { recursive: true });
          return { name: "frida:inject-probe", ok: true, classification: "healthy" };
        },
      });
      return fakeServices()(core);
    };
    const r = await doctor(["--probe"], { env: { BEA_HOME: fresh }, services });
    expect(r.code).toBe(0);
    expect(runDir.startsWith(fresh)).toBe(true);
    await expect(stat(fresh)).rejects.toThrow();
    expect(await listing(home.root)).toEqual(before);

    // An existing home keeps everything that was there; only the probe's run goes.
    await mkdir(join(fresh, "runs", "run_earlier"), { recursive: true });
    expect((await doctor(["--probe"], { env: { BEA_HOME: fresh }, services })).code).toBe(0);
    expect(await listing(fresh)).toEqual(["runs", join("runs", "run_earlier")]);
  });
});
