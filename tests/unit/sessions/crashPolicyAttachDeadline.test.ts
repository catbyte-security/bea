import { describe, expect, it } from "vitest";

import { loadConfig, type BeaConfig } from "../../../src/domain/config.js";
import { projectBeaError } from "../../../src/domain/errors/projection.js";
import { hostLimitsFrom } from "../../../src/providers/frida/hostLimits.js";
import { helloCrashPolicy } from "../../../src/providers/frida/startup.js";
import type { HelloParams } from "../../../src/shared/agentProtocol.js";
import { connectInMemoryBea } from "../../support/mcp/inMemory.js";
import { expectToolSuccess } from "../../support/mcp/parseToolError.js";
import { addForeign, createHarness, errTag } from "./support/harness.js";

/**
 * BEA-FEEDBACK items 3 and 4 on the host: the Frida attach deadline is limits.attach_timeout_ms /
 * BEA_ATTACH_TIMEOUT_MS on both startup paths and its timeout names the setting; the hello crash policy has blocking
 * first-chance reports off unless crash.first_chance_blocking / BEA_CRASH_FIRST_CHANCE_BLOCKING turns them on, carries
 * crash.passthrough_modules, and bea_status reports both.
 */
const configOf = async (
  env: Readonly<Record<string, string>>,
  file?: Readonly<Record<string, unknown>>,
): Promise<BeaConfig> => {
  const loaded = await loadConfig({
    env: { BEA_HOME: "C:/bea-home", ...env },
    platform: "win32",
    accountHome: "C:/Users/t",
    readConfigFile: async () => (file === undefined ? null : JSON.stringify({ schema: "bea.config/1", ...file })),
  });
  if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
  return loaded.value;
};

describe("host limits and the hello crash policy", () => {
  it("hostLimitsFrom: the attach deadline and the crash policy come from the configuration", async () => {
    const defaults = hostLimitsFrom(await configOf({}));
    expect(defaults.startup.attachMs).toBe(10_000);
    expect(defaults.crash).toEqual({ firstChanceBlocking: false, passthroughModules: [] });
    const configured = hostLimitsFrom(
      await configOf(
        { BEA_ATTACH_TIMEOUT_MS: "45000", BEA_CRASH_FIRST_CHANCE_BLOCKING: "1" },
        { crash: { passthrough_modules: ["nvwgf2um*.dll"] } },
      ),
    );
    expect(configured.startup.attachMs).toBe(45_000);
    expect(configured.crash).toEqual({ firstChanceBlocking: true, passthroughModules: ["nvwgf2um*.dll"] });
  });

  it("helloCrashPolicy: blocking first-chance reports off by default, the configured part on top of the defaults", () => {
    const off = helloCrashPolicy({ firstChanceBlocking: false, passthroughModules: [] });
    expect(off).toMatchObject({
      first_chance_rows: true,
      first_chance_blocking: false,
      crash_class: ["access-violation", "illegal-instruction", "stack-overflow", "arithmetic", "abort"],
      last_chance_ack_timeout_ms: 2000,
      backtrace_depth: 32,
      passthrough_modules: [],
    });
    const on = helloCrashPolicy({ firstChanceBlocking: true, passthroughModules: ["vehcommit.exe"] });
    expect(on.first_chance_blocking).toBe(true);
    expect(on.passthrough_modules).toEqual(["vehcommit.exe"]);
    // every call gets its own arrays (the hello is serialized per session)
    expect(on.crash_class).not.toBe(off.crash_class);
  });

  it("every session's hello carries the configured crash policy (spawn and attach)", async () => {
    const seen: HelloParams[] = [];
    const h = createHarness({
      limits: (l) => ({ ...l, crash: { firstChanceBlocking: true, passthroughModules: ["vehcommit.exe"] } }),
    });
    h.fake.defaultBehavior = {
      rpc: {
        hello: (params, script) => {
          seen.push(params as unknown as HelloParams);
          return { ok: true, value: h.fake.helloResult(script.pid) };
        },
      },
    };
    expect(errTag(await h.spawn())).toBe("ok");
    addForeign(h, 7300);
    expect(errTag(await h.attach(7300))).toBe("ok");
    expect(seen.map((p) => [p.crash.first_chance_blocking, p.crash.passthrough_modules])).toEqual([
      [true, ["vehcommit.exe"]],
      [true, ["vehcommit.exe"]],
    ]);
    await h.closeAll();
  });

  it("the default hello has blocking first-chance reports off", async () => {
    const seen: HelloParams[] = [];
    const h = createHarness();
    h.fake.defaultBehavior = {
      rpc: {
        hello: (params, script) => {
          seen.push(params as unknown as HelloParams);
          return { ok: true, value: h.fake.helloResult(script.pid) };
        },
      },
    };
    expect(errTag(await h.spawn())).toBe("ok");
    expect(seen[0]?.crash).toMatchObject({ first_chance_blocking: false, first_chance_rows: true });
    await h.closeAll();
  });
});

describe("the attach deadline (BEA-FEEDBACK #3)", () => {
  it.each(["spawn", "attach"] as const)(
    "a Frida attach that outlives limits.attach_timeout_ms (%s path) is a provider_timeout that names the setting",
    async (path) => {
      const h = createHarness({ limits: (l) => ({ ...l, startup: { ...l.startup, attachMs: 0 } }) });
      if (path === "attach") addForeign(h, 7400);
      const gate = h.fake.hold("attach");
      // the cancelled native attach rejects the way Frida does once its Cancellable fires
      h.fake.fail("attach", new Error("Operation was cancelled"));
      const pending = path === "spawn" ? h.spawn() : h.attach(7400);
      await gate.entered;
      // the step's deadline timer (0 ms) was armed before the held attach was entered, so it fires first
      await new Promise((resolve) => setTimeout(resolve, 0));
      gate.release();
      const result = await pending;
      expect(errTag(result)).toBe("ProviderTimeout");
      if (result.ok) return;
      expect(result.error).toMatchObject({ phase: "attach", timeout_ms: 0 });
      const projected = projectBeaError(result.error);
      expect(projected.code).toBe("provider_timeout");
      expect(projected.message).toContain("limits.attach_timeout_ms");
      expect(projected.message).toContain("BEA_ATTACH_TIMEOUT_MS");
      expect(projected.remediation.action).toContain("1000-110000 ms");
      expect(projected.details["diagnostics"]).toEqual({
        setting: "limits.attach_timeout_ms",
        env: "BEA_ATTACH_TIMEOUT_MS",
      });
      // an attached target is never killed; an owned one is cleaned up
      if (path === "attach") expect(h.fake.process(7400)?.alive).toBe(true);
      await h.closeAll();
    },
  );
});

describe("bea_status reports the crash policy and the attach deadline", () => {
  it("defaults", async () => {
    const bea = await connectInMemoryBea();
    try {
      const status = expectToolSuccess(await bea.client.callTool({ name: "bea_status", arguments: {} }));
      expect(status["crash"]).toEqual({
        first_chance_blocking: false,
        source: "default",
        env: "BEA_CRASH_FIRST_CHANCE_BLOCKING",
        passthrough_modules: [],
      });
      expect(status["limits"]).toMatchObject({ attach_timeout_ms: 10_000 });
    } finally {
      await bea.close();
    }
  });

  it("environment overrides", async () => {
    const bea = await connectInMemoryBea({
      env: { BEA_CRASH_FIRST_CHANCE_BLOCKING: "on", BEA_ATTACH_TIMEOUT_MS: "30000" },
    });
    try {
      const status = expectToolSuccess(await bea.client.callTool({ name: "bea_status", arguments: {} }));
      expect(status["crash"]).toMatchObject({ first_chance_blocking: true, source: "env" });
      expect(status["limits"]).toMatchObject({ attach_timeout_ms: 30_000 });
    } finally {
      await bea.close();
    }
  });
});
