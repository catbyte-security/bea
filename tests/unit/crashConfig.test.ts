import { describe, expect, it } from "vitest";

import { KNOWN_ENV, loadConfig } from "../../src/domain/config.js";

/**
 * BEA-FEEDBACK items 3 and 4 in the configuration: limits.attach_timeout_ms / BEA_ATTACH_TIMEOUT_MS (1000..110000,
 * default 10000), crash.first_chance_blocking / BEA_CRASH_FIRST_CHANCE_BLOCKING (default false) and
 * crash.passthrough_modules (config file only, ≤ 32 module-name patterns). Bad values are collected as issues.
 */
const load = (env: Readonly<Record<string, string>>, file?: unknown) =>
  loadConfig({
    env: { BEA_HOME: "C:/h", ...env },
    platform: "win32",
    accountHome: "C:/u",
    readConfigFile: async () => (file === undefined ? null : JSON.stringify(file)),
  });

describe("crash policy and attach deadline settings", () => {
  it("defaults: blocking first-chance reports off, no pass-through modules, a 10 s attach deadline", async () => {
    const loaded = await load({});
    if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
    expect(loaded.value.crash.firstChanceBlocking).toEqual({ value: false, source: "default" });
    expect(loaded.value.crash.passthroughModules).toEqual({ value: [], source: "default" });
    expect(loaded.value.limits.attachTimeoutMs).toEqual({ value: 10_000, source: "default" });
  });

  it("config file values, and environment variables over them", async () => {
    const file = {
      schema: "bea.config/1",
      limits: { attach_timeout_ms: 60_000 },
      crash: { first_chance_blocking: true, passthrough_modules: ["nvwgf2um*.dll", "vehcommit.exe"] },
    };
    const fromFile = await load({}, file);
    if (!fromFile.ok) throw new Error(JSON.stringify(fromFile.error));
    expect(fromFile.value.crash.firstChanceBlocking).toEqual({ value: true, source: "config-file" });
    expect(fromFile.value.crash.passthroughModules).toEqual({
      value: ["nvwgf2um*.dll", "vehcommit.exe"],
      source: "config-file",
    });
    expect(fromFile.value.limits.attachTimeoutMs).toEqual({ value: 60_000, source: "config-file" });
    const fromEnv = await load({ BEA_CRASH_FIRST_CHANCE_BLOCKING: "off", BEA_ATTACH_TIMEOUT_MS: "110000" }, file);
    if (!fromEnv.ok) throw new Error(JSON.stringify(fromEnv.error));
    expect(fromEnv.value.crash.firstChanceBlocking).toEqual({ value: false, source: "env" });
    expect(fromEnv.value.limits.attachTimeoutMs).toEqual({ value: 110_000, source: "env" });
  });

  it("the environment variables are known (never reported as likely typos)", async () => {
    expect(KNOWN_ENV).toEqual(expect.arrayContaining(["BEA_ATTACH_TIMEOUT_MS", "BEA_CRASH_FIRST_CHANCE_BLOCKING"]));
    const loaded = await load({ BEA_ATTACH_TIMEOUT_MS: "20000", BEA_CRASH_FIRST_CHANCE_BLOCKING: "1" });
    if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
    expect(loaded.value.unknownEnv).toEqual([]);
  });

  it("out-of-range and malformed values are collected, environment and file alike", async () => {
    const bad = await load(
      { BEA_ATTACH_TIMEOUT_MS: "999", BEA_CRASH_FIRST_CHANCE_BLOCKING: "maybe" },
      {
        schema: "bea.config/1",
        limits: { attach_timeout_ms: 110_001 },
        crash: { first_chance_blocking: "yes", passthrough_modules: ["C:\\x\\a.dll", "*", "ok.dll"], extra: 1 },
      },
    );
    expect(bad.ok).toBe(false);
    if (bad.ok) return;
    const settings = bad.error.settings.map((s) => s.setting).sort();
    expect(settings).toEqual([
      "BEA_ATTACH_TIMEOUT_MS",
      "BEA_CRASH_FIRST_CHANCE_BLOCKING",
      "config.json:crash",
      "config.json:crash.first_chance_blocking",
      "config.json:crash.passthrough_modules.0",
      "config.json:crash.passthrough_modules.1",
      "config.json:limits.attach_timeout_ms",
    ]);
    const attach = bad.error.settings.find((s) => s.setting === "BEA_ATTACH_TIMEOUT_MS");
    expect(attach?.constraint).toBe("BEA_ATTACH_TIMEOUT_MS must be a decimal integer from 1000 to 110000 ms.");
  });

  it("at most 32 pass-through patterns of at most 128 characters", async () => {
    const tooMany = await load(
      {},
      { schema: "bea.config/1", crash: { passthrough_modules: Array.from({ length: 33 }, (_, i) => `m${i}.dll`) } },
    );
    expect(tooMany.ok).toBe(false);
    const tooLong = await load({}, { schema: "bea.config/1", crash: { passthrough_modules: ["x".repeat(129)] } });
    expect(tooLong.ok).toBe(false);
  });
});
