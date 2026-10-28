import canonicalize from "canonicalize";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { pollOutput, recordedOutput, ReservedKeyError } from "../../src/contracts/schemas/envelope.js";
import { canonicalDigest, canonicalJson, sha256Hex } from "../../src/domain/canonical.js";
import { loadConfig } from "../../src/domain/config.js";
import { mapAgentError } from "../../src/domain/errors/agentErrorMap.js";
import { projectBeaError } from "../../src/domain/errors/projection.js";
import { mergeCoverage } from "../../src/domain/evidence/coverage.js";
import { idOf } from "../../src/domain/ids.js";
import type { JsonValue } from "../../src/domain/json.js";
import { clampAgentLimits, AGENT_LIMIT_HARD } from "../../src/shared/agentLimits.js";

let seed = 0x9e3779b9;
const rnd = (): number => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32;
const strings = ["", "a", "é", "\u2028", "\ud83d\ude00", "key", "\u0000", '"q"', "€", "\uffff", "aa", "B"];
const gen = (depth: number): JsonValue => {
  const r = rnd();
  if (depth > 4 || r < 0.35) {
    const k = Math.floor(rnd() * 6);
    if (k === 0) return null;
    if (k === 1) return rnd() < 0.5;
    if (k === 2) return (rnd() - 0.5) * 10 ** Math.floor(rnd() * 30 - 10);
    if (k === 3) return Math.floor((rnd() - 0.5) * 2 ** 53);
    return strings[Math.floor(rnd() * strings.length)] ?? "";
  }
  if (r < 0.65) return Array.from({ length: Math.floor(rnd() * 5) }, () => gen(depth + 1));
  const o: Record<string, JsonValue> = {};
  for (let i = 0; i < Math.floor(rnd() * 6); i++)
    o[(strings[Math.floor(rnd() * strings.length)] ?? "") + String(Math.floor(rnd() * 3))] = gen(depth + 1);
  return o;
};

describe("integrated shared core", () => {
  it("BEA's JCS emitter equals canonicalize@5.1.0 on 5000 random JSON values; streaming digest equals sha256(text)", () => {
    for (let i = 0; i < 5000; i++) {
      const v = gen(0);
      const mine = canonicalJson(v);
      expect(mine).toBe(canonicalize(v));
      expect(canonicalDigest(v)).toBe(sha256Hex(mine));
    }
  });
  it("RFC 8785 number vectors and NaN refusal", () => {
    expect(canonicalJson([1e21, 1e-7, -0, 333333333.33333329, 4.5, 2e-3, 1e30])).toBe(
      "[1e+21,1e-7,0,333333333.3333333,4.5,0.002,1e+30]",
    );
    expect(() => canonicalJson(Number.NaN)).toThrow();
    expect(idOf("pi", { t: "bea.pi/1", b: 1, a: 2 })).toMatch(/^pi_[0-9a-f]{64}$/u);
  });
  it("reserved envelope keys are refused in result shapes", () => {
    expect(() => recordedOutput({ coverage: z.string() })).toThrow(ReservedKeyError);
    expect(Object.keys(pollOutput({ x: z.number() }).shape).sort()).toEqual([
      "coverage",
      "evidence_id",
      "limitations",
      "next",
      "x",
    ]);
  });
  it("agent errors map to the closed BeaError union and project with effects_applied", () => {
    const e = mapAgentError(
      {
        _tag: "HookDenied",
        message: "m",
        address: "0x1",
        api: "ntdll.dll!NtAllocateVirtualMemory",
        reason: "deadlock-risk",
        alternatives: [],
      },
      { operation: "hook_function", effects_applied: ["fx_" + "a".repeat(64)] },
    );
    const p = projectBeaError(e);
    expect(p.code).toBe("instrumentation_failed");
    expect(p.details["effects_applied"]).toEqual(["fx_" + "a".repeat(64)]);
    const g = projectBeaError(
      mapAgentError({ _tag: "GateClosed", message: "x", gate: "call_function" }, { operation: "call_function" }),
    );
    expect(g.code).toBe("capability_unavailable");
  });
  it("coverage merge: worst status wins, reasons sorted", () => {
    expect(
      mergeCoverage(
        { status: "complete", truncated: false, reasons: [] },
        { status: "partial", truncated: true, dropped: 3, reasons: ["seq_gap"] },
      ),
    ).toEqual({ status: "partial", truncated: true, dropped: 3, reasons: ["seq_gap"] });
  });
  it("config: MiB quotas, limits, anti-cheat opt-in, emulator keys; bad values collected", async () => {
    const ok = await loadConfig({
      env: { BEA_HOME: "C:/h", BEA_LEDGER_QUOTA_MB: "1024", BEA_ALLOW_ANTI_CHEAT: "1", BEA_MAX_LIVE_SESSIONS: "6" },
      platform: "win32",
      accountHome: "C:/u",
      readConfigFile: async () =>
        JSON.stringify({
          schema: "bea.config/1",
          emu: { memory_limit_mb: 2048 },
          attach: { extra_denylist: ["game.exe"] },
        }),
    });
    if (!ok.ok) throw new Error(JSON.stringify(ok.error));
    expect(ok.value.quotas.ledgerMb).toEqual({ value: 1024, source: "env" });
    expect(ok.value.attach.allowAntiCheat.value).toBe(true);
    expect(ok.value.limits.maxLiveSessions.value).toBe(6);
    expect(ok.value.emu.memoryLimitMb).toEqual({ value: 2048, source: "config-file" });
    expect(ok.value.layout.venvDir.replaceAll("\\", "/")).toBe("C:/h/emu/venv");
    const bad = await loadConfig({
      env: { BEA_HOME: "C:/h", BEA_MAX_LIVE_SESSIONS: "9", BEA_EMU_SELFTEST: "sometimes" },
      platform: "win32",
      accountHome: "C:/u",
      readConfigFile: async () => null,
    });
    expect(bad.ok).toBe(false);
    if (!bad.ok)
      expect(bad.error.settings.map((s) => s.setting).sort()).toEqual(["BEA_EMU_SELFTEST", "BEA_MAX_LIVE_SESSIONS"]);
  });
  it("agent limits clamp to hard caps", () => {
    const l = clampAgentLimits({ flush_ms: 10_000, call_max_vectors: 5 });
    expect(l.flush_ms).toBe(AGENT_LIMIT_HARD.flush_ms);
    expect(l.call_max_vectors).toBe(5);
  });
});
