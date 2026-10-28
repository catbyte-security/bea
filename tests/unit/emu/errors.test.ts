import { describe, expect, it } from "vitest";

import type { BridgeErrorCode } from "../../../src/domain/emuProtocol.js";
import { beaErrorEnvelopeSchema, projectBeaError } from "../../../src/domain/errors/projection.js";
import {
  bridgeErrorToBea,
  crashLoopError,
  identityChangedError,
  requestFailureToBea,
  startErrorToBea,
} from "../../../src/providers/emulator/errors.js";

const CODES: readonly BridgeErrorCode[] = [
  "parse_error",
  "frame_too_large",
  "invalid_request",
  "invalid_params",
  "unknown_method",
  "protocol_mismatch",
  "unknown_session",
  "session_poisoned",
  "unknown_snapshot",
  "unknown_symbol",
  "image_unreadable",
  "unsupported_image",
  "relocation_unavailable",
  "layout_conflict",
  "dump_invalid",
  "dump_incomplete",
  "unmapped",
  "resource_exhausted",
  "unsupported_combination",
  "cancelled",
  "engine_crashed",
  "internal_error",
];
const SECRET = "C:\\Users\\victim\\secret-target-text";

describe("bridge error mapping (S5 §12)", () => {
  it("maps every bridge error code to a strict, projectable BEA error without bridge text", () => {
    for (const code of CODES) {
      const error = bridgeErrorToBea("emu_call", { code, message: SECRET, data: { note: SECRET, size: 4 } });
      const projected = projectBeaError(error);
      expect(beaErrorEnvelopeSchema.safeParse({ error: projected }).success, code).toBe(true);
      expect(JSON.stringify(projected), code).not.toContain("secret-target-text");
    }
  });

  it("names the emulated region and the per-call vector limit (review fixes EMU-6, EMU-2)", () => {
    const heap = projectBeaError(
      bridgeErrorToBea("emu_call", {
        code: "resource_exhausted",
        message: SECRET,
        data: { resource: "heap", buffer: SECRET, bytes: 4096, heapBytes: 1_048_576 },
      }),
    );
    expect(heap).toMatchObject({ code: "resource_constraint", retryable: false });
    expect(heap.remediation.action).toMatch(/memory\.heap_mb/u);
    expect(JSON.stringify(heap)).not.toContain("secret-target-text");
    expect(JSON.stringify(heap)).not.toContain("emu.memory_limit_mb");
    const scratch = projectBeaError(
      bridgeErrorToBea("emu_call", { code: "resource_exhausted", message: "", data: { resource: "scratch" } }),
    );
    expect(scratch.remediation.action).toMatch(/memory\.scratch_mb/u);
    const budget = projectBeaError(
      bridgeErrorToBea("emu_call", {
        code: "invalid_params",
        message: SECRET,
        data: { path: "params.vectors", outHexBytes: 70_000_000, limit: 58_720_256, maxVectors: 27 },
      }),
    );
    expect(budget).toMatchObject({ code: "invalid_request" });
    expect(budget.details["issues"]).toEqual([
      expect.objectContaining({ path: "vectors", message: expect.stringMatching(/at most 27 vector/u) }),
    ]);
  });

  it("follows the table row by row", () => {
    const code = (c: BridgeErrorCode, context = {}) =>
      projectBeaError(bridgeErrorToBea("emu_call", { code: c, message: "" }, context));
    expect(code("resource_exhausted")).toMatchObject({
      code: "resource_constraint",
      retryable: true,
      details: { resource: "memory" },
    });
    expect(code("unknown_snapshot")).toMatchObject({ code: "invalid_request" });
    expect(code("unknown_snapshot").details["issues"]).toEqual([expect.objectContaining({ path: "state.from" })]);
    expect(code("dump_invalid").code).toBe("evidence_integrity_mismatch");
    expect(code("engine_crashed")).toMatchObject({ code: "capability_unavailable", retryable: true });
    expect(code("session_poisoned")).toMatchObject({ code: "capability_unavailable", retryable: true });
    expect(code("protocol_mismatch")).toMatchObject({ code: "capability_unavailable", retryable: false });
    expect(code("unsupported_image").code).toBe("unsupported_target");
    expect(code("layout_conflict").code).toBe("unsupported_target");
    expect(code("image_unreadable", { imagePath: "C:\\x.dll" })).toMatchObject({
      code: "file_operation_failed",
      details: { path: "C:\\x.dll" },
    });
    expect(code("unmapped", { address: "0x10" })).toMatchObject({
      code: "memory_access_failed",
      details: { address: "0x10" },
    });
    expect(code("relocation_unavailable").details["issues"]).toEqual([expect.objectContaining({ path: "image_base" })]);
    expect(code("dump_incomplete").code).toBe("invalid_request");
    expect(code("unsupported_combination").code).toBe("invalid_request");
    for (const host of [
      "parse_error",
      "frame_too_large",
      "invalid_request",
      "unknown_method",
      "internal_error",
    ] as const)
      expect(code(host).code, host).toBe("execution_failure");
    expect(code("invalid_params").code).toBe("execution_failure");
    expect(code("invalid_params", { path: "patches[0].address" }).code).toBe("execution_failure");
    expect(code("invalid_params", { invalidParamsPath: "patches[0].address" }).code).toBe("invalid_request");
    expect(code("cancelled").code).toBe("cancelled");
  });

  it("maps startup failures and lost bridges, keeping only exit facts", () => {
    const exit = { code: 70, signal: null, reason: "crashed" as const, stderrTail: SECRET };
    const lost = projectBeaError(requestFailureToBea("emu_call", { kind: "bridge_lost", exit }, { generation: 2 }));
    expect(lost).toMatchObject({ code: "capability_unavailable", retryable: true });
    expect(lost.details["diagnostics"]).toEqual({ bridge_exit: { code: 70, reason: "crashed" }, generation: 2 });
    expect(JSON.stringify(lost)).not.toContain("secret-target-text");
    expect(projectBeaError(startErrorToBea("emu_open", { kind: "spawn_failed", message: SECRET })).retryable).toBe(
      true,
    );
    expect(
      projectBeaError(startErrorToBea("emu_open", { kind: "engine_unavailable", missing: ["unicorn"] })).retryable,
    ).toBe(false);
    expect(projectBeaError(startErrorToBea("emu_open", { kind: "timeout", afterMs: 15_000 })).code).toBe(
      "capability_unavailable",
    );
    expect(
      projectBeaError(
        startErrorToBea("emu_open", { kind: "version_mismatch", field: "sha256", expected: "a", actual: "b" }),
      ).details["diagnostics"],
    ).toEqual({ field: "sha256" });
    expect(projectBeaError(startErrorToBea("emu_open", { kind: "exited", exit })).details["diagnostics"]).toEqual({
      bridge_exit: { code: 70, reason: "crashed" },
    });
    expect(
      projectBeaError(requestFailureToBea("emu_call", { kind: "deadline", partial: null }, { timeoutMs: 900 })),
    ).toMatchObject({
      code: "provider_timeout",
      details: { timeout_ms: 900 },
    });
    expect(projectBeaError(requestFailureToBea("emu_call", { kind: "local", reason: "nan" })).code).toBe(
      "execution_failure",
    );
    expect(projectBeaError(crashLoopError("emu_call"))).toMatchObject({ code: "execution_failure", retryable: false });
    expect(projectBeaError(identityChangedError("emu_call")).code).toBe("evidence_integrity_mismatch");
  });
});
