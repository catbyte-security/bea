import { describe, expect, it } from "vitest";

import { HARD_LIMITS } from "../../../src/domain/config.js";
import { beaErrorEnvelopeSchema } from "../../../src/domain/errors/projection.js";
import { startInProcessStdio, type JsonRpcMessage } from "../../support/mcp/inProcessStdio.js";

/**
 * [REV-lab R2] (r2_oversize.mjs) ported to the production stdio entry over PassThrough (WP0 acceptance 7, CT-B3,
 * D-INT-37): a 12.1 MB `tools/call` line must get `invalid_request` (`out_of_range`, refused by invokeTool before
 * parsing), the next call must succeed, and the server must not shut down (the SDK's default 10 MiB read buffer used
 * to close the transport, which ended the server).
 */
const toolError = (message: JsonRpcMessage) => {
  const result = message.result as
    | { readonly isError?: boolean; readonly content?: readonly { readonly text: string }[] }
    | undefined;
  expect(result?.isError).toBe(true);
  return beaErrorEnvelopeSchema.parse(JSON.parse(result?.content?.[0]?.text ?? "{}")).error;
};

describe("oversize tools/call line (CT-B3, REV-lab R2)", () => {
  it("answers a 12.1 MB request with invalid_request, keeps serving, and does not shut down", async () => {
    const stdio = await startInProcessStdio();
    try {
      await stdio.initialize();
      const before = await stdio.request("tools/call", { name: "bea_status", arguments: {} });
      expect((before.result as { readonly isError?: boolean } | undefined)?.isError).toBeUndefined();

      const big = "0x3f800000,".repeat(1_100_000); // ~12.1 MB, as in [CT-lab E12] / [REV-lab R2]
      expect(big.length).toBeGreaterThan(10 * 1024 * 1024); // above the SDK's default stdio buffer
      const id = stdio.nextId();
      stdio.sendRaw(
        `${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "bea_status", arguments: { pad: big } } })}\n`,
      );
      const error = toolError(await stdio.response(id, 20_000));
      expect(error.code).toBe("invalid_request");
      expect(error.details["issues"]).toMatchObject([
        { path: "$", reason: "out_of_range", maximum: HARD_LIMITS.defaultToolInputBytes },
      ]);

      const after = await stdio.request("tools/call", { name: "bea_status", arguments: {} });
      expect((after.result as { readonly isError?: boolean } | undefined)?.isError).toBeUndefined();
      expect(after.result?.["structuredContent"]).toMatchObject({
        evidence_id: null,
        coverage: { status: "complete" },
      });

      // No shutdown trigger fired: no provisional exit code, no hard-exit timer armed.
      expect(stdio.exitCodes()).toEqual([]);
      expect(stdio.hardExits()).toEqual([]);
    } finally {
      const code = await stdio.endStdin();
      expect(code).toBe(0);
    }
  });
});
