import type { CallToolResult } from "@modelcontextprotocol/server";

import type { ToolOutput } from "../application/invokeTool.js";
import type { ToolContract } from "../contracts/toolContract.js";
import type { BeaError, BeaErrorOf } from "../domain/errors/beaError.js";
import { projectBeaError, type BeaErrorProjection } from "../domain/errors/projection.js";
import type { JsonValue } from "../domain/json.js";
import type { Result } from "../domain/result.js";

/** On by default for every tool not audited as target-content-free (rea-mcp §4.6). */
export const UNTRUSTED_META = Object.freeze({
  provenance: Object.freeze({ untrusted_content: true, source: "analysis_target" }),
});

/** Room for the JSON-RPC envelope around the result (REA: max - 1024). */
const ENVELOPE_RESERVE_BYTES = 1024;
const SUCCESS_SKELETON_BYTES =
  Buffer.byteLength(JSON.stringify({ content: [{ type: "text", text: "" }], structuredContent: null })) - 4;
const META_BYTES = Buffer.byteLength(JSON.stringify({ _meta: UNTRUSTED_META })) - 1;

/**
 * Turns a Result into a CallToolResult.
 * Success: compact JSON text + identical structuredContent (+ untrusted marker).
 * Error: isError + text {"error": projection}, no structuredContent (output
 * schemas describe successes; the SDK skips output validation on isError).
 * Over budget: never truncate; return resource_constraint(transport).
 */
export class Delivery {
  readonly budgetBytes: number;

  constructor(readonly maxResponseBytes: number) {
    this.budgetBytes = maxResponseBytes - ENVELOPE_RESERVE_BYTES;
  }

  toCallToolResult(result: Result<ToolOutput, BeaError>, contract: ToolContract): CallToolResult {
    return result.ok ? this.success(result.value, contract) : this.error(result.error, contract);
  }

  success(value: ToolOutput, contract: ToolContract): CallToolResult {
    const text = JSON.stringify(value);
    const structuredBytes = Buffer.byteLength(text);
    const meta = contract.returnsTargetContent ? META_BYTES : 0;
    // The escaped text copy is at least as long as the raw JSON: cheap early refusal.
    if (SUCCESS_SKELETON_BYTES + meta + 2 * structuredBytes > this.budgetBytes)
      return this.error(this.#overflow(contract, value, SUCCESS_SKELETON_BYTES + meta + 2 * structuredBytes), contract);
    const escapedBytes = Buffer.byteLength(JSON.stringify(text)) - 2;
    const total = SUCCESS_SKELETON_BYTES + meta + structuredBytes + escapedBytes;
    if (total > this.budgetBytes) return this.error(this.#overflow(contract, value, total), contract);
    return {
      content: [{ type: "text", text }],
      structuredContent: value as Record<string, unknown>,
      ...(contract.returnsTargetContent ? { _meta: UNTRUSTED_META } : {}),
    };
  }

  error(error: BeaError, contract: ToolContract): CallToolResult {
    let projected: BeaErrorProjection = projectBeaError(error);
    let text = JSON.stringify({ error: projected });
    if (Buffer.byteLength(text) > this.budgetBytes) {
      // Errors are small by construction; this guards a pathological diagnostics payload.
      projected = {
        ...projected,
        details: { effects_applied: projected.details["effects_applied"] ?? [], details_dropped: true },
      };
      text = JSON.stringify({ error: projected });
    }
    return {
      content: [{ type: "text", text }],
      isError: true,
      ...(contract.returnsTargetContent ? { _meta: UNTRUSTED_META } : {}),
    };
  }

  #overflow(contract: ToolContract, value: ToolOutput, bytesAtLeast: number): BeaErrorOf<"ResourceConstraint"> {
    const evidenceId = typeof value["evidence_id"] === "string" ? value["evidence_id"] : null;
    const limits: Record<string, JsonValue> = {
      boundary: "mcp-response",
      budget_bytes: this.budgetBytes,
      response_bytes_at_least: bytesAtLeast,
    };
    if (evidenceId !== null) limits["evidence_reference"] = { kind: "retained-evidence", evidence_id: evidenceId };
    return {
      _tag: "ResourceConstraint",
      operation: contract.name,
      resource: "transport",
      limits,
      retryable: false,
    };
  }
}
