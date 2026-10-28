import type { CallToolResult } from "@modelcontextprotocol/client";

import { beaErrorEnvelopeSchema, type BeaErrorProjection } from "../../../src/domain/errors/projection.js";

/**
 * Strict parse of a BEA tool error (rea-testing §4.2, S1 §6.3): `isError: true`, exactly one text content item whose
 * text is `{"error": projection}` under the closed projection schema, and no structuredContent. Throws with the
 * offending payload otherwise, so a test can assert on `code`, `category`, `details` and `recovery` directly.
 */
export const parseToolError = (result: CallToolResult | Readonly<Record<string, unknown>>): BeaErrorProjection => {
  const record = result as Readonly<Record<string, unknown>>;
  const show = (): string => JSON.stringify(record).slice(0, 2000);
  if (record["isError"] !== true) throw new Error(`expected a tool error (isError: true), got ${show()}`);
  if (record["structuredContent"] !== undefined)
    throw new Error(`a tool error must not carry structuredContent: ${show()}`);
  const content = record["content"];
  if (!Array.isArray(content) || content.length !== 1)
    throw new Error(`a tool error carries exactly one content item: ${show()}`);
  const item = content[0] as Readonly<Record<string, unknown>>;
  if (item["type"] !== "text" || typeof item["text"] !== "string")
    throw new Error(`the error content must be text: ${show()}`);
  const parsed = beaErrorEnvelopeSchema.safeParse(JSON.parse(item["text"]));
  if (!parsed.success)
    throw new Error(`the error text does not match {error: projection}: ${parsed.error.message}\n${item["text"]}`);
  return parsed.data.error as BeaErrorProjection;
};

/** The structured result of a successful call; throws (with the error projection when there is one) otherwise. */
export const expectToolSuccess = (
  result: CallToolResult | Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> => {
  const record = result as Readonly<Record<string, unknown>>;
  if (record["isError"] === true) {
    const content = record["content"] as readonly { readonly text?: string }[] | undefined;
    throw new Error(`expected success, got a tool error: ${content?.[0]?.text ?? JSON.stringify(record)}`);
  }
  const structured = record["structuredContent"];
  if (typeof structured !== "object" || structured === null)
    throw new Error(`expected structuredContent: ${JSON.stringify(record)}`);
  return structured as Readonly<Record<string, unknown>>;
};
