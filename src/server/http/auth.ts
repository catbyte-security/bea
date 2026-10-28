import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** 32 random bytes, base64url (43 chars). Used when BEA_HTTP_TOKEN is not set. */
export const newHttpToken = (): string => randomBytes(32).toString("base64url");

const digest = (text: string): Buffer => createHash("sha256").update(text, "utf8").digest();

/** Constant-time bearer check; compares SHA-256 digests so token lengths never leak. */
export const bearerVerifier = (token: string): ((authorization: string | null) => boolean) => {
  const expected = digest(token);
  return (authorization) => {
    const match = /^Bearer ([A-Za-z0-9_-]{32,256})$/u.exec(authorization ?? "");
    return match?.[1] !== undefined && timingSafeEqual(digest(match[1]), expected);
  };
};

/** A JSON-RPC error body with `id: null`, the shape the SDK transport uses for its own HTTP-level refusals. */
export const jsonRpcErrorResponse = (
  status: number,
  code: number,
  message: string,
  headers: Readonly<Record<string, string>> = {},
): Response =>
  new Response(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

export const unauthorized = (): Response =>
  jsonRpcErrorResponse(401, -32001, "Missing or invalid bearer token. Read the token from the BEA connection file.", {
    "www-authenticate": 'Bearer realm="bea"',
  });
