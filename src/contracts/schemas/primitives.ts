import { z } from "zod";

import { UUID_PATTERN } from "../../domain/canonical.js";
import { HARD_LIMITS } from "../../domain/config.js";

/**
 * Shared input/output building blocks. Every number is bounded (an unbounded
 * z.number().int() advertises +/-2^53). Descriptions are short: they ship in
 * every tools/list.
 */

/** Lowercase UUID v4 (crypto.randomUUID). A regex is ~70 bytes vs ~150 for .uuid(). */
export const sessionIdSchema = z
  .string()
  .regex(UUID_PATTERN)
  .describe("Session id from spawn_process, attach_process or emu_open.");

/** A runtime VA. Output addresses are lowercase; input accepts either case. @public */
export const hexAddressSchema = z
  .string()
  .regex(/^0x[0-9a-fA-F]{1,16}$/u)
  .describe("0x-prefixed hex address.");

/** @public */
export const detailSchema = z
  .enum(["summary", "complete"])
  .default("summary")
  .describe("summary returns the compact envelope; complete returns the full Evidence record.");

export const offsetSchema = z.number().int().min(0).max(100_000_000).default(0);

export const limitSchema = (max: number, fallback: number) => z.number().int().min(1).max(max).default(fallback);

export const durationMsSchema = (max: number, fallback: number) => z.number().int().min(1).max(max).default(fallback);

/** wait-style blocking, capped by the orchestrator's 60 s ceiling. @public */
export const waitTimeoutMsSchema = durationMsSchema(HARD_LIMITS.maxWaitMs, 10_000).describe(
  "Max time to block, at most 60000 ms. Running out of time returns a poll result, not an error.",
);

export const maxEventsSchema = (max: number, fallback: number) => z.number().int().min(1).max(max).default(fallback);

/**
 * Absolute LOCAL path: drive-absolute (C:\…) or POSIX-absolute (/…). UNC, device and long-path prefixes (\\host,
 * \\?\, \\.\, //) are refused here (review fix SEC-2: opening one authenticates to that host with the user's NTLM
 * credentials); handlers re-check with the host platform's rules and the resolved location (application/localPaths.ts).
 */
export const localPathSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((value) => /^(?:[A-Za-z]:[\\/]|\/(?![\\/]))/u.test(value) && !value.includes("\u0000"), {
    message: "Path must be an absolute local path (C:\\dir\\file); UNC and device paths are refused.",
  });

/** @public */
export const pagedOutputShape = {
  total: z.number().int().min(0),
  next_offset: z.number().int().min(0).nullable(),
} as const;
