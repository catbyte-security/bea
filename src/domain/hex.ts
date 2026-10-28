import { z } from "zod";

import { HEX_BYTES_RE, HEX_CANONICAL_RE, HEX_INPUT_RE, type Hex } from "../shared/hex.js";

export { bytesToHex, canonicalHex, formatHex, hexToBytes, type Hex } from "../shared/hex.js";

/** Records and outputs: canonical lowercase hex. */
export const hexSchema = z.string().regex(HEX_CANONICAL_RE) as unknown as z.ZodType<Hex, string>;
/** Tool inputs: any case, leading zeros ok. No transform (JSON-Schema safe); handlers normalize. */
export const hexInputSchema = z.string().regex(HEX_INPUT_RE);
/** @public */
export const hexBytesSchema = (maxBytes: number) =>
  z
    .string()
    .max(maxBytes * 2)
    .regex(HEX_BYTES_RE);

/** S2 A13: Windows x64 user-mode VA ceiling (47-bit). @public */
export const USER_VA_MAX = 0x7fff_ffff_ffffn;
