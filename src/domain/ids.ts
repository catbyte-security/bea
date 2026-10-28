import { z } from "zod";

import { canonicalDigest } from "./canonical.js";
import type { JsonValue } from "./json.js";

/**
 * Content-addressed id families (S2 §2.4): `<prefix>_<64 lowercase hex>` = SHA-256 of an RFC 8785 canonical
 * PROJECTION that carries a type tag (`t` or `schema`). `query` is reserved for v0.2. Blobs use the bare sha256.
 */
export const ID_PREFIXES = ["ev", "pi", "mm", "fx", "st", "unk", "query"] as const;
export type IdPrefix = (typeof ID_PREFIXES)[number];
export type EvId = `ev_${string}`;
export type PiId = `pi_${string}`;
export type MmId = `mm_${string}`;
export type FxId = `fx_${string}`;
export type StId = `st_${string}`;
export type UnkId = `unk_${string}`;
export type IdOf<P extends IdPrefix> = `${P}_${string}`;

export const SHA256_RE = /^[a-f0-9]{64}$/u;
export const sha256Schema = z.string().regex(SHA256_RE);

export const idPattern = (prefix: IdPrefix): RegExp => new RegExp(`^${prefix}_[a-f0-9]{64}$`, "u");
export const idSchema = <P extends IdPrefix>(prefix: P) =>
  z.string().regex(idPattern(prefix), `Expected a ${prefix}_ prefixed lowercase sha256`) as unknown as z.ZodType<
    IdOf<P>,
    string
  >;

export const evIdSchema = idSchema("ev");
export const piIdSchema = idSchema("pi");
export const mmIdSchema = idSchema("mm");
export const fxIdSchema = idSchema("fx");
export const stIdSchema = idSchema("st");
export const unkIdSchema = idSchema("unk");
export const ANY_LEDGER_ID_RE = /^(ev|pi|mm|fx|st|unk)_[a-f0-9]{64}$/u;

/** idOf(prefix, projection): the ONLY way an id is minted. */
export const idOf = <P extends IdPrefix>(prefix: P, projection: JsonValue): IdOf<P> =>
  `${prefix}_${canonicalDigest(projection)}` as IdOf<P>;

/** Server run id: UTC second + 64 random bits; sorts by time. One run = one server process or CLI command. */
export type RunId = `run_${string}`;
export const RUN_ID_RE = /^run_\d{8}T\d{6}Z_[0-9a-f]{16}$/u;
export const runIdSchema = z.string().regex(RUN_ID_RE) as unknown as z.ZodType<RunId, string>;
