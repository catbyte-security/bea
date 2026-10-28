// =================================================================================================
// src/application/watch/decoders.ts — the `decoders` JSON stored with watch/poll/trace recordings and the address
// helpers their row decoders use (WP9-WATCH). The JSON is written once at install (RecordingCreate.decoders and the
// stream descriptor) and read back by the kind decoders, so it carries everything decoding needs: view and size,
// the watched address, and a module legend (name, runtime base, size, path) for module-relative row addresses.
// =================================================================================================
import { formatHex, type Hex } from "../../domain/hex.js";
import { isJsonObject, type JsonObject, type JsonValue } from "../../domain/json.js";
import type { DecodeContext } from "../../ports/recordings.js";
import type { LayoutId } from "../../shared/agentProtocol.js";
import { WATCH_VIEWS, type WatchView } from "./values.js";

/** Marker rows of the agent (src/agent/watch.ts; a unit test pins both copies). */
export const WATCH_MARKER_RATE_LIMIT = "bea:rate-limit";
export const WATCH_MARKER_FINAL = "bea:watch-final";

/** [name, runtime base, size, path] */
export type LegendEntry = readonly [name: string, base: Hex, size: number, path: string | null];

export interface WatchDecoders {
  readonly v: 1;
  readonly kind: "watch";
  readonly method: "debug_register" | "page_guard";
  readonly view: WatchView;
  readonly size: number;
  readonly address: Hex;
  readonly registers: readonly string[];
  readonly modules: readonly LegendEntry[];
}
export interface PollDecoders {
  readonly v: 1;
  readonly kind: "poll";
  readonly view: WatchView;
  readonly size: number;
  readonly address: Hex;
  readonly interval_ms: number;
}
export interface TraceDecoders {
  readonly v: 1;
  readonly kind: "trace";
  readonly mode: "coverage" | "block_counts" | "calls";
  readonly layout: LayoutId;
  readonly on_call: Hex | null;
  readonly invocations: number;
  readonly threads: readonly number[];
  readonly modules: readonly LegendEntry[];
  readonly instance_id: string | null;
}

const HEX_RE = /^0x[0-9a-f]{1,16}$/u;
const str = (v: JsonValue | undefined): string | null => (typeof v === "string" ? v : null);
const num = (v: JsonValue | undefined): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const hexOr = (v: JsonValue | undefined): Hex | null => {
  const s = str(v);
  return s !== null && HEX_RE.test(s) ? (s as Hex) : null;
};
const viewOf = (v: JsonValue | undefined): WatchView =>
  typeof v === "string" && (WATCH_VIEWS as readonly string[]).includes(v) ? (v as WatchView) : "hex";
const legendOf = (v: JsonValue | undefined): LegendEntry[] => {
  if (!Array.isArray(v)) return [];
  const out: LegendEntry[] = [];
  for (const e of v as readonly JsonValue[]) {
    if (!Array.isArray(e)) continue;
    const [name, base, size, path] = e as readonly JsonValue[];
    const b = hexOr(base);
    if (typeof name === "string" && b !== null && typeof size === "number")
      out.push([name, b, size, typeof path === "string" ? path : null]);
  }
  return out.sort((a, b) => (BigInt(a[1]) < BigInt(b[1]) ? -1 : 1));
};

export const watchDecodersOf = (d: JsonValue): WatchDecoders => {
  const o: JsonObject = isJsonObject(d) ? d : {};
  return {
    v: 1,
    kind: "watch",
    method: o["method"] === "page_guard" ? "page_guard" : "debug_register",
    view: viewOf(o["view"]),
    size: num(o["size"]) ?? 0,
    address: hexOr(o["address"]) ?? "0x0",
    registers: Array.isArray(o["registers"])
      ? (o["registers"] as JsonValue[]).filter((r): r is string => typeof r === "string")
      : [],
    modules: legendOf(o["modules"]),
  };
};
export const pollDecodersOf = (d: JsonValue): PollDecoders => {
  const o: JsonObject = isJsonObject(d) ? d : {};
  return {
    v: 1,
    kind: "poll",
    view: viewOf(o["view"]),
    size: num(o["size"]) ?? 0,
    address: hexOr(o["address"]) ?? "0x0",
    interval_ms: num(o["interval_ms"]) ?? 16,
  };
};
export const traceDecodersOf = (d: JsonValue): TraceDecoders => {
  const o: JsonObject = isJsonObject(d) ? d : {};
  const mode = o["mode"] === "block_counts" || o["mode"] === "calls" ? o["mode"] : "coverage";
  const layout = str(o["layout"]);
  return {
    v: 1,
    kind: "trace",
    mode,
    layout:
      layout === "block-count/1" || layout === "call-site-count/1" || layout === "gum-event-x64/1"
        ? layout
        : "block-span/1",
    on_call: hexOr(o["on_call"]),
    invocations: num(o["invocations"]) ?? 0,
    threads: Array.isArray(o["threads"])
      ? (o["threads"] as JsonValue[]).filter((t): t is number => typeof t === "number")
      : [],
    modules: legendOf(o["modules"]),
    instance_id: str(o["instance_id"]),
  };
};

/** Binary search of the (sorted) legend. */
export const locate = (
  legend: readonly LegendEntry[],
  va: bigint,
): { readonly name: string; readonly rva: bigint; readonly entry: LegendEntry } | null => {
  let lo = 0;
  let hi = legend.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const e = legend[mid];
    if (e === undefined) return null;
    const base = BigInt(e[1]);
    if (va < base) hi = mid - 1;
    else if (va >= base + BigInt(e[2])) lo = mid + 1;
    else return { name: e[0], rva: va - base, entry: e };
  }
  return null;
};

export interface CompactAddress {
  readonly va: Hex;
  readonly at: string | null;
  readonly static: string | null;
}
/** Compact Addr forms (S6 §2.2): module-relative through the legend, static form through the registry's frame(). */
export const compactOf = (ctx: DecodeContext, legend: readonly LegendEntry[], va: bigint): CompactAddress => {
  const hex = formatHex(va);
  const m = locate(legend, va);
  const ref = m === null ? hex : `${m.name}+${formatHex(m.rva)}`;
  let framed: { readonly at: string | null; readonly static: string | null } = { at: null, static: null };
  try {
    framed = ctx.frame(ref);
  } catch {
    // frame decoding is best effort: the module-relative text still stands
  }
  return { va: hex, at: framed.at ?? (m === null ? null : ref), static: framed.static };
};

/** u64 fields of binary records arrive as numbers, decimal strings or hex strings (descriptor dependent). */
export const toBig = (v: JsonValue | undefined): bigint | null => {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === "string" && /^(?:0x[0-9a-fA-F]{1,16}|\d{1,20})$/u.test(v)) return BigInt(v);
  return null;
};

/** The named field of a fixed record (object form) or the n-th cell (array form). */
export const fieldOf = (fields: JsonValue, name: string, index: number): JsonValue | undefined => {
  if (Array.isArray(fields)) return (fields as readonly JsonValue[])[index];
  return isJsonObject(fields) ? fields[name] : undefined;
};
