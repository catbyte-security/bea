import type { ReadView } from "../../contracts/areas/inspect.js";
import { INSPECT_CAPS } from "../../contracts/areas/inspect.js";
import { bytesToHex, formatHex } from "../../shared/hex.js";

/**
 * read_memory typed views (S6 §2.3 output encoding), decoded on the host from the raw bytes so live and emulation
 * sessions share one exact path (floats come from their bits, never through an agent float round trip):
 * ≤ 32-bit integers are numbers, 64-bit integers decimal strings, `ptr` hex, `bool` one byte, floats the shortest
 * decimal that round-trips through their type, or "NaN" / "Infinity" / "-Infinity"; utf8/utf16 stop at the first NUL.
 */
export type ViewScalar = number | string | boolean;
export interface DecodedView {
  readonly data?: string;
  readonly values?: readonly ViewScalar[];
  readonly text?: string;
  /** typed values beyond INSPECT_CAPS.readValues were not returned */
  readonly valuesCapped: boolean;
  /** element count before the cap (0 for hex/base64/text views) */
  readonly elements: number;
}

const ELEMENT_BYTES: Readonly<Record<Exclude<ReadView, "hex" | "base64" | "utf8" | "utf16">, number>> = {
  i8: 1,
  u8: 1,
  i16: 2,
  u16: 2,
  i32: 4,
  u32: 4,
  i64: 8,
  u64: 8,
  ptr: 8,
  bool: 1,
  f32: 4,
  f64: 8,
};

const floatSpecial = (v: number): string | null =>
  Number.isNaN(v) ? "NaN" : v === Infinity ? "Infinity" : v === -Infinity ? "-Infinity" : null;

/** Shortest decimal that maps back to the same f32 (lab L-S6-9: 14.905, not 14.904999732971191). */
export const shortestF32 = (v: number): number | string => {
  const special = floatSpecial(v);
  if (special !== null) return special;
  if (v === 0) return v;
  for (let precision = 1; precision <= 9; precision++) {
    const candidate = Number(v.toPrecision(precision));
    if (Math.fround(candidate) === v) return candidate;
  }
  return v;
};
/** JavaScript's own number text is already the shortest round trip for f64. */
export const shortestF64 = (v: number): number | string => floatSpecial(v) ?? v;

const decodeElement = (dv: DataView, at: number, view: keyof typeof ELEMENT_BYTES): ViewScalar => {
  switch (view) {
    case "i8":
      return dv.getInt8(at);
    case "u8":
      return dv.getUint8(at);
    case "i16":
      return dv.getInt16(at, true);
    case "u16":
      return dv.getUint16(at, true);
    case "i32":
      return dv.getInt32(at, true);
    case "u32":
      return dv.getUint32(at, true);
    case "i64":
      return dv.getBigInt64(at, true).toString();
    case "u64":
      return dv.getBigUint64(at, true).toString();
    case "ptr":
      return formatHex(dv.getBigUint64(at, true));
    case "bool":
      return dv.getUint8(at) !== 0;
    case "f32":
      return shortestF32(dv.getFloat32(at, true));
    case "f64":
      return shortestF64(dv.getFloat64(at, true));
  }
};

/** Text up to the first NUL unit (utf16: a zero 16-bit unit at an even offset). */
const textView = (bytes: Uint8Array, view: "utf8" | "utf16"): string => {
  if (view === "utf8") {
    const end = bytes.indexOf(0);
    return new TextDecoder("utf-8").decode(end < 0 ? bytes : bytes.subarray(0, end));
  }
  let end = bytes.length - (bytes.length % 2);
  for (let i = 0; i + 1 < bytes.length; i += 2)
    if (bytes[i] === 0 && bytes[i + 1] === 0) {
      end = i;
      break;
    }
  return new TextDecoder("utf-16le").decode(bytes.subarray(0, end));
};

export const decodeView = (bytes: Uint8Array, view: ReadView): DecodedView => {
  if (view === "hex") return { data: bytesToHex(bytes), valuesCapped: false, elements: 0 };
  if (view === "base64") return { data: Buffer.from(bytes).toString("base64"), valuesCapped: false, elements: 0 };
  if (view === "utf8" || view === "utf16") return { text: textView(bytes, view), valuesCapped: false, elements: 0 };
  const width = ELEMENT_BYTES[view];
  const elements = Math.floor(bytes.length / width);
  const shown = Math.min(elements, INSPECT_CAPS.readValues);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const values: ViewScalar[] = [];
  for (let i = 0; i < shown; i++) values.push(decodeElement(dv, i * width, view));
  return { values, valuesCapped: shown < elements, elements };
};
