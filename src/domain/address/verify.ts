import { bytesToHex, formatHex, type Hex } from "../hex.js";

/**
 * S2 §18.3 byte verification, the pure part (I/O — agent read, EffectRegistry.originalBytes, PeImage.imageBytes,
 * FootprintScanner — lives in src/application/address). VERIFIED basis [S2-lab E2/E2c]: code matches the relocated
 * file exactly; the loader writes IAT / delay-IAT slots, `fothk` thunks and CFG pointer slots; the Frida agent
 * patches a few system-DLL functions (detected by the footprint scan, never hard-coded).
 */
export type LoaderClass = "iat" | "delay-iat" | "loader-thunk" | "loader-cfg" | "header";

export interface ExcludedCounts {
  readonly iat: number;
  readonly delay_iat: number;
  readonly loader_thunk: number;
  readonly loader_cfg: number;
  readonly zero_fill: number;
  readonly unreadable: number;
}

export interface VerifyDifference {
  readonly rva: Hex;
  readonly size: number;
  readonly class: "unexplained" | "foreign-or-agent-patch";
  /** ≤ 32 bytes each (hex); record only (byte field, redaction-scanned) */
  readonly live_hex: string;
  readonly expected_hex: string;
}

export type VerifyStatus = "match" | "mismatch" | "partial" | "not-applicable" | "skipped";
export type VerifyReason = "writable_section" | "no_session" | "zero_bytes_requested" | "unreadable" | "not_image";

export interface VerifyDetail {
  readonly status: VerifyStatus;
  readonly compared: number;
  readonly equal: number;
  /** loader-written + zero-fill bytes (the port's ByteVerification.excluded_loader) */
  readonly excluded_loader: number;
  readonly own_effects_restored: number;
  readonly differences: readonly VerifyDifference[];
  readonly excluded: ExcludedCounts;
  readonly reason?: VerifyReason;
}

export const MAX_DIFFERENCES = 8;
export const DIFF_HEX_BYTES = 32;
/** S2 §18.3: differing bytes closer than this coalesce into one range */
export const COALESCE_GAP = 4;

const ZERO_EXCLUDED: ExcludedCounts = {
  iat: 0,
  delay_iat: 0,
  loader_thunk: 0,
  loader_cfg: 0,
  zero_fill: 0,
  unreadable: 0,
};

/** A verification that compared nothing (writable section, no live process, verify_bytes 0, non-image address). */
export const verificationWithout = (status: "not-applicable" | "skipped", reason: VerifyReason): VerifyDetail => ({
  status,
  compared: 0,
  equal: 0,
  excluded_loader: 0,
  own_effects_restored: 0,
  differences: [],
  excluded: ZERO_EXCLUDED,
  reason,
});

export interface RvaRange {
  readonly rva: number;
  readonly size: number;
}

export interface CompareInput {
  /** window start (module rva) and length */
  readonly rva: number;
  readonly len: number;
  /** live bytes, already overlaid with BEA's own originals; length = readable prefix (≤ len) */
  readonly live: Uint8Array;
  /** count of bytes BEA's own originals replaced (EffectRegistry.originalBytes) */
  readonly ownRestored: number;
  /** relocated file bytes for the window (length len) */
  readonly expected: Uint8Array;
  /** 1 = file-backed, 0 = zero-fill (PeImage.readRva backed), length len */
  readonly backed: Uint8Array;
  /** loader-written ranges (any overlap with the window) */
  readonly loader: readonly (RvaRange & { readonly class: LoaderClass })[];
}

export interface RawDiff {
  readonly rva: number;
  readonly size: number;
  readonly live: Uint8Array;
  readonly expected: Uint8Array;
}

export interface CompareResult {
  readonly compared: number;
  readonly equal: number;
  readonly excluded: ExcludedCounts;
  readonly ownRestored: number;
  readonly diffs: readonly RawDiff[];
  readonly unreadable: number;
  /** in-memory header fields the loader rewrites (OptionalHeader.ImageBase) */
  readonly headerExcluded: number;
}

const CLASS_KEY: { readonly [C in LoaderClass]: keyof ExcludedCounts | null } = {
  iat: "iat",
  "delay-iat": "delay_iat",
  "loader-thunk": "loader_thunk",
  "loader-cfg": "loader_cfg",
  header: null,
};

/** Mask + compare + coalesce (gap ≤ COALESCE_GAP). Loader-written bytes and zero-fill are excluded, never compared. */
export const compareWindow = (input: CompareInput): CompareResult => {
  const { rva, len, live, expected, backed } = input;
  const mask = new Uint8Array(len); // 0 compare, 1+ = excluded class index
  const counts: Record<keyof ExcludedCounts, number> = { ...ZERO_EXCLUDED };
  const classOrder: LoaderClass[] = [];
  for (const range of input.loader) {
    const from = Math.max(range.rva, rva);
    const to = Math.min(range.rva + range.size, rva + len);
    if (from >= to) continue;
    let index = classOrder.indexOf(range.class);
    if (index === -1) index = classOrder.push(range.class) - 1;
    for (let k = from - rva; k < to - rva; k++) if (mask[k] === 0) mask[k] = index + 1;
  }
  let compared = 0;
  let equal = 0;
  let headerExcluded = 0;
  const differing: number[] = [];
  const readable = Math.min(live.length, len);
  for (let k = 0; k < len; k++) {
    const m = mask[k] ?? 0;
    if (m !== 0) {
      const cls = classOrder[m - 1];
      const key = cls === undefined ? null : CLASS_KEY[cls];
      if (key === null) headerExcluded++;
      else counts[key]++;
      continue;
    }
    if ((backed[k] ?? 0) === 0) {
      counts.zero_fill++;
      continue;
    }
    if (k >= readable) {
      counts.unreadable++;
      continue;
    }
    compared++;
    if (live[k] === expected[k]) equal++;
    else differing.push(k);
  }
  const diffs: RawDiff[] = [];
  let start = -1;
  let last = -1;
  const flush = (): void => {
    if (start === -1) return;
    diffs.push({
      rva: rva + start,
      size: last - start + 1,
      live: live.slice(start, last + 1),
      expected: expected.slice(start, last + 1),
    });
  };
  for (const k of differing) {
    if (start !== -1 && k - last <= COALESCE_GAP) {
      last = k;
      continue;
    }
    flush();
    start = k;
    last = k;
  }
  flush();
  return {
    compared,
    equal,
    excluded: counts,
    ownRestored: input.ownRestored,
    diffs,
    unreadable: counts.unreadable,
    headerExcluded,
  };
};

const intersects = (a: RvaRange, b: RvaRange): boolean => a.rva < b.rva + b.size && b.rva < a.rva + a.size;

/**
 * Status + classification. `footprint` = FootprintScanner ranges of the module (null when the scan was not run or
 * failed: every difference is then `unexplained`).
 */
export const finishVerification = (result: CompareResult, footprint: readonly RvaRange[] | null): VerifyDetail => {
  const excludedLoader =
    result.excluded.iat +
    result.excluded.delay_iat +
    result.excluded.loader_thunk +
    result.excluded.loader_cfg +
    result.excluded.zero_fill +
    result.headerExcluded;
  const differences: VerifyDifference[] = result.diffs.slice(0, MAX_DIFFERENCES).map((d) => ({
    rva: formatHex(d.rva),
    size: d.size,
    class: footprint !== null && footprint.some((f) => intersects(f, d)) ? "foreign-or-agent-patch" : "unexplained",
    live_hex: bytesToHex(d.live.subarray(0, DIFF_HEX_BYTES)),
    expected_hex: bytesToHex(d.expected.subarray(0, DIFF_HEX_BYTES)),
  }));
  const status: VerifyStatus =
    result.diffs.length > 0
      ? "mismatch"
      : result.compared === 0
        ? result.unreadable > 0
          ? "partial"
          : "skipped"
        : result.unreadable > 0
          ? "partial"
          : "match";
  return {
    status,
    compared: result.compared,
    equal: result.equal,
    excluded_loader: excludedLoader,
    own_effects_restored: result.ownRestored,
    differences,
    excluded: result.excluded,
    ...(status === "partial" || (status === "skipped" && result.compared === 0 && result.unreadable > 0)
      ? { reason: "unreadable" as const }
      : {}),
  };
};

/** Overlay BEA's own original bytes (EffectRegistry.originalBytes) onto a live window; returns the bytes overlaid. */
export const overlayOriginals = (
  live: Uint8Array,
  windowVa: bigint,
  ranges: readonly { readonly va: bigint; readonly bytes: Uint8Array }[],
): number => {
  let restored = 0;
  for (const range of ranges) {
    const offset = Number(range.va - windowVa);
    for (let i = 0; i < range.bytes.length; i++) {
      const k = offset + i;
      if (k < 0 || k >= live.length) continue;
      live[k] = range.bytes[i] ?? 0;
      restored++;
    }
  }
  return restored;
};

/** All differing rva ranges of one compare (FootprintScanner accumulates these across a module's code sections). */
export const diffRanges = (result: CompareResult): RvaRange[] =>
  result.diffs.map((d) => ({ rva: d.rva, size: d.size }));
