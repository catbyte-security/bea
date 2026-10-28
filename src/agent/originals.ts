// =================================================================================================
// src/agent/originals.ts — WP3-AGENT OriginalBytes registry (S4 §8.4): the bytes under every BEA patch. Before any
// patch (Interceptor attach/replace, override, patchCode write) the patcher saves ≥ 32 bytes at EACH site that will be
// patched (the thunk target when the requested address is a `jmp [rip+x]` stub, F5): `save(site, 32)` (S4 §10.2).
// Records are refcounted per site (several listeners share one patch). Used by the overlay-aware decoder, by dumps
// (`overlay(buf, base)`, CT-I6), by fingerprint() (`markPatched` records the expected head) and by revert checks.
// Feature seam compatibility: `save(owner, address, size)` / `release(owner)` (owner-first form used by WP12) and
// `isPatched({base, size})` (range form used by WP6) are accepted besides the S4 forms.
// =================================================================================================
import type { Hex, HexBytes } from "../shared/agentProtocol.js";
import { big, hex } from "./encode.js";
import { bytesHex } from "./pure/coreHex.js";

export interface OriginalRecord {
  readonly site: NativePointer;
  readonly key: string;
  readonly bytes: Uint8Array;
  /** who patched (instrument id, "core" for the agent's own exit/UEF hooks, write id) */
  readonly owners: Map<string, number>;
  refs: number;
  /** bytes at the site right after BEA patched it (fingerprint's expected head); null until markPatched */
  patchedHead: Uint8Array | null;
}

const DEFAULT_SAVE = 32;
const HEAD_BYTES = 16;
const ANONYMOUS = "agent";

const readBytes = (p: NativePointer, n: number): Uint8Array | null => {
  try {
    const ab = p.readByteArray(n);
    return ab === null ? null : new Uint8Array(ab);
  } catch {
    return null;
  }
};

export class OriginalBytes {
  readonly #records = new Map<string, OriginalRecord>();

  /** S4 form: save the bytes at `site` before patching it (refcounted per site). */
  save(site: NativePointer, n?: number, owner?: string): OriginalRecord | null;
  /** Owner-first form (WP12 seam): save `size` bytes at `address` for `owner`. */
  save(owner: string, address: NativePointer, size?: number): OriginalRecord | null;
  save(a: NativePointer | string, b?: number | NativePointer, c?: number | string): OriginalRecord | null {
    if (typeof a === "string") return this.#save(b as NativePointer, typeof c === "number" ? c : DEFAULT_SAVE, a);
    return this.#save(a, typeof b === "number" ? b : DEFAULT_SAVE, typeof c === "string" ? c : ANONYMOUS);
  }

  /** S4 form: drop one reference at `site` (the record goes with the last). Owner form: drop every site of `owner`. */
  release(site: NativePointer, owner?: string): OriginalRecord | null;
  release(owner: string): OriginalRecord | null;
  release(a: NativePointer | string, owner?: string): OriginalRecord | null {
    if (typeof a === "string") {
      let last: OriginalRecord | null = null;
      for (const rec of this.#records.values()) {
        const n = rec.owners.get(a) ?? 0;
        for (let i = 0; i < n; i++) last = this.#release(rec, a) ?? last;
      }
      return last;
    }
    const rec = this.#records.get(a.toString());
    return rec === undefined ? null : this.#release(rec, owner ?? [...rec.owners.keys()][0] ?? ANONYMOUS);
  }

  /** Record the bytes now at the site (after Interceptor.flush / patchCode) as the expected patched head. */
  markPatched(site: NativePointer): void {
    const rec = this.#records.get(site.toString());
    if (rec !== undefined) rec.patchedHead = readBytes(site, Math.min(HEAD_BYTES, rec.bytes.length));
  }

  /** Another BEA patch still keeps `site` patched (verification after a detach). */
  patchedByOthers(site: NativePointer): boolean {
    return this.#records.has(site.toString());
  }

  get(site: NativePointer): OriginalRecord | null {
    return this.#records.get(site.toString()) ?? null;
  }

  /** Some saved byte lies inside the range ((address, size) or {base, size}). */
  isPatched(address: NativePointer | { readonly base: NativePointer; readonly size: number }, size = 1): boolean {
    const [base, n] = address instanceof NativePointer ? [address, size] : [address.base, address.size];
    return this.intersecting(base, n).length > 0;
  }

  /** Records whose saved bytes intersect [address, address+size) (overlay inputs). */
  intersecting(address: NativePointer, size: number): { address: bigint; bytes: Uint8Array }[] {
    const a = big(address);
    const end = a + BigInt(Math.max(1, size));
    const out: { address: bigint; bytes: Uint8Array }[] = [];
    for (const rec of this.#records.values()) {
      const s = big(rec.site);
      if (s < end && a < s + BigInt(rec.bytes.length)) out.push({ address: s, bytes: rec.bytes });
    }
    return out;
  }

  /** Write the original bytes of every BEA patch inside [base, base+buf.byteLength) into `buf` (dumps, disassembly). */
  overlay(buf: ArrayBuffer, base: NativePointer): { offset: number; size: number }[] {
    const view = new Uint8Array(buf);
    const b = big(base);
    const restored: { offset: number; size: number }[] = [];
    for (const o of this.intersecting(base, view.length)) {
      let first = -1;
      let last = -1;
      for (let i = 0; i < o.bytes.length; i++) {
        const at = o.address + BigInt(i) - b;
        if (at < 0n || at >= BigInt(view.length)) continue;
        view[Number(at)] = o.bytes[i]!;
        if (first < 0) first = Number(at);
        last = Number(at);
      }
      if (first >= 0) restored.push({ offset: first, size: last - first + 1 });
    }
    return restored;
  }

  /** Every record (fingerprint, dumps, status). */
  list(): OriginalRecord[] {
    return [...this.#records.values()];
  }

  /** EffectHint.before entries (≤ 64 B each) for the given sites. */
  beforeOf(sites: readonly NativePointer[]): { address: Hex; hex: HexBytes }[] {
    const out: { address: Hex; hex: HexBytes }[] = [];
    for (const site of sites) {
      const rec = this.#records.get(site.toString());
      if (rec !== undefined)
        out.push({ address: hex(rec.site), hex: bytesHex(rec.bytes, 0, Math.min(64, rec.bytes.length)) });
    }
    return out;
  }

  /** Current head bytes at a site vs the recorded patched head (fingerprint). */
  check(rec: OriginalRecord): { expected: Uint8Array; actual: Uint8Array | null } {
    const expected = rec.patchedHead ?? rec.bytes.slice(0, HEAD_BYTES);
    return { expected, actual: readBytes(rec.site, expected.length) };
  }

  #save(site: NativePointer, n: number, owner: string): OriginalRecord | null {
    const key = site.toString();
    const existing = this.#records.get(key);
    if (existing !== undefined) {
      existing.refs++;
      existing.owners.set(owner, (existing.owners.get(owner) ?? 0) + 1);
      return existing;
    }
    let bytes: Uint8Array | null = null;
    for (let len = Math.max(1, n); len > 0 && bytes === null; len = len > 8 ? len >> 1 : len - 1)
      bytes = readBytes(site, len);
    if (bytes === null) return null;
    const rec: OriginalRecord = { site, key, bytes, owners: new Map([[owner, 1]]), refs: 1, patchedHead: null };
    this.#records.set(key, rec);
    return rec;
  }

  #release(rec: OriginalRecord, owner: string): OriginalRecord | null {
    const n = rec.owners.get(owner) ?? 0;
    if (n <= 1) rec.owners.delete(owner);
    else rec.owners.set(owner, n - 1);
    rec.refs--;
    if (rec.refs > 0) return null;
    this.#records.delete(rec.key);
    return rec;
  }
}
