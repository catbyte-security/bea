import type { Addr } from "./addressRef.js";
import { atText, staticText, USER_VA_MAX } from "./grammar.js";
import { formatHex, type Hex } from "../hex.js";
import { err, ok, type Result } from "../result.js";

/**
 * ASLR arithmetic (S2 §16.3 steps 2–4; VERIFIED formula `va = base + (static_va − static_base)` [ext-frida §3.14],
 * [S2-lab E2]). Pure; bigint throughout so 64-bit static bases never lose precision.
 */
const U64_MAX = (1n << 64n) - 1n;

/** rva from a static VA and its image base; the rva must fall inside the image. */
export const rvaOfStatic = (
  staticVa: bigint,
  staticBase: bigint,
  sizeOfImage: number,
): Result<number, "static_out_of_image"> => {
  const delta = staticVa - staticBase;
  return delta < 0n || delta >= BigInt(sizeOfImage) ? err("static_out_of_image") : ok(Number(delta));
};

/** 0 ≤ rva < SizeOfImage. */
export const rvaInImage = (rva: number, sizeOfImage: number): boolean =>
  Number.isInteger(rva) && rva >= 0 && rva < sizeOfImage;

/** base + rva, or null when the sum leaves the user-mode range (a corrupt base or a bogus module entry). */
export const vaOfRva = (base: bigint, rva: number): bigint | null => {
  const va = base + BigInt(rva);
  return va > USER_VA_MAX ? null : va;
};

/** static_base + rva, or null on 64-bit overflow. */
export const staticOfRva = (staticBase: bigint, rva: number): bigint | null => {
  const value = staticBase + BigInt(rva);
  return value > U64_MAX ? null : value;
};

/** One module of an address space, as compact formatting needs it. */
export interface CompactModule {
  readonly name: string;
  readonly base: bigint;
  readonly size: number;
  /** preferred (static) base, or null when not known/prepared: `static` is then null */
  readonly staticBase: bigint | null;
  /** another module of the space shares the basename: texts carry `@0x<base>` */
  readonly ambiguous: boolean;
}

/** Binary search over modules sorted by base. @public */
export const compactModuleAt = <M extends { readonly base: bigint; readonly size: number }>(
  modules: readonly M[],
  va: bigint,
): M | null => {
  let lo = 0;
  let hi = modules.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const m = modules[mid];
    if (m === undefined) return null;
    if (va < m.base) hi = mid - 1;
    else if (va >= m.base + BigInt(m.size)) lo = mid + 1;
    else return m;
  }
  return null;
};

/** Compact data address (S6 §2.2). */
export const compactAddr = (va: bigint, module: CompactModule | null): Addr => {
  const vaHex: Hex = formatHex(va);
  if (module === null) return { va: vaHex, at: null, static: null };
  const rva = Number(va - module.base);
  const qualifier = module.ambiguous ? module.base : null;
  const staticVa = module.staticBase === null ? null : staticOfRva(module.staticBase, rva);
  return {
    va: vaHex,
    at: atText(module.name, rva, qualifier),
    static: staticVa === null ? null : staticText(module.name, staticVa, qualifier),
  };
};

/** Compact `sym` text: "name" at offset 0, else "name+0xoff" (S6 §2.2). */
export const symText = (name: string, offset: number): string =>
  offset === 0 ? name : `${name}+0x${offset.toString(16)}`;
