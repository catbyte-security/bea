// GumJS side of the profile decoders (WP-BEHAVIOR): the NativePointer ProfileMem used by src/agent/pure/profileDecode.ts,
// the agent-only lookups the decoders need (NtQueryKey root names, getsockname), and the "first caller outside system
// modules" resolver of ApiRow.caller (S6 §4.21 `caller`). Imports only shared code and the pure helpers.
import type { Hex } from "../shared/hex.js";
import type { SockName } from "./pure/profileDecode.js";
import { readSockaddr } from "./pure/profileDecode.js";
import { isUnder, type ModuleTable } from "./pure/profileModules.js";
import type { ProfileMem } from "./pure/profileTypes.js";

const HEX_DIGITS = "0123456789abcdef";

const bufferHex = (buf: ArrayBuffer | null): string => {
  if (buf === null) return "";
  const bytes = new Uint8Array(buf);
  let out = "";
  for (const b of bytes) out += (HEX_DIGITS[b >> 4] ?? "0") + (HEX_DIGITS[b & 15] ?? "0");
  return out;
};

/** ProfileMem over NativePointer. Reads throw on unmapped memory; the pure decoders catch per argument. */
export const gumMem: ProfileMem<NativePointer> = {
  isNull: (p) => p.isNull(),
  add: (p, offset) => p.add(offset),
  hex: (p) => p.toString() as Hex,
  u32: (p) => p.toUInt32(),
  i32: (p) => p.toInt32(),
  readPointer: (p) => p.readPointer(),
  readU8: (p) => p.readU8(),
  readU16: (p) => p.readU16(),
  readU32: (p) => p.readU32(),
  readU64: (p) => `0x${p.readU64().toString(16)}` as Hex,
  readUtf16: (p, chars) => (chars <= 0 ? "" : (p.readUtf16String(chars) ?? "")),
  readAnsi: (p, chars) => {
    if (chars <= 0) return "";
    const s = p.readAnsiString(chars) ?? "";
    const nul = s.indexOf("\0");
    return nul >= 0 ? s.slice(0, nul) : s;
  },
  readUtf16z: (p, max) => {
    // GLib's UTF-16 conversion stops at the first NUL within `max` units
    const s = p.readUtf16String(max) ?? "";
    return { s, trunc: s.length >= max };
  },
  readAnsiz: (p, max) => {
    const s = p.readAnsiString(max) ?? "";
    const nul = s.indexOf("\0");
    return nul >= 0 ? { s: s.slice(0, nul), trunc: false } : { s, trunc: s.length >= max };
  },
  readHex: (p, bytes) => bufferHex(p.readByteArray(bytes)),
};

// ---------------------------------------------------------------------------------------------- lookups
// Resolved once on the JS thread at install (initLookups): resolving exports inside a hook could take the loader lock
// while the hook holds the script lock (see ./pure/profileModules.ts for the deadlock this avoids).
type NtQueryKeyFn = NativeFunction<
  number,
  [NativePointerValue, number, NativePointerValue, number, NativePointerValue]
>;
type GetSockNameFn = NativeFunction<number, [NativePointerValue, NativePointerValue, NativePointerValue]>;
let ntQueryKey: NtQueryKeyFn | null = null;
let getSockName: GetSockNameFn | null = null;

/** JS thread, before any listener is attached. ws2_32 is normally loaded already (Frida's injection loads it). */
export const initLookups = (loaded: ReadonlyMap<string, Module>): void => {
  if (ntQueryKey === null) {
    const addr = loaded.get("ntdll.dll")?.findExportByName("NtQueryKey") ?? null;
    if (addr !== null)
      ntQueryKey = new NativeFunction(addr, "uint32", ["pointer", "uint32", "pointer", "uint32", "pointer"]);
  }
  if (getSockName === null) {
    const addr = loaded.get("ws2_32.dll")?.findExportByName("getsockname") ?? null;
    if (addr !== null) getSockName = new NativeFunction(addr, "int", ["pointer", "pointer", "pointer"]);
  }
};

/**
 * Registry root name of a key handle missing from the cache: NtQueryKey(KeyNameInformation = 3) from inside the
 * hook (F10; the Interceptor guard keeps our own NtQueryKey listener quiet, F3). KEY_NAME_INFORMATION:
 * NameLength u32 +0, Name +4. Returns the NT name ("\REGISTRY\MACHINE\…") or null.
 */
export const keyNameOf = (handle: NativePointer): string | null => {
  if (ntQueryKey === null) return null;
  try {
    const size = 2048;
    const buf = Memory.alloc(size);
    const resultLength = Memory.alloc(4);
    const status = ntQueryKey(handle, 3, buf, size, resultLength) >>> 0;
    if (status !== 0) return null;
    const bytes = buf.readU32();
    return buf.add(4).readUtf16String(Math.min(bytes >>> 1, (size - 4) >>> 1)) ?? null;
  } catch {
    return null;
  }
};

/** getsockname() for a socket bound to port 0 (the listener's real port); null when unavailable. */
export const localEndpointOf = (socket: NativePointer): SockName | null => {
  if (getSockName === null) return null;
  try {
    const buf = Memory.alloc(128);
    const len = Memory.alloc(4);
    len.writeS32(128);
    if (getSockName(socket, buf, len) !== 0) return null;
    return readSockaddr(gumMem, buf);
  } catch {
    return null;
  }
};

// ---------------------------------------------------------------------------------------------- callers
const big = (p: NativePointer): bigint => BigInt(p.toString());

/**
 * ApiRow.caller: the first caller outside system modules (modules under %SystemRoot%). Uses the observer-fed module
 * table only (never enumerates modules inside a hook).
 */
export class CallerResolver {
  private readonly systemRoot: string;

  constructor(private readonly modules: ModuleTable) {
    const ntdll = modules.findByName("ntdll.dll")?.path.toLowerCase() ?? "";
    const cut = ntdll.lastIndexOf("\\system32\\");
    this.systemRoot = cut > 0 ? ntdll.slice(0, cut + 1) : "c:\\windows\\";
  }

  isSystem(address: NativePointer): boolean {
    const m = this.modules.find(big(address));
    return m !== null && isUnder(m.path, this.systemRoot);
  }

  /** The return address if it is outside system modules, else the first fuzzy-backtrace frame that is. */
  resolve(ctx: InvocationContext): Hex {
    const ra = ctx.returnAddress;
    if (!this.isSystem(ra) && !Cloak.hasRangeContaining(ra)) return ra.toString() as Hex;
    const frames = Thread.backtrace(ctx.context, Backtracer.FUZZY);
    for (let i = 0; i < frames.length && i < 24; i++) {
      const f = frames[i];
      if (f !== undefined && !this.isSystem(f) && !Cloak.hasRangeContaining(f)) return f.toString() as Hex;
    }
    return ra.toString() as Hex;
  }
}

/** Module name for a module handle (base) from the observer-fed table. */
export const moduleNameIn =
  (modules: ModuleTable) =>
  (base: NativePointer): string | null =>
    modules.nameAt(big(base));
