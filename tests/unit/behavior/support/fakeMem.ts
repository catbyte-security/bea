import type { ProfileMem } from "../../../../src/agent/pure/profileTypes.js";
import { formatHex, type Hex } from "../../../../src/shared/hex.js";

/**
 * Sparse little-endian fake target memory for the pure profile engine (pointer type = bigint). Unwritten bytes are
 * unmapped: reading them throws like a Frida access violation. Builders lay out the NT/Winsock structures the
 * decoders read (S4 §10.5 offsets).
 */
export class FakeMem implements ProfileMem<bigint> {
  private readonly bytes = new Map<bigint, number>();
  private next = 0x10_0000n;

  // ------------------------------------------------------------------ writers
  write(addr: bigint, data: Uint8Array): bigint {
    data.forEach((b, i) => this.bytes.set(addr + BigInt(i), b));
    return addr;
  }
  writeUInt(addr: bigint, value: bigint | number, size: number): bigint {
    let v = BigInt(value) & ((1n << BigInt(size * 8)) - 1n);
    for (let i = 0; i < size; i++) {
      this.bytes.set(addr + BigInt(i), Number(v & 0xffn));
      v >>= 8n;
    }
    return addr;
  }
  alloc(size: number, fill = 0): bigint {
    const addr = this.next;
    this.next += BigInt(Math.ceil((size + 16) / 16) * 16);
    for (let i = 0; i < size; i++) this.bytes.set(addr + BigInt(i), fill);
    return addr;
  }
  /** UTF-16LE text (+ NUL terminator) */
  wstr(s: string): bigint {
    const addr = this.alloc(s.length * 2 + 2);
    for (let i = 0; i < s.length; i++) this.writeUInt(addr + BigInt(2 * i), s.charCodeAt(i), 2);
    return addr;
  }
  astr(s: string): bigint {
    const addr = this.alloc(s.length + 1);
    for (let i = 0; i < s.length; i++) this.bytes.set(addr + BigInt(i), s.charCodeAt(i));
    return addr;
  }
  /** UNICODE_STRING {Length u16, MaximumLength u16, Buffer +8}; Buffer is NOT NUL-terminated on purpose */
  ustr(s: string): bigint {
    const buffer = this.alloc(s.length * 2);
    for (let i = 0; i < s.length; i++) this.writeUInt(buffer + BigInt(2 * i), s.charCodeAt(i), 2);
    const us = this.alloc(16);
    this.writeUInt(us, s.length * 2, 2);
    this.writeUInt(us + 2n, s.length * 2, 2);
    this.writeUInt(us + 8n, buffer, 8);
    return us;
  }
  /** ANSI_STRING */
  anstr(s: string): bigint {
    const buffer = this.astr(s);
    const us = this.alloc(16);
    this.writeUInt(us, s.length, 2);
    this.writeUInt(us + 8n, buffer, 8);
    return us;
  }
  /** OBJECT_ATTRIBUTES {Length +0, RootDirectory +8, ObjectName +0x10, Attributes +0x18} */
  oa(name: string, root = 0n, attributes = 0x40): bigint {
    const oa = this.alloc(48);
    this.writeUInt(oa, 48, 4);
    this.writeUInt(oa + 8n, root, 8);
    this.writeUInt(oa + 0x10n, this.ustr(name), 8);
    this.writeUInt(oa + 0x18n, attributes, 4);
    return oa;
  }
  /** sockaddr_in */
  sockaddrIn(ip: string, port: number): bigint {
    const sa = this.alloc(16);
    this.writeUInt(sa, 2, 2);
    this.bytes.set(sa + 2n, (port >> 8) & 0xff);
    this.bytes.set(sa + 3n, port & 0xff);
    ip.split(".").forEach((p, i) => this.bytes.set(sa + 4n + BigInt(i), Number(p)));
    return sa;
  }
  /** an out slot (PHANDLE, PULONG, PVOID*) */
  slot(initial: bigint | number = 0): bigint {
    return this.writeUInt(this.alloc(8), initial, 8);
  }
  /** IO_STATUS_BLOCK {Status +0, Information +8} */
  iosb(): bigint {
    return this.alloc(16);
  }
  setIosb(iosb: bigint, information: number): void {
    this.writeUInt(iosb + 8n, information, 8);
  }

  // ------------------------------------------------------------------ ProfileMem
  isNull = (p: bigint): boolean => p === 0n;
  add = (p: bigint, offset: number): bigint => p + BigInt(offset);
  hex = (p: bigint): Hex => formatHex(p);
  u32 = (p: bigint): number => Number(p & 0xffff_ffffn);
  i32 = (p: bigint): number => Number(BigInt.asIntN(32, p));
  private byte(p: bigint): number {
    const b = this.bytes.get(p);
    if (b === undefined) throw new Error(`access violation accessing ${formatHex(p)}`);
    return b;
  }
  private uint(p: bigint, size: number): bigint {
    let v = 0n;
    for (let i = size - 1; i >= 0; i--) v = (v << 8n) | BigInt(this.byte(p + BigInt(i)));
    return v;
  }
  readPointer = (p: bigint): bigint => this.uint(p, 8);
  readU8 = (p: bigint): number => this.byte(p);
  readU16 = (p: bigint): number => Number(this.uint(p, 2));
  readU32 = (p: bigint): number => Number(this.uint(p, 4));
  readU64 = (p: bigint): Hex => formatHex(this.uint(p, 8));
  readUtf16 = (p: bigint, chars: number): string => {
    let s = "";
    for (let i = 0; i < chars; i++) {
      const c = Number(this.uint(p + BigInt(2 * i), 2));
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  };
  readAnsi = (p: bigint, chars: number): string => {
    let s = "";
    for (let i = 0; i < chars; i++) {
      const c = this.byte(p + BigInt(i));
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  };
  readUtf16z = (p: bigint, max: number) => {
    const s = this.readUtf16(p, max);
    return { s, trunc: s.length >= max };
  };
  readAnsiz = (p: bigint, max: number) => {
    const s = this.readAnsi(p, max);
    return { s, trunc: s.length >= max };
  };
  readHex = (p: bigint, n: number): string => {
    let out = "";
    for (let i = 0; i < n; i++)
      out += this.byte(p + BigInt(i))
        .toString(16)
        .padStart(2, "0");
    return out;
  };
}

/** Win64 -1 / INVALID_HANDLE_VALUE / NtCurrentProcess() */
export const MINUS_ONE = 0xffff_ffff_ffff_ffffn;
