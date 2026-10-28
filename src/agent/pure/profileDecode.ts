// Argument decoders of the API profile engine (S4 §10.5 "Decoder layouts"). Pure: target memory is read through
// ProfileMem<P>, the handle cache is passed in, and agent-only lookups (NtQueryKey, getsockname) are callbacks.
// Every decoder writes FLAT ValueCell keys (`<name>`, `<name>_<suffix>`); src/application/behavior/apiEvents.ts
// reads the same keys. A decoder that throws (unreadable memory) yields `<name>_err: 1` and nothing else.
import type { ValueCell } from "../../shared/agentProtocol.js";
import type { ApiArgSpec, ApiSpec, HandleKind } from "../../shared/apiProfiles.js";
import type { Hex } from "../../shared/hex.js";
import type { HandleCache } from "./profileHandles.js";
import type { Cells, PayloadCaps, ProfileMem } from "./profileTypes.js";

export interface SockName {
  readonly family: number;
  readonly addr: string;
  readonly port: number;
}

export interface DecodeEnv<P> {
  readonly mem: ProfileMem<P>;
  readonly cache: HandleCache;
  readonly caps: PayloadCaps;
  /** NtQueryKey(KeyNameInformation) on a root handle missing from the cache (F10); null when unavailable */
  readonly keyName: (root: P) => string | null;
  /** module base → module name for handles loaded before tracing (agent: a ModuleMap; never the loader lock) */
  readonly moduleName?: (base: P) => string | null;
}

const MAX_SLOTS = 12;
const ADDRINFO_MAX = 8;

const text = (s: string, trunc: boolean): ValueCell => (trunc ? { s, trunc: true } : { s });

/** Raw argument values by Win64 slot, captured once at enter (leave decoders need the original pointers). */
export const captureRaw = <P>(args: (index: number) => P, spec: ApiSpec): P[] => {
  let max = 0;
  for (const arg of spec.args) {
    max = Math.max(max, arg.slot);
    const d = arg.d;
    if ("len_arg" in d) max = Math.max(max, d.len_arg);
    if ("count_arg" in d) max = Math.max(max, d.count_arg);
    if ("class_arg" in d) max = Math.max(max, d.class_arg);
    if (d.k === "regdata") max = Math.max(max, d.type_arg, d.size_arg);
    if (d.k === "buf" && d.out_arg !== undefined) max = Math.max(max, d.out_arg);
    if (d.k === "procname") max = Math.max(max, 2);
  }
  const raw: P[] = [];
  for (let i = 0; i <= Math.min(max, MAX_SLOTS - 1); i++) raw.push(args(i));
  return raw;
};

const at = <P>(raw: readonly P[], slot: number): P => {
  const v = raw[slot];
  if (v === undefined) throw new RangeError(`slot ${String(slot)} not captured`);
  return v;
};

/** UNICODE_STRING / ANSI_STRING at p (Length u16 +0, Buffer +8), capped by max characters. */
const readCountedString = <P>(mem: ProfileMem<P>, p: P, wide: boolean, max: number): ValueCell => {
  if (mem.isNull(p)) return null;
  const bytes = mem.readU16(p);
  const buffer = mem.readPointer(mem.add(p, 8));
  if (mem.isNull(buffer) || bytes === 0) return { s: "" };
  const chars = wide ? bytes >>> 1 : bytes;
  const n = Math.min(chars, max);
  const s = wide ? mem.readUtf16(buffer, n) : mem.readAnsi(buffer, n);
  return text(s, n < chars);
};

const readZ = <P>(mem: ProfileMem<P>, p: P, wide: boolean, max: number): ValueCell => {
  if (mem.isNull(p)) return null;
  const r = wide ? mem.readUtf16z(p, max) : mem.readAnsiz(p, max);
  return text(r.s, r.trunc);
};

const cellText = (c: ValueCell | undefined): string | null =>
  c !== null && c !== undefined && typeof c === "object" && "s" in c ? c.s : null;

/** sockaddr at p (S4: family u16 +0; AF_INET port BE +2, IPv4 +4; AF_INET6 port +2, address +8). */
export const readSockaddr = <P>(mem: ProfileMem<P>, p: P): SockName | null => {
  if (mem.isNull(p)) return null;
  const family = mem.readU16(p);
  const port = (mem.readU8(mem.add(p, 2)) << 8) | mem.readU8(mem.add(p, 3));
  if (family === 2) {
    const parts: number[] = [];
    for (let i = 0; i < 4; i++) parts.push(mem.readU8(mem.add(p, 4 + i)));
    return { family, addr: parts.join("."), port };
  }
  if (family === 23) {
    const groups: string[] = [];
    for (let i = 0; i < 8; i++) {
      const hi = mem.readU8(mem.add(p, 8 + 2 * i));
      const lo = mem.readU8(mem.add(p, 9 + 2 * i));
      groups.push(((hi << 8) | lo).toString(16));
    }
    return { family, addr: groups.join(":"), port };
  }
  return { family, addr: "", port: 0 };
};

/** "127.0.0.1:80" / "[::1]:80" (no protocol suffix; sockets carry `_proto` separately). */
export const endpointText = (s: SockName): string =>
  s.family === 23 ? `[${s.addr}]:${String(s.port)}` : `${s.addr}:${String(s.port)}`;

const putSock = (cells: Cells, name: string, s: SockName | null): void => {
  if (s === null) return;
  cells[`${name}_family`] = s.family;
  if (s.family === 2 || s.family === 23) {
    cells[`${name}_addr`] = { s: s.addr };
    cells[`${name}_port`] = s.port;
  }
};

/** Path text of a handle (cache), or the S6 placeholder for handles opened before tracing. */
const handleText = (cache: HandleCache, h: Hex): string => cache.get(h)?.name ?? `<handle ${h}>`;

const joinPath = (root: string, name: string): string =>
  name === "" ? root : root.endsWith("\\") ? `${root}${name}` : `${root}\\${name}`;

/** OBJECT_ATTRIBUTES (RootDirectory +0x8, ObjectName +0x10, Attributes +0x18) → full path text. */
const decodeOa = <P>(env: DecodeEnv<P>, cells: Cells, name: string, p: P, kind: "file" | "key"): void => {
  const { mem, cache } = env;
  if (mem.isNull(p)) {
    cells[name] = null;
    return;
  }
  const root = mem.readPointer(mem.add(p, 8));
  const object = readCountedString(mem, mem.readPointer(mem.add(p, 0x10)), true, 4096);
  cells[`${name}_attr`] = mem.readU32(mem.add(p, 0x18));
  const leaf = cellText(object) ?? "";
  if (mem.isNull(root)) {
    cells[name] = object;
    return;
  }
  const rootHex = mem.hex(root);
  cells[`${name}_root`] = rootHex;
  let rootName = cache.get(rootHex)?.name ?? null;
  if (rootName === null && kind === "key") {
    rootName = env.keyName(root);
    if (rootName !== null) cache.set(rootHex, { kind: "key", name: rootName });
  }
  const trunc = object !== null && typeof object === "object" && "trunc" in object;
  cells[name] = text(joinPath(rootName ?? `<handle ${rootHex}>`, leaf), trunc);
};

/** FILE_* information payload of NtSetInformationFile, by class (S4 §10.5 fileinfo; layouts BELIEVED). */
const decodeFileInfo = <P>(env: DecodeEnv<P>, cells: Cells, name: string, p: P, cls: number, len: number): void => {
  const { mem, cache } = env;
  cells[`${name}_class`] = cls;
  if (mem.isNull(p)) return;
  if (cls === 10 || cls === 65) {
    // FILE_RENAME_INFORMATION: Flags/ReplaceIfExists +0, RootDirectory +8, FileNameLength +0x10, FileName +0x14
    cells[`${name}_flags`] = cls === 10 ? mem.readU8(p) : mem.readU32(p);
    const root = mem.readPointer(mem.add(p, 8));
    const bytes = mem.readU32(mem.add(p, 0x10));
    const chars = Math.min(bytes >>> 1, 4096, Math.max(0, (len - 0x14) >>> 1));
    const leaf = mem.readUtf16(mem.add(p, 0x14), chars);
    const target = mem.isNull(root) ? leaf : joinPath(handleText(cache, mem.hex(root)), leaf);
    cells[`${name}_target`] = text(target, chars < bytes >>> 1);
  } else if (cls === 13) {
    cells[`${name}_delete`] = mem.readU8(p) !== 0 ? 1 : 0;
  } else if (cls === 64) {
    const flags = mem.readU32(p);
    cells[`${name}_flags`] = flags;
    cells[`${name}_delete`] = flags & 1;
  } else if (cls === 20) {
    cells[`${name}_eof`] = mem.readU64(p);
  } else if (cls === 4) {
    cells[`${name}_attributes`] = mem.readU32(mem.add(p, 0x20));
  }
};

/** RTL_USER_PROCESS_PARAMETERS (CurrentDirectory.DosPath +0x38, ImagePathName +0x60, CommandLine +0x70; BELIEVED).
 *  A non-normalized block (Flags +8 bit 0 clear) stores Buffer as an offset from the block. */
const decodeProcParams = <P>(mem: ProfileMem<P>, cells: Cells, name: string, p: P): void => {
  if (mem.isNull(p)) return;
  const normalized = (mem.readU32(mem.add(p, 8)) & 1) !== 0;
  const us = (off: number, max: number): ValueCell => {
    const u = mem.add(p, off);
    const bytes = mem.readU16(u);
    let buffer = mem.readPointer(mem.add(u, 8));
    if (!normalized && !mem.isNull(buffer)) buffer = mem.add(p, Number(BigInt(mem.hex(buffer))));
    if (mem.isNull(buffer) || bytes === 0) return { s: "" };
    const chars = Math.min(bytes >>> 1, max);
    return text(mem.readUtf16(buffer, chars), chars < bytes >>> 1);
  };
  cells[`${name}_image`] = us(0x60, 1024);
  cells[`${name}_cmdline`] = us(0x70, 4096);
  cells[`${name}_cwd`] = us(0x38, 1024);
};

const readAddrinfo = <P>(mem: ProfileMem<P>, cells: Cells, name: string, pp: P, ex: boolean): void => {
  if (mem.isNull(pp)) return;
  let node = mem.readPointer(pp);
  let n = 0;
  while (!mem.isNull(node) && n < ADDRINFO_MAX) {
    const sa = readSockaddr(mem, mem.readPointer(mem.add(node, 32)));
    if (sa !== null && (sa.family === 2 || sa.family === 23)) cells[`${name}_addr${String(n)}`] = { s: sa.addr };
    n++;
    node = mem.readPointer(mem.add(node, ex ? 64 : 40));
  }
  cells[`${name}_count`] = n;
};

const payload = <P>(mem: ProfileMem<P>, cells: Cells, name: string, p: P, len: number, cap: number): void => {
  cells[`${name}_len`] = len;
  if (cap > 0 && len > 0 && !mem.isNull(p)) cells[`${name}_hex`] = { s: mem.readHex(p, Math.min(len, cap)) };
};

const capFor = (spec: ApiSpec, caps: PayloadCaps): number =>
  spec.profile === "file" ? caps.fileBytes : spec.profile === "network" ? caps.netBytes : 0;

/** Registry value preview (S4 kvinfo/regdata value rules), only when capture_value_bytes > 0. */
const regPreview = <P>(
  mem: ProfileMem<P>,
  cells: Cells,
  name: string,
  type: number,
  p: P,
  size: number,
  cap: number,
) => {
  if (cap <= 0 || mem.isNull(p) || size <= 0) return;
  const n = Math.min(size, cap);
  if (type === 1 || type === 2)
    cells[`${name}_preview`] = text(mem.readUtf16(p, n >>> 1).replace(/\0+$/u, ""), n < size);
  else if (type === 4 && size >= 4) cells[`${name}_preview`] = mem.readU32(p);
  else if (type === 11 && size >= 8) cells[`${name}_preview`] = mem.readU64(p);
  else cells[`${name}_preview`] = text(mem.readHex(p, n), n < size);
};

/** Decode the enter-time view of one argument. */
const decodeArgEnter = <P>(env: DecodeEnv<P>, spec: ApiSpec, arg: ApiArgSpec, raw: readonly P[], cells: Cells) => {
  const { mem } = env;
  const v = at(raw, arg.slot);
  const n = arg.name;
  const d = arg.d;
  switch (d.k) {
    case "u32":
      cells[n] = mem.u32(v);
      return;
    case "i32":
      cells[n] = mem.i32(v);
      return;
    case "u64":
    case "ptr":
      cells[n] = mem.hex(v);
      return;
    case "bool":
      cells[n] = (mem.u32(v) & 0xff) !== 0 ? 1 : 0;
      return;
    case "handle": {
      const hx = mem.hex(v);
      cells[n] = hx;
      let entry = env.cache.get(hx);
      if (entry === undefined && d.kind === "module" && env.moduleName !== undefined) {
        const name = env.moduleName(v);
        if (name !== null) {
          entry = { kind: "module", name };
          env.cache.set(hx, entry);
        }
      }
      cells[`${n}_name`] = entry?.name === null || entry === undefined ? null : { s: entry.name };
      if (entry?.proto !== undefined) cells[`${n}_proto`] = { s: entry.proto };
      return;
    }
    case "wstr":
    case "astr":
      cells[n] = readZ(mem, v, d.k === "wstr", d.max);
      return;
    case "ustr":
      cells[n] = readCountedString(mem, v, true, d.max);
      return;
    case "oa":
      decodeOa(env, cells, n, v, d.kind);
      return;
    case "inout_ptr":
      cells[n] = mem.isNull(v) ? null : mem.hex(mem.readPointer(v));
      return;
    case "inout_size":
      cells[n] = mem.isNull(v) ? null : mem.readU64(v);
      return;
    case "i64ptr":
      cells[n] = mem.isNull(v) ? null : mem.readU64(v);
      return;
    case "client_id":
      if (mem.isNull(v)) return;
      cells[`${n}_pid`] = mem.u32(mem.readPointer(v));
      cells[`${n}_tid`] = mem.u32(mem.readPointer(mem.add(v, 8)));
      return;
    case "proc_params":
      decodeProcParams(mem, cells, n, v);
      return;
    case "loadpath":
      if ((mem.u32(v) & 1) === 1) cells[`${n}_flags`] = mem.u32(v);
      else cells[n] = readZ(mem, v, true, 1024);
      return;
    case "procname": {
      const s = readCountedString(mem, v, false, 256);
      cells[n] = s;
      if (s === null) cells[`${n}_ordinal`] = mem.u32(at(raw, 2));
      return;
    }
    case "sockaddr":
      putSock(cells, n, readSockaddr(mem, v));
      return;
    case "wsabufs":
      if (d.when === "enter") cells[`${n}_len`] = wsabufTotal(mem, v, mem.u32(at(raw, d.count_arg)));
      return;
    case "buf":
      if (d.when === "enter" && d.len_from === "arg")
        payload(mem, cells, n, v, Math.max(0, mem.i32(at(raw, d.len_arg))), capFor(spec, env.caps));
      return;
    case "fileinfo":
      decodeFileInfo(env, cells, n, v, mem.u32(at(raw, d.class_arg)), mem.u32(at(raw, d.len_arg)));
      return;
    case "regdata": {
      const type = mem.u32(at(raw, d.type_arg));
      const size = mem.u32(at(raw, d.size_arg));
      cells[`${n}_type`] = type;
      cells[`${n}_size`] = size;
      regPreview(mem, cells, n, type, v, size, env.caps.valueBytes);
      return;
    }
    case "dnsreq":
      if (mem.isNull(v)) return;
      cells[`${n}_name`] = readZ(mem, mem.readPointer(mem.add(v, 8)), true, 256);
      cells[`${n}_type`] = mem.readU16(mem.add(v, 16));
      return;
    // leave-only decoders
    case "out_handle":
    case "iosb":
    case "out_u32":
    case "out_ptr":
    case "proc_info_out":
    case "out_sockaddr":
    case "kvinfo":
    case "addrinfo_out":
      return;
  }
};

const wsabufTotal = <P>(mem: ProfileMem<P>, p: P, count: number): number => {
  if (mem.isNull(p)) return 0;
  let total = 0;
  for (let i = 0; i < Math.min(count, 64); i++) total += mem.readU32(mem.add(p, 16 * i));
  return total;
};

/** Information of an IO_STATUS_BLOCK argument of the same spec (for buf len_from "iosb"). */
const iosbInformation = <P>(mem: ProfileMem<P>, spec: ApiSpec, raw: readonly P[]): number | null => {
  const iosb = spec.args.find((x) => x.d.k === "iosb");
  if (iosb === undefined) return null;
  const p = at(raw, iosb.slot);
  return mem.isNull(p) ? null : Number(BigInt(mem.readU64(mem.add(p, 8))));
};

/** Decode the leave-time view of one argument (`ok` = the call succeeded per its return convention). */
const decodeArgLeave = <P>(
  env: DecodeEnv<P>,
  spec: ApiSpec,
  arg: ApiArgSpec,
  raw: readonly P[],
  ret: P,
  ok: boolean,
  cells: Cells,
) => {
  const { mem } = env;
  const v = at(raw, arg.slot);
  const n = arg.name;
  const d = arg.d;
  switch (d.k) {
    case "out_handle":
      cells[n] = ok && !mem.isNull(v) ? mem.hex(mem.readPointer(v)) : null;
      return;
    case "iosb":
      cells[n] = ok && !mem.isNull(v) ? mem.readU64(mem.add(v, 8)) : null;
      return;
    case "inout_ptr":
      if (ok && !mem.isNull(v)) cells[`${n}_out`] = mem.hex(mem.readPointer(v));
      return;
    case "inout_size":
      if (ok && !mem.isNull(v)) cells[`${n}_out`] = mem.readU64(v);
      return;
    case "out_u32":
      cells[n] = ok && !mem.isNull(v) ? mem.readU32(v) : null;
      return;
    case "out_ptr":
      cells[n] = ok && !mem.isNull(v) ? mem.hex(mem.readPointer(v)) : null;
      return;
    case "proc_info_out":
      if (!ok || mem.isNull(v)) return;
      cells[`${n}_pid`] = mem.readU32(mem.add(v, 0x10));
      cells[`${n}_tid`] = mem.readU32(mem.add(v, 0x14));
      return;
    case "out_sockaddr":
      if (ok && !mem.isNull(v)) putSock(cells, n, readSockaddr(mem, v));
      return;
    case "wsabufs":
      if (d.when === "leave" && ok) cells[`${n}_len`] = wsabufTotal(mem, v, mem.u32(at(raw, d.count_arg)));
      return;
    case "buf": {
      if (d.when !== "leave") return;
      let len: number | null = null;
      if (ok) {
        if (d.len_from === "ret") len = Math.max(0, mem.i32(ret));
        else if (d.len_from === "iosb") len = iosbInformation(mem, spec, raw);
        else if (d.len_from === "out_arg" && d.out_arg !== undefined) {
          const out = at(raw, d.out_arg);
          len = mem.isNull(out) ? null : mem.readU32(out);
        } else len = Math.max(0, mem.i32(at(raw, d.len_arg)));
      }
      if (len === null) cells[`${n}_len`] = null;
      else payload(mem, cells, n, v, len, capFor(spec, env.caps));
      return;
    }
    case "kvinfo": {
      if (!ok || mem.isNull(v)) return;
      const cls = mem.u32(at(raw, d.class_arg));
      if (cls === 2) {
        // KEY_VALUE_PARTIAL_INFORMATION: TitleIndex +0, Type +4, DataLength +8, Data +0xC
        const type = mem.readU32(mem.add(v, 4));
        const size = mem.readU32(mem.add(v, 8));
        cells[`${n}_type`] = type;
        cells[`${n}_size`] = size;
        regPreview(mem, cells, n, type, mem.add(v, 0xc), size, env.caps.valueBytes);
      } else if (cls === 1) {
        // KEY_VALUE_FULL_INFORMATION: Type +4, DataOffset +8, DataLength +0xC
        const type = mem.readU32(mem.add(v, 4));
        const size = mem.readU32(mem.add(v, 0xc));
        cells[`${n}_type`] = type;
        cells[`${n}_size`] = size;
        regPreview(mem, cells, n, type, mem.add(v, mem.readU32(mem.add(v, 8))), size, env.caps.valueBytes);
      }
      return;
    }
    case "addrinfo_out":
      if (ok) readAddrinfo(mem, cells, n, v, d.ex);
      return;
    default:
      return;
  }
};

/** Enter-time cells of a call. Unreadable arguments mark `<name>_err` and never abort the row. */
export const decodeEnter = <P>(env: DecodeEnv<P>, spec: ApiSpec, raw: readonly P[]): Cells => {
  const cells: Cells = {};
  for (const arg of spec.args) {
    try {
      decodeArgEnter(env, spec, arg, raw, cells);
    } catch {
      cells[`${arg.name}_err`] = 1;
    }
  }
  return cells;
};

export const decodeLeave = <P>(
  env: DecodeEnv<P>,
  spec: ApiSpec,
  raw: readonly P[],
  ret: P,
  ok: boolean,
  cells: Cells,
): void => {
  for (const arg of spec.args) {
    try {
      decodeArgLeave(env, spec, arg, raw, ret, ok, cells);
    } catch {
      cells[`${arg.name}_err`] = 1;
    }
  }
};

const INVALID_SOCKET: Hex = "0xffffffffffffffff";

/** Did the call succeed, per its return convention? */
export const callSucceeded = <P>(mem: ProfileMem<P>, spec: ApiSpec, ret: P): boolean => {
  switch (spec.ret) {
    case "ntstatus":
      return mem.i32(ret) >= 0;
    case "bool32":
      return mem.u32(ret) !== 0;
    case "handle":
    case "ptr":
      return !mem.isNull(ret);
    case "socket":
      return mem.hex(ret) !== INVALID_SOCKET;
    case "i32":
      // getaddrinfo-style APIs return an error code (0 = ok); Winsock calls return SOCKET_ERROR (-1)
      return spec.op === "dns" ? mem.i32(ret) === 0 : mem.i32(ret) >= 0;
    case "u32":
    case "void":
      return true;
  }
};

/** The row's ret cell (S4 §10.6: NTSTATUS as u32 Hex; BOOL/int as numbers; handles/pointers as Hex). */
export const retCell = <P>(mem: ProfileMem<P>, spec: ApiSpec, ret: P): ValueCell => {
  switch (spec.ret) {
    case "ntstatus":
      return `0x${(mem.u32(ret) >>> 0).toString(16)}` as Hex;
    case "bool32":
    case "u32":
      return mem.u32(ret);
    case "i32":
      return mem.i32(ret);
    case "handle":
    case "ptr":
    case "socket":
      return mem.hex(ret);
    case "void":
      return null;
  }
};

/** Name to cache for a successfully opened handle: the first path-like cell of the row. */
export const openedName = (spec: ApiSpec, cells: Cells, kind: HandleKind): string | null => {
  for (const arg of spec.args) {
    if (arg.d.k === "oa") return cellText(cells[arg.name]);
    if (arg.d.k === "client_id" && kind === "process") {
      const pid = cells[`${arg.name}_pid`];
      return typeof pid === "number" ? `pid:${String(pid)}` : null;
    }
    if (arg.d.k === "proc_params" && kind === "process") return cellText(cells[`${arg.name}_image`]);
  }
  return null;
};

export { cellText };
