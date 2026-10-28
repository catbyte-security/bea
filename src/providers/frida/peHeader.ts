import { open, stat } from "node:fs/promises";

import type { BeaError } from "../../domain/errors/beaError.js";
import { formatHex, type Hex } from "../../domain/hex.js";
import { err, ok, type Result } from "../../domain/result.js";

/**
 * Spawn/attach preflight over the ON-DISK image (S3 §8.1 step 1; pure parsing over bounded reads): machine 0x8664 and
 * PE32+ magic, the preferred ImageBase (the loader rewrites the in-memory header, ext-frida §1.12), SizeOfImage,
 * TimeDateStamp, and the imported DLL names (static + delay-load) for anti-cheat signal (b). Reads at most a few
 * hundred KiB whatever the image size.
 */
export interface PeHeaderFacts {
  readonly machine: number;
  readonly imageBase: Hex;
  readonly sizeOfImage: number;
  readonly timeDateStamp: number;
  readonly fileSize: number;
  /** lowercase-preserving DLL names; empty when the import tables could not be read */
  readonly imports: readonly string[];
  readonly importsComplete: boolean;
  /**
   * VERSIONINFO OriginalFilename and InternalName (review fix SEC-1: the spawn policy refuses renamed copies of
   * interpreters by these); empty when the image has no readable version resource.
   */
  readonly versionNames: readonly string[];
}

const MACHINE_AMD64 = 0x8664;
const MACHINE_I386 = 0x14c;
const PE32_PLUS = 0x20b;
const PE32 = 0x10b;
const MAX_HEADER_READ = 64 * 1024;
const MAX_DESCRIPTORS = 512;
const MAX_NAME = 260;

interface Section {
  readonly va: number;
  readonly vsize: number;
  readonly rawPtr: number;
  readonly rawSize: number;
}

const notPe64 = (operation: string, reason: "not-pe64" | "wow64" | "unsupported-arch", path: string): BeaError => ({
  _tag: "UnsupportedTarget",
  operation,
  reason,
  diagnostics: { file: basenameSafe(path) },
});

const basenameSafe = (path: string): string => path.slice(Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/")) + 1);

export const readPeHeader = async (path: string, operation: string): Promise<Result<PeHeaderFacts, BeaError>> => {
  let size: number;
  try {
    const info = await stat(path);
    if (!info.isFile())
      return err({ _tag: "FileOperationFailed", operation, file_operation: "stat", path, reason: "not-file" });
    size = info.size;
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    return err({
      _tag: "FileOperationFailed",
      operation,
      file_operation: "stat",
      path,
      reason:
        code === "ENOENT" || code === "ENOTDIR"
          ? "missing"
          : code === "EACCES" || code === "EPERM"
            ? "permission"
            : "io",
    });
  }
  let handle;
  try {
    handle = await open(path, "r");
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    return err({
      _tag: "FileOperationFailed",
      operation,
      file_operation: "read",
      path,
      reason: code === "EACCES" || code === "EPERM" || code === "EBUSY" ? "permission" : "io",
    });
  }
  try {
    const read = async (offset: number, length: number): Promise<Buffer> => {
      const buffer = Buffer.alloc(Math.max(0, Math.min(length, size - offset)));
      if (buffer.length === 0 || offset < 0) return Buffer.alloc(0);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
      return buffer.subarray(0, bytesRead);
    };
    const head = await read(0, MAX_HEADER_READ);
    return await parsePe(head, size, read, path, operation);
  } finally {
    await handle.close().catch(() => undefined);
  }
};

const parsePe = async (
  head: Buffer,
  size: number,
  read: (offset: number, length: number) => Promise<Buffer>,
  path: string,
  operation: string,
): Promise<Result<PeHeaderFacts, BeaError>> => {
  if (head.length < 0x40 || head.readUInt16LE(0) !== 0x5a4d) return err(notPe64(operation, "not-pe64", path));
  const peOffset = head.readUInt32LE(0x3c);
  if (peOffset + 24 > head.length || head.readUInt32LE(peOffset) !== 0x0000_4550)
    return err(notPe64(operation, "not-pe64", path));
  const machine = head.readUInt16LE(peOffset + 4);
  const sectionCount = head.readUInt16LE(peOffset + 6);
  const timeDateStamp = head.readUInt32LE(peOffset + 8);
  const optSize = head.readUInt16LE(peOffset + 20);
  const opt = peOffset + 24;
  if (opt + 2 > head.length) return err(notPe64(operation, "not-pe64", path));
  const magic = head.readUInt16LE(opt);
  if (machine === MACHINE_I386 || magic === PE32) return err(notPe64(operation, "wow64", path));
  if (machine !== MACHINE_AMD64) return err(notPe64(operation, "unsupported-arch", path));
  if (magic !== PE32_PLUS || opt + 112 > head.length) return err(notPe64(operation, "not-pe64", path));
  const imageBase = formatHex(head.readBigUInt64LE(opt + 24));
  const sizeOfImage = head.readUInt32LE(opt + 56);
  const dirCount = head.readUInt32LE(opt + 108);
  const dir = (index: number): { readonly rva: number; readonly size: number } | null => {
    const at = opt + 112 + index * 8;
    if (index >= dirCount || at + 8 > opt + optSize || at + 8 > head.length) return null;
    return { rva: head.readUInt32LE(at), size: head.readUInt32LE(at + 4) };
  };
  const sections: Section[] = [];
  const sectionTable = opt + optSize;
  for (let i = 0; i < Math.min(sectionCount, 96); i += 1) {
    const at = sectionTable + i * 40;
    if (at + 40 > head.length) break;
    sections.push({
      vsize: head.readUInt32LE(at + 8),
      va: head.readUInt32LE(at + 12),
      rawSize: head.readUInt32LE(at + 16),
      rawPtr: head.readUInt32LE(at + 20),
    });
  }
  const fileOffset = (rva: number): number | null => {
    for (const s of sections)
      if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) {
        const offset = s.rawPtr + (rva - s.va);
        return offset < size ? offset : null;
      }
    return rva < head.length ? rva : null;
  };
  const readName = async (rva: number): Promise<string | null> => {
    const offset = fileOffset(rva);
    if (offset === null) return null;
    const bytes = await read(offset, MAX_NAME + 1);
    const end = bytes.indexOf(0);
    if (end <= 0) return null;
    const name = bytes.subarray(0, end).toString("latin1");
    return /^[\x20-\x7e]+$/u.test(name) ? name : null;
  };
  const imports: string[] = [];
  let complete = true;
  for (const [index, stride, nameOffset] of [
    [1, 20, 12],
    [13, 32, 4],
  ] as const) {
    const directory = dir(index);
    if (directory === null || directory.rva === 0 || directory.size === 0) continue;
    const offset = fileOffset(directory.rva);
    if (offset === null) {
      complete = false;
      continue;
    }
    const table = await read(offset, Math.min(directory.size, MAX_DESCRIPTORS * stride));
    for (let at = 0; at + stride <= table.length; at += stride) {
      const nameRva = table.readUInt32LE(at + nameOffset);
      if (nameRva === 0) break;
      const name = await readName(nameRva);
      if (name === null) complete = false;
      else imports.push(name);
    }
  }
  const versionNames = await readVersionNames(dir(2), fileOffset, read);
  return ok({
    machine,
    imageBase,
    sizeOfImage,
    timeDateStamp,
    fileSize: size,
    imports,
    importsComplete: complete,
    versionNames,
  });
};

const RT_VERSION = 16;
const MAX_RESOURCE_ENTRIES = 256;
const MAX_VERSION_BYTES = 64 * 1024;
const VERSION_KEYS = ["OriginalFilename", "InternalName"] as const;

/**
 * RT_VERSION → first name → first language → VS_VERSIONINFO, then the String entries named by VERSION_KEYS (bounded
 * reads; any malformed structure gives no names).
 */
const readVersionNames = async (
  directory: { readonly rva: number; readonly size: number } | null,
  fileOffset: (rva: number) => number | null,
  read: (offset: number, length: number) => Promise<Buffer>,
): Promise<readonly string[]> => {
  if (directory === null || directory.rva === 0 || directory.size === 0) return [];
  const base = fileOffset(directory.rva);
  if (base === null) return [];
  /** one IMAGE_RESOURCE_DIRECTORY's entries: [name/id, offsetToData] */
  const entries = async (offset: number): Promise<[number, number][]> => {
    const head = await read(base + offset, 16);
    if (head.length < 16) return [];
    const count = Math.min(head.readUInt16LE(12) + head.readUInt16LE(14), MAX_RESOURCE_ENTRIES);
    const table = await read(base + offset + 16, count * 8);
    const out: [number, number][] = [];
    for (let at = 0; at + 8 <= table.length; at += 8) out.push([table.readUInt32LE(at), table.readUInt32LE(at + 4)]);
    return out;
  };
  const SUBDIR = 0x8000_0000;
  const types = await entries(0);
  const version = types.find(([id, to]) => id === RT_VERSION && (to & SUBDIR) !== 0);
  if (version === undefined) return [];
  const names = await entries(version[1] & ~SUBDIR);
  const name = names.find(([, to]) => (to & SUBDIR) !== 0);
  if (name === undefined) return [];
  const languages = await entries(name[1] & ~SUBDIR);
  const language = languages.find(([, to]) => (to & SUBDIR) === 0);
  if (language === undefined) return [];
  const dataEntry = await read(base + language[1], 16);
  if (dataEntry.length < 16) return [];
  const dataOffset = fileOffset(dataEntry.readUInt32LE(0));
  if (dataOffset === null) return [];
  const data = await read(dataOffset, Math.min(dataEntry.readUInt32LE(4), MAX_VERSION_BYTES));
  const out: string[] = [];
  for (const key of VERSION_KEYS) {
    const value = versionString(data, key);
    if (value !== null && value.length > 0) out.push(value.slice(0, MAX_NAME));
  }
  return out;
};

/**
 * A VERSIONINFO String {wLength, wValueLength, wType, szKey, padding, Value}: the key is found by its UTF-16LE
 * spelling (NUL-terminated), the value starts at the next 32-bit boundary of the resource data.
 */
const versionString = (data: Buffer, key: string): string | null => {
  const needle = Buffer.from(`${key}\0`, "utf16le");
  for (let at = data.indexOf(needle); at >= 6; at = data.indexOf(needle, at + 2)) {
    if (at % 2 !== 0) continue;
    const wLength = data.readUInt16LE(at - 6);
    const wValueLength = data.readUInt16LE(at - 4);
    const valueAt = (at + needle.length + 3) & ~3;
    const end = Math.min(at - 6 + wLength, data.length, valueAt + wValueLength * 2);
    if (wValueLength === 0 || end <= valueAt) continue;
    const text = data.subarray(valueAt, end - ((end - valueAt) % 2)).toString("utf16le");
    const value = text.split("\0")[0] ?? "";
    return /^[\x20-\x7e]+$/u.test(value) ? value.trim() : null;
  }
  return null;
};
