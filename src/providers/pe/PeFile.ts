import { formatHex, type Hex } from "../../domain/hex.js";
import type { HostPlatform } from "../../domain/paths.js";
import type { FileKey } from "../../domain/process/instance.js";
import type { FunctionTable, PeExport, PeImage, PeImport, PeSection } from "../../ports/pe.js";
import { withFile, type FileReader } from "./fileAccess.js";
import { DIR, locateRva, parseHeaders, sectionIndexOf, type PeHeaders } from "./headers.js";
import {
  parseCfgSlots,
  parseCodeView,
  parseDebugDirectory,
  parseExports,
  parseImports,
  parsePdata,
  parseRelocations,
  parseTlsCallbacks,
  type Parsed,
  type PdataTable,
  type TableIssue,
} from "./tables.js";
import { runTable, type ImageView } from "./view.js";

/**
 * BEA's on-disk PE32+ reader (S2 §17; VERIFIED equal to pefile on gcc fixtures and five system DLLs, S2 lab E1).
 * Headers, sections, CodeView and TLS are parsed at open; exports, imports, .pdata and relocations lazily (once,
 * cached). Every read re-checks the FileKey: a file that changed on disk fails with an io PeFailure and
 * PeImageCache re-parses it on the next open (S2 §17.5).
 */
const MAX_CODEVIEW = 4096;

export type LoaderRange = { rva: number; size: number; class: "iat" | "delay-iat" | "loader-thunk" | "loader-cfg" };

const machineOf = (machine: number): PeImage["machine"] =>
  machine === 0x8664 ? "x64" : machine === 0xaa64 ? "arm64" : "unknown";

const lowerBound = (sorted: Uint32Array, value: number): number => {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if ((sorted[mid] ?? 0) < value) lo = mid + 1;
    else hi = mid;
  }
  return lo;
};

export class PeFile implements PeImage {
  readonly format = "pe32+" as const;
  readonly machine: PeImage["machine"];
  readonly time_date_stamp: number;
  readonly characteristics: number;
  readonly dll: boolean;
  readonly image_base: Hex;
  readonly size_of_image: number;
  readonly size_of_headers: number;
  readonly entry_rva: number | null;
  readonly subsystem: number;
  readonly dll_characteristics: PeImage["dll_characteristics"];
  readonly sections: readonly PeSection[];
  readonly signed: boolean;
  readonly clr: boolean;
  readonly #issues: TableIssue[];
  readonly #lazy = new Map<string, Promise<unknown>>();

  private constructor(
    readonly path_display: string,
    readonly file: FileKey,
    private readonly platform: HostPlatform,
    readonly headers: PeHeaders,
    readonly codeview: PeImage["codeview"],
    readonly tls_callbacks: readonly number[],
    issues: readonly TableIssue[],
  ) {
    this.machine = machineOf(headers.machine);
    this.time_date_stamp = headers.timeDateStamp;
    this.characteristics = headers.characteristics;
    this.dll = (headers.characteristics & 0x2000) !== 0;
    this.image_base = formatHex(headers.imageBase);
    this.size_of_image = headers.sizeOfImage;
    this.size_of_headers = headers.sizeOfHeaders;
    this.entry_rva = headers.entryRva === 0 ? null : headers.entryRva;
    this.subsystem = headers.subsystem;
    const dc = headers.dllCharacteristics;
    this.dll_characteristics = {
      dynamic_base: (dc & 0x40) !== 0,
      high_entropy_va: (dc & 0x20) !== 0,
      nx_compat: (dc & 0x100) !== 0,
      guard_cf: (dc & 0x4000) !== 0,
    };
    this.sections = headers.sections;
    this.signed = (headers.dirs[DIR.security]?.size ?? 0) > 0;
    this.clr = (headers.dirs[DIR.clr]?.rva ?? 0) !== 0;
    this.#issues = [...headers.issues, ...issues];
  }

  /** Parse headers + CodeView + TLS callbacks (throws PeFailure on an invalid header). */
  static async open(path: string, file: FileKey, platform: HostPlatform, signal?: AbortSignal): Promise<PeFile> {
    return withFile(
      path,
      platform,
      file,
      async (reader) => {
        const headers = await parseHeaders(reader);
        const issues: TableIssue[] = [];
        const debug = await runTable(reader, headers, parseDebugDirectory);
        issues.push(...debug.issues);
        let codeview: PeImage["codeview"] = null;
        for (const entry of debug.value) {
          if (entry.type !== 2 || entry.pointerToRawData === 0 || entry.sizeOfData < 24) continue;
          if (entry.pointerToRawData + Math.min(entry.sizeOfData, MAX_CODEVIEW) > reader.size) {
            issues.push({ table: "debug", reason: "CodeView data outside the file" });
            continue;
          }
          codeview = parseCodeView(
            await reader.readAt(entry.pointerToRawData, Math.min(entry.sizeOfData, MAX_CODEVIEW)),
          );
          if (codeview !== null) break;
        }
        const tls = await runTable(reader, headers, parseTlsCallbacks);
        issues.push(...tls.issues);
        return new PeFile(path, file, platform, headers, codeview, tls.value, issues);
      },
      signal,
    );
  }

  get issues(): readonly { readonly table: string; readonly reason: string }[] {
    return this.#issues;
  }

  #withReader<T>(fn: (reader: FileReader) => Promise<T>): Promise<T> {
    return withFile(this.path_display, this.platform, this.file, fn);
  }

  /** Parse a table once; its issues join `issues`. */
  #table<T>(key: string, parse: (view: ImageView) => Parsed<T>): Promise<T> {
    let pending = this.#lazy.get(key) as Promise<T> | undefined;
    if (pending === undefined) {
      pending = this.#withReader(async (reader) => {
        const parsed = await runTable(reader, this.headers, parse);
        this.#issues.push(...parsed.issues);
        return parsed.value;
      });
      // a failed read (file changed, io) is not cached: the next call retries
      pending.catch(() => this.#lazy.delete(key));
      this.#lazy.set(key, pending);
    }
    return pending;
  }

  exports(): Promise<readonly PeExport[]> {
    return this.#table("exports", parseExports);
  }

  imports(): Promise<readonly PeImport[]> {
    return this.#table("imports", parseImports);
  }

  functions(): Promise<FunctionTable> {
    return this.pdata();
  }

  /** The .pdata table with the reader-internal extras (primary fragment end). */
  pdata(): Promise<PdataTable> {
    return this.#table("pdata", parsePdata);
  }

  async relocations(): Promise<Uint32Array> {
    return (await this.#table("relocations", parseRelocations)).slots;
  }

  async relocationOtherTypes(): Promise<number> {
    return (await this.#table("relocations", parseRelocations)).other;
  }

  async cfgSlots(): Promise<readonly number[]> {
    return this.#table("cfg", parseCfgSlots);
  }

  /** S2 §17.2 step 13: bytes the Windows loader writes (VERIFIED classes, S2 lab E2). */
  async loaderWritten(): Promise<readonly LoaderRange[]> {
    const out: LoaderRange[] = [];
    for (const imp of await this.imports())
      out.push({ rva: imp.slot_rva, size: 8, class: imp.delay ? "delay-iat" : "iat" });
    const iatDir = this.headers.dirs[DIR.iat];
    if (iatDir !== undefined && iatDir.rva !== 0 && iatDir.size > 0)
      out.push({ rva: iatDir.rva, size: iatDir.size, class: "iat" });
    for (const s of this.sections)
      if (s.name === "fothk" || s.short_name === "fothk")
        out.push({ rva: s.rva, size: Math.max(s.virtual_size, s.raw_size), class: "loader-thunk" });
    for (const rva of await this.cfgSlots()) out.push({ rva, size: 8, class: "loader-cfg" });
    out.sort((a, b) => a.rva - b.rva);
    return out;
  }

  /** File bytes for [rva, rva+len): zero-fill where not file-backed (backed 0) and outside every section. */
  readRva(rva: number, len: number): Promise<{ readonly bytes: Buffer; readonly backed: Uint8Array }> {
    return this.#withReader((reader) => this.readRvaWith(reader, rva, len));
  }

  async readRvaWith(reader: FileReader, rva: number, len: number): Promise<{ bytes: Buffer; backed: Uint8Array }> {
    const bytes = Buffer.alloc(len);
    const backed = new Uint8Array(len);
    let i = 0;
    while (i < len) {
      const at = locateRva(this.headers, rva + i);
      if (at.kind === "outside") {
        i++;
        continue;
      }
      const run = Math.min(at.run, len - i);
      if (at.kind === "file") {
        (await reader.readAt(at.offset, run)).copy(bytes, i);
        backed.fill(1, i, i + run);
      }
      i += run;
    }
    return { bytes, backed };
  }

  /** S2 §17.3: file bytes + DIR64 base relocations for actualBase (full 8-byte slots even when they straddle). */
  async imageBytes(rva: number, len: number, actualBase: bigint): Promise<Buffer> {
    const relocations = await this.relocations();
    return this.#withReader(async (reader) => {
      const out = (await this.readRvaWith(reader, rva, len)).bytes;
      const delta = BigInt.asUintN(64, actualBase - this.headers.imageBase);
      if (delta === 0n) return out;
      for (let i = lowerBound(relocations, rva - 7); i < relocations.length; i++) {
        const slotRva = relocations[i] ?? 0;
        if (slotRva >= rva + len) break;
        if (slotRva >= rva && slotRva + 8 <= rva + len) {
          const j = slotRva - rva;
          out.writeBigUInt64LE(BigInt.asUintN(64, out.readBigUInt64LE(j) + delta), j);
          continue;
        }
        // a slot straddling the window: relocate the full 8-byte value, keep the bytes inside the window
        const slot = (await this.readRvaWith(reader, slotRva, 8)).bytes;
        slot.writeBigUInt64LE(BigInt.asUintN(64, slot.readBigUInt64LE(0) + delta));
        for (let k = 0; k < 8; k++) {
          const j = slotRva + k - rva;
          if (j >= 0 && j < len) out[j] = slot[k] ?? 0;
        }
      }
      return out;
    });
  }

  sectionOf(rva: number): PeSection | null {
    const index = sectionIndexOf(this.headers, rva);
    return index === -1 ? null : (this.sections[index] ?? null);
  }
}
