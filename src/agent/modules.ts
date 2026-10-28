// =================================================================================================
// src/agent/modules.ts — WP3-AGENT ModuleIndex (S4 §8.1). One ModuleMap snapshot serves every hot path (find() does
// not take the loader lock, A-16); the module observer (attached at boot, onAdded fires synchronously for existing
// modules) only emits a cheap `module/1` row and bumps the epoch on the loading thread; the map rebuild and the
// listeners (WP8 lazy profile installs, instrument unload stops) run later on the JS thread. Never an
// Interceptor.attach inside the loader callback. Per-module caches: exports sorted by VA (export_hint), .pdata, PE
// facts from memory (pure/corePe.ts). DebugSymbol is never used for names [ext-frida §3.12].
// =================================================================================================
import type { Hex, ModuleInfo, ModuleRow, PeFacts } from "../shared/agentProtocol.js";
import { big, hex } from "./encode.js";
import {
  dataDir,
  DATA_DIR,
  parseCodeView,
  parseHeaders,
  parsePdata,
  parseSections,
  parseTlsCallbacks,
  type PdataTable,
  type PeHeaders,
  type RvaReader,
  type SectionHeader,
} from "./pure/corePe.js";
import { hexOfBigint, hexOfNumber } from "./pure/coreHex.js";
import { findPdataIndex, lastIndexAtOrBelow } from "./pure/coreRanges.js";
import type { AgentCore } from "./state.js";

export interface ModuleChange {
  readonly ev: "L" | "U";
  readonly module: Module;
  readonly epoch: number;
}

export interface ExportEntry {
  readonly name: string;
  readonly kind: "function" | "variable";
  readonly va: bigint;
}

interface ModuleCache {
  exports?: ExportEntry[];
  exportVas?: bigint[];
  headers?: PeHeaders | null;
  pdata?: PdataTable;
  sections?: SectionHeader[];
  pe?: PeFacts | null;
}

export class ModuleIndex {
  readonly #core: AgentCore;
  #map: ModuleMap | null = null;
  #dirty = true;
  #epoch = 0;
  readonly #pending: ModuleChange[] = [];
  #drainScheduled = false;
  readonly #listeners = new Set<(changes: readonly ModuleChange[]) => void>();
  readonly #caches = new Map<string, ModuleCache>();
  #observer: ModuleObserver | null = null;

  constructor(core: AgentCore) {
    this.#core = core;
  }

  get epoch(): number {
    return this.#epoch;
  }

  /** Attach the module observer (boot step 5); onAdded fires for every loaded module right away. */
  start(): void {
    if (this.#observer !== null) return;
    this.#observer = Process.attachModuleObserver({
      onAdded: (m) => this.#onChange("L", m),
      onRemoved: (m) => this.#onChange("U", m),
    });
    this.#core.early.module_observer = true;
  }

  dispose(): void {
    try {
      this.#observer?.detach();
    } catch {
      // unloading anyway
    }
    this.#observer = null;
  }

  /** The current ModuleMap (rebuilt on demand after loads/unloads; never on the loader thread). */
  get map(): ModuleMap {
    if (this.#map === null || (this.#dirty && Process.getCurrentThreadId() === this.#core.jsTid)) this.#rebuild();
    return this.#map!;
  }

  find(address: NativePointer): Module | null {
    return this.map.find(address);
  }

  byName(name: string): Module | null {
    return Process.findModuleByName(name);
  }

  /** Every loaded module (cloaked ones such as frida-agent are absent). */
  list(): Module[] {
    return Process.enumerateModules();
  }

  /** Subscribe to batched load/unload changes (run on the JS thread after the map rebuild). */
  onChange(listener: (changes: readonly ModuleChange[]) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  info(m: Module, withPe: boolean): ModuleInfo {
    return { name: m.name, path: m.path, base: hex(m.base), size: m.size, pe: withPe ? this.pe(m) : null };
  }

  /** "<module>+0x<rva>" inside a module (at capture time), else the bare VA (FrameRef). */
  frameRef(address: NativePointer): string {
    const m = this.map.find(address);
    return m === null ? hex(address) : `${m.name}+0x${address.sub(m.base).toString(16).replace(/^0x/u, "")}`;
  }

  /** {va, module, rva} of an address (crash backtraces). */
  locate(address: NativePointer): { va: Hex; module: string | null; rva: Hex | null } {
    const m = this.map.find(address);
    return { va: hex(address), module: m?.name ?? null, rva: m === null ? null : hex(address.sub(m.base)) };
  }

  /** Bounded reader over a module's mapped image (RVA → bytes; null when unreadable). */
  reader(m: Module): RvaReader {
    return (rva, len) => {
      if (rva < 0 || len <= 0 || rva + len > m.size) return null;
      try {
        const ab = m.base.add(rva).readByteArray(len);
        return ab === null ? null : new Uint8Array(ab);
      } catch {
        return null;
      }
    };
  }

  headers(m: Module): PeHeaders | null {
    const cache = this.#cache(m);
    if (cache.headers === undefined) {
      const parsed = parseHeaders(this.reader(m));
      cache.headers = parsed.ok ? parsed.headers : null;
    }
    return cache.headers;
  }

  sections(m: Module): SectionHeader[] {
    const cache = this.#cache(m);
    const h = this.headers(m);
    cache.sections ??= h === null ? [] : parseSections(this.reader(m), h);
    return cache.sections;
  }

  pdata(m: Module): PdataTable {
    const cache = this.#cache(m);
    const h = this.headers(m);
    cache.pdata ??=
      h === null
        ? { begins: new Uint32Array(0), ends: new Uint32Array(0), unwinds: new Uint32Array(0) }
        : parsePdata(this.reader(m), h);
    return cache.pdata;
  }

  /** The .pdata entry containing `address` (exact function fragment), or null. */
  functionRange(
    address: NativePointer,
  ): { base: NativePointer; size: number; unwindRva: number; module: Module } | null {
    const m = this.map.find(address);
    if (m === null) return null;
    const table = this.pdata(m);
    const rva = address.sub(m.base).toUInt32();
    const i = findPdataIndex(table.begins, table.ends, rva);
    if (i < 0) return null;
    const begin = table.begins[i]!;
    return { base: m.base.add(begin), size: table.ends[i]! - begin, unwindRva: table.unwinds[i]!, module: m };
  }

  /** In-memory PE facts (ImageBase = the actual base: the loader rewrites it). */
  pe(m: Module): PeFacts | null {
    const cache = this.#cache(m);
    if (cache.pe !== undefined) return cache.pe;
    const h = this.headers(m);
    if (h === null) return (cache.pe = null);
    const read = this.reader(m);
    const cv = parseCodeView(read, h);
    const pdataDir = dataDir(h, DATA_DIR.exception);
    cache.pe = {
      machine: h.machine,
      time_date_stamp: h.timeDateStamp,
      size_of_image: h.sizeOfImage,
      checksum: h.checksum,
      entry_rva: hexOfNumber(h.entryRva),
      subsystem: h.subsystem,
      dll_characteristics: h.dllCharacteristics,
      mapped_image_base: hexOfBigint(h.imageBase),
      section_count: h.numberOfSections,
      codeview: cv,
      tls_callbacks: parseTlsCallbacks(read, h, big(m.base)).map(hexOfBigint),
      pdata_entries: pdataDir === null ? 0 : Math.floor(pdataDir.size / 12),
    };
    return cache.pe;
  }

  /** Exports sorted by VA (cached per module load). */
  exports(m: Module): ExportEntry[] {
    const cache = this.#cache(m);
    if (cache.exports === undefined) {
      let list: ModuleExportDetails[] = [];
      try {
        list = m.enumerateExports();
      } catch (e) {
        this.#core.fault("enumerate-exports", e);
      }
      cache.exports = list
        .map((e) => ({
          name: e.name,
          kind: e.type === "variable" ? ("variable" as const) : ("function" as const),
          va: big(e.address),
        }))
        .sort((a, b) => (a.va < b.va ? -1 : a.va > b.va ? 1 : a.name < b.name ? -1 : 1));
      cache.exportVas = cache.exports.map((e) => e.va);
    }
    return cache.exports;
  }

  /** Exact export name at a VA, if any. */
  exportAt(m: Module, va: bigint): string | null {
    const list = this.exports(m);
    const i = lastIndexAtOrBelow(this.#cache(m).exportVas ?? [], va);
    return i >= 0 && list[i]!.va === va ? list[i]!.name : null;
  }

  /** Nearest preceding function export (a HINT only, S4 §8.5). */
  exportHint(m: Module, va: bigint): { name: string; va: Hex; distance: number } | null {
    const list = this.exports(m);
    const vas = this.#cache(m).exportVas ?? [];
    for (let i = lastIndexAtOrBelow(vas, va); i >= 0; i--) {
      const e = list[i]!;
      if (e.kind === "function") return { name: e.name, va: hexOfBigint(e.va), distance: Number(va - e.va) };
    }
    return null;
  }

  #cache(m: Module): ModuleCache {
    const key = `${m.base.toString()}/${m.size}/${m.path}`;
    let c = this.#caches.get(key);
    if (c === undefined) {
      c = {};
      this.#caches.set(key, c);
    }
    return c;
  }

  #rebuild(): void {
    this.#map = new ModuleMap();
    this.#dirty = false;
  }

  /** Loader thread: one row + epoch bump; everything else is deferred to the JS thread. */
  #onChange(ev: "L" | "U", m: Module): void {
    try {
      const c = this.#core;
      const epoch = ++this.#epoch;
      this.#dirty = true;
      const stream = c.systemStreams.modules;
      if (stream !== null) {
        const row: ModuleRow = [c.native.nextG(), c.native.nowUs(), ev, m.name, m.path, hex(m.base), m.size, epoch];
        c.streams.emit(stream, row);
      }
      if (ev === "U") this.#caches.delete(`${m.base.toString()}/${m.size}/${m.path}`);
      this.#pending.push({ ev, module: m, epoch });
      if (!this.#drainScheduled) {
        this.#drainScheduled = true;
        setImmediate(() => this.#drain());
      }
    } catch (e) {
      this.#core.fault("module-observer", e);
    }
  }

  #drain(): void {
    this.#drainScheduled = false;
    const changes = this.#pending.splice(0);
    this.#rebuild();
    for (const listener of this.#listeners) {
      try {
        listener(changes);
      } catch (e) {
        this.#core.fault("module-listener", e);
      }
    }
  }
}
