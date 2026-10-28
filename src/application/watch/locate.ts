// =================================================================================================
// src/application/watch/locate.ts — .pdata function attribution of code addresses for watch writers, trace
// summaries and coverage exports (S6 §5.3 `func`/`sym`; WP9-WATCH). Reads each module's image from disk through
// PeImageCache (WP-ADDR), so it works after the session closed. `func` is the function start in module+0xRVA form;
// `sym` names an export at exactly that start (BEA never fabricates names, S2 §16.4).
// =================================================================================================
import { staticText } from "../../domain/address/grammar.js";
import { formatHex } from "../../domain/hex.js";
import type { FunctionTable, PeImageCache } from "../../ports/pe.js";
import { locate, type LegendEntry } from "./decoders.js";

export interface FunctionRef {
  readonly func: string;
  readonly sym: string | null;
}

interface ImageFacts {
  readonly functions: FunctionTable;
  readonly exports: ReadonlyMap<number, string>;
  /** the image's preferred ImageBase (review fix UX-10: the pasteable static VA) */
  readonly preferredBase: bigint;
}

export class CodeLocator {
  readonly #images = new Map<string, Promise<ImageFacts | null>>();
  constructor(
    private readonly pe: PeImageCache,
    private readonly signal?: AbortSignal,
  ) {}

  #facts(path: string): Promise<ImageFacts | null> {
    let known = this.#images.get(path);
    if (known === undefined) {
      known = (async () => {
        const opened = await this.pe.open(path, this.signal);
        if (!opened.ok) return null;
        try {
          const functions = await opened.value.functions();
          const exports = new Map<number, string>();
          for (const e of await opened.value.exports())
            if (e.rva !== null && e.name !== null && !exports.has(e.rva)) exports.set(e.rva, e.name);
          return { functions, exports, preferredBase: BigInt(opened.value.image_base) };
        } catch {
          return null;
        }
      })();
      this.#images.set(path, known);
    }
    return known;
  }

  /**
   * Review fix UX-10: the static (preferred-base) text of a module address, "module:0x<preferred base + rva>" as
   * map_address and scan_results give it; null outside a module or without its image on disk.
   */
  async staticOf(legend: readonly LegendEntry[], va: bigint): Promise<string | null> {
    const m = locate(legend, va);
    const path = m?.entry[3] ?? null;
    if (m === null || path === null) return null;
    const facts = await this.#facts(path);
    return facts === null ? null : staticText(m.name, facts.preferredBase + m.rva);
  }

  /** The .pdata function containing `va`, or null (no module, no image path, no unwind entry). */
  async functionOf(legend: readonly LegendEntry[], va: bigint): Promise<FunctionRef | null> {
    const m = locate(legend, va);
    const path = m?.entry[3] ?? null;
    if (m === null || path === null || m.rva > 0xffff_ffffn) return null;
    const facts = await this.#facts(path);
    const hit = facts?.functions.lookup(Number(m.rva)) ?? null;
    if (facts === null || hit === null) return null;
    return {
      func: `${m.name}+${formatHex(hit.primary_begin)}`,
      sym: facts.exports.get(hit.primary_begin) ?? null,
    };
  }
}
