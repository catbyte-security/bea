import type { CallerSymbol } from "../../domain/address/symbolize.js";

/**
 * Caller symbol tables (S2 §19.3): Ghidra/REA/analyst names registered through `map_address.symbols`, kept in
 * memory per image digest for the run (so they apply to every instance of that binary). A later registration
 * overrides an earlier entry at the same rva; each name carries its bea.symbols.caller evidence id.
 */
export class CallerSymbolStore {
  readonly #tables = new Map<string, CallerSymbol[]>();

  /** Merge entries into the image's table; returns the table size after the merge. */
  register(imageSha256: string, entries: readonly CallerSymbol[]): number {
    const byRva = new Map<number, CallerSymbol>();
    for (const entry of this.#tables.get(imageSha256) ?? []) byRva.set(entry.rva, entry);
    for (const entry of entries) byRva.set(entry.rva, entry);
    const table = [...byRva.values()].sort((a, b) => a.rva - b.rva);
    this.#tables.set(imageSha256, table);
    return table.length;
  }

  /** Sorted by rva; empty when nothing was registered (or the digest is unknown). */
  table(imageSha256: string | null | undefined): readonly CallerSymbol[] {
    return imageSha256 === null || imageSha256 === undefined ? [] : (this.#tables.get(imageSha256) ?? []);
  }
}
