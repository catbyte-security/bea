// Handle cache of the API profile engine (S4 §10.6): handle value (canonical hex) → {kind, name}. Inserted on
// successful opens, evicted by NtClose/closesocket; bounded, dropping the oldest 25% on overflow (Map keeps
// insertion order). Pure; shared by every listener of one profile instrument.
import type { Hex } from "../../shared/hex.js";
import type { HandleEntry } from "./profileTypes.js";

export class HandleCache {
  private readonly map = new Map<Hex, HandleEntry>();
  /** entries dropped by the overflow policy (diagnostic only) */
  evicted = 0;

  constructor(private readonly capacity: number) {}

  get size(): number {
    return this.map.size;
  }

  get(handle: Hex): HandleEntry | undefined {
    return this.map.get(handle);
  }

  /** Insert or replace (a reused handle value names a new object). */
  set(handle: Hex, entry: HandleEntry): void {
    if (handle === "0x0" || handle === "0xffffffffffffffff") return;
    this.map.delete(handle);
    this.map.set(handle, entry);
    if (this.map.size > this.capacity) {
      const drop = Math.max(1, Math.floor(this.capacity / 4));
      let n = 0;
      for (const key of this.map.keys()) {
        if (n++ >= drop) break;
        this.map.delete(key);
        this.evicted++;
      }
    }
  }

  delete(handle: Hex): boolean {
    return this.map.delete(handle);
  }

  clear(): void {
    this.map.clear();
  }
}
