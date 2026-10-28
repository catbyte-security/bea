import type { BeaError } from "../../domain/errors/beaError.js";
import type { HostPlatform } from "../../domain/paths.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { PeImageCache } from "../../ports/pe.js";
import { fileError, PeFailure, peErrorToBea } from "./errors.js";
import { fileKeyString, statFileKey } from "./fileAccess.js";
import { PeFile } from "./PeFile.js";

/**
 * LRU of parsed images keyed by FileKey (S2 §17.5): stat on every open, re-parse when the key changed (rewrite,
 * rename-replace, restored mtime with a new ctime). Parsed tables are cached, never file handles or file bytes.
 */
const DEFAULT_MAX_IMAGES = 64;

export class LruPeImageCache implements PeImageCache {
  readonly #entries = new Map<string, Promise<PeFile>>();

  constructor(
    private readonly platform: HostPlatform,
    private readonly maxImages = DEFAULT_MAX_IMAGES,
  ) {}

  async open(path: string, signal?: AbortSignal): Promise<Result<PeFile, BeaError>> {
    try {
      const key = await statFileKey(path, this.platform);
      const id = fileKeyString(key);
      let pending = this.#entries.get(id);
      if (pending === undefined) {
        pending = PeFile.open(path, key, this.platform, signal);
        this.#entries.set(id, pending);
        pending.catch(() => this.#entries.delete(id));
        while (this.#entries.size > this.maxImages) {
          const oldest = this.#entries.keys().next().value;
          if (oldest === undefined) break;
          this.#entries.delete(oldest);
        }
      } else {
        // LRU touch
        this.#entries.delete(id);
        this.#entries.set(id, pending);
      }
      return ok(await pending);
    } catch (thrown) {
      return err(toBeaError("pe.open", path, thrown));
    }
  }

  /** Drop every cached image (tests; a long-lived server never needs it). */
  clear(): void {
    this.#entries.clear();
  }
}

/** Any failure of the reader as a BeaError (PeFailure → S2 §16.2 mapping; anything else is an io read failure). */
export const toBeaError = (operation: string, path: string, thrown: unknown): BeaError =>
  thrown instanceof PeFailure ? peErrorToBea(operation, path, thrown) : fileError(operation, path, thrown);
