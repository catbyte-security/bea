import { join } from "node:path";

import type { BeaCore } from "../../application/BeaApplication.js";
import type { FileHashCache, PeImageCache } from "../../ports/pe.js";
import { PersistentFileHashCache } from "./FileHashCache.js";
import { LruPeImageCache } from "./PeImageCache.js";

/**
 * WP-ADDR: the on-disk PE reader cache and the persistent file hash cache (S2 §17.5–17.6). Construction is
 * synchronous and touches nothing on disk (CI-M20): the hash cache loads BEA_HOME/cache/file-sha256.jsonl lazily
 * on its first use and creates the cache directory only when it first appends.
 */
export const createPeServices = (core: BeaCore): { readonly images: PeImageCache; readonly hashes: FileHashCache } => {
  const { platform, layout } = core.config;
  return {
    images: new LruPeImageCache(platform),
    hashes: new PersistentFileHashCache(join(layout.cacheDir, "file-sha256.jsonl"), platform),
  };
};
