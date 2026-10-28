import { posix, win32 } from "node:path";

import type { ModuleToken } from "../../domain/address/grammar.js";
import type { MmId, PiId } from "../../domain/ids.js";
import type { HostPlatform } from "../../domain/paths.js";
import { pathDigest, pathKey, type ModuleMap } from "../../domain/process/instance.js";
import type { EmuModuleView } from "../../ports/emu.js";

/**
 * One address space's module table in a uniform shape (live module map, emulated images, or one PE file) and
 * S2 §16.3 step 1 module selection. Pure over the table; the I/O that builds tables is in AddressService.
 */
export interface SpaceModule {
  /** display basename (loader casing); untrusted text */
  readonly name: string;
  readonly path: string | null;
  readonly base: bigint;
  readonly size: number;
  readonly primary: boolean;
  /** known digest (emulation) — undefined: compute from the file */
  readonly sha256?: string | null;
  /** known preferred base (emulation) — null: read it from the file */
  readonly preferredBase: bigint | null;
}

export interface SpaceView {
  readonly kind: "live" | "emulation" | "file";
  /** sorted by base */
  readonly modules: readonly SpaceModule[];
  readonly moduleMapId: MmId | null;
  readonly instanceId: PiId | null;
  readonly epoch: number | null;
  /** file space: the caller supplied runtime_base (otherwise the PE preferred base stands in) */
  readonly runtimeBaseGiven: boolean;
}

export const keyPlatform = (platform: HostPlatform): "win32" | "linux" => (platform === "win32" ? "win32" : "linux");

const pathApi = (platform: HostPlatform) => (platform === "win32" ? win32 : posix);

const baseName = (path: string, platform: HostPlatform): string => pathApi(platform).basename(path);

const sortModules = <M extends { readonly base: bigint }>(modules: M[]): M[] =>
  modules.sort((a, b) => (a.base < b.base ? -1 : a.base > b.base ? 1 : 0));

/** Live: the host module map (S2 §5); main = the entry whose path digest equals the identity's image path. */
export const liveModules = (map: ModuleMap, mainPath: string, platform: HostPlatform): SpaceModule[] => {
  const mainDigest = pathDigest(mainPath, keyPlatform(platform));
  return sortModules(
    map.modules.map((m) => {
      const path = m.display.path;
      return {
        name: m.display.name ?? (path === null ? "?" : baseName(path, platform)),
        path,
        base: BigInt(m.base),
        size: m.size,
        primary: m.path_sha256 === mainDigest,
        preferredBase: null,
      };
    }),
  );
};

/** Live without a tracked map: an agent listModules snapshot. */
export const agentModules = (
  modules: readonly { readonly name: string; readonly path: string; readonly base: string; readonly size: number }[],
  mainPath: string,
  platform: HostPlatform,
): SpaceModule[] => {
  const mainKey = pathKey(mainPath, keyPlatform(platform));
  return sortModules(
    modules.map((m) => ({
      name: m.name,
      path: m.path,
      base: BigInt(m.base),
      size: m.size,
      primary: pathKey(m.path, keyPlatform(platform)) === mainKey,
      preferredBase: null,
    })),
  );
};

/** Emulation: the session's mapped images (EmuPort.modules, CI-B5); `$main` = the opened image. */
export const emulationModules = (modules: readonly EmuModuleView[]): SpaceModule[] =>
  sortModules(
    modules.map((m) => ({
      name: m.name,
      path: m.path,
      base: BigInt(m.base),
      size: m.size,
      primary: m.primary,
      sha256: m.sha256,
      preferredBase: m.preferredBase === null ? null : BigInt(m.preferredBase),
    })),
  );

export const moduleAtVa = (modules: readonly SpaceModule[], va: bigint): SpaceModule | null => {
  let lo = 0;
  let hi = modules.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const m = modules[mid];
    if (m === undefined) return null;
    if (va < m.base) hi = mid - 1;
    else if (va >= m.base + BigInt(m.size)) lo = mid + 1;
    else return m;
  }
  return null;
};

/** Another module of the space shares the basename (texts then carry `@0x<base>`). */
export const isAmbiguous = (modules: readonly SpaceModule[], module: SpaceModule): boolean => {
  const lower = module.name.toLowerCase();
  return modules.some((m) => m !== module && m.name.toLowerCase() === lower);
};

export type ModuleSelection =
  | { readonly kind: "found"; readonly module: SpaceModule }
  | { readonly kind: "not_loaded"; readonly suggestions: readonly string[] }
  | {
      readonly kind: "ambiguous";
      readonly candidates: readonly { readonly name: string; readonly path: string | null; readonly base: bigint }[];
    };

const sameName = (m: SpaceModule, wanted: string, platform: HostPlatform): boolean => {
  if (platform !== "win32") return m.name === wanted || (m.path !== null && baseName(m.path, platform) === wanted);
  const lower = wanted.toLowerCase();
  return m.name.toLowerCase() === lower || (m.path !== null && baseName(m.path, platform).toLowerCase() === lower);
};

/** S2 §16.3 step 1. */
export const selectModule = (
  modules: readonly SpaceModule[],
  token: ModuleToken,
  platform: HostPlatform,
): ModuleSelection => {
  const pick = (matches: readonly SpaceModule[], base: bigint | null): ModuleSelection | null => {
    const filtered = base === null ? matches : matches.filter((m) => m.base === base);
    if (filtered.length === 1 && filtered[0] !== undefined) return { kind: "found", module: filtered[0] };
    if (filtered.length > 1)
      return {
        kind: "ambiguous",
        candidates: filtered.slice(0, 16).map((m) => ({ name: m.name, path: m.path, base: m.base })),
      };
    return null;
  };
  if (token.kind === "main") {
    const main = modules.filter((m) => m.primary);
    return pick(main, null) ?? { kind: "not_loaded", suggestions: [] };
  }
  if (token.kind === "path") {
    const wanted = pathKey(token.path, keyPlatform(platform));
    const hit = pick(
      modules.filter((m) => m.path !== null && pathKey(m.path, keyPlatform(platform)) === wanted),
      token.base,
    );
    return hit ?? { kind: "not_loaded", suggestions: suggest(modules, baseName(token.path, platform)) };
  }
  const direct = pick(
    modules.filter((m) => sameName(m, token.name, platform)),
    token.base,
  );
  if (direct !== null) return direct;
  if (!token.name.includes(".")) {
    for (const extension of [".dll", ".exe"]) {
      const hit = pick(
        modules.filter((m) => sameName(m, `${token.name}${extension}`, platform)),
        token.base,
      );
      if (hit !== null) return hit;
    }
  }
  return { kind: "not_loaded", suggestions: suggest(modules, token.name) };
};

/** Bounded edit distance (≤ limit + 1). */
const editDistance = (a: string, b: string, limit = 8): number => {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const value = Math.min((prev[j] ?? 0) + 1, (cur[j - 1] ?? 0) + 1, (prev[j - 1] ?? 0) + cost);
      cur.push(value);
      best = Math.min(best, value);
    }
    if (best > limit) return limit + 1;
    prev = cur;
  }
  return prev[b.length] ?? limit + 1;
};

/** Up to `max` names close to `wanted` (substring either way, else small edit distance), case-insensitive. */
export const similarNames = (
  names: Iterable<string>,
  wanted: string,
  max = 5,
  normalize: (name: string) => string = (name) => name,
): string[] => {
  const lower = normalize(wanted).toLowerCase();
  const scored: { name: string; score: number }[] = [];
  const seen = new Set<string>();
  for (const name of names) {
    if (seen.has(name)) continue;
    seen.add(name);
    const candidate = normalize(name).toLowerCase();
    const score =
      candidate === lower
        ? 0
        : candidate.includes(lower) || lower.includes(candidate)
          ? 1
          : 1 + editDistance(candidate, lower, 3);
    if (score <= 4) scored.push({ name, score });
  }
  scored.sort((a, b) => a.score - b.score || a.name.localeCompare(b.name));
  return scored.slice(0, max).map((s) => s.name);
};

const withoutExtension = (name: string): string => name.replace(/\.(dll|exe|sys|drv|ocx|cpl)$/iu, "");

const suggest = (modules: readonly SpaceModule[], wanted: string): string[] =>
  similarNames(
    modules.map((m) => m.name),
    wanted,
    5,
    withoutExtension,
  );
