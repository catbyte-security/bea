/**
 * Target-scoped anti-cheat signals (D-INT-1, CT-I11/CI-I12; pure). Any signal refuses spawn/attach by default with
 * access_denied{reason:"anti-cheat-detected"}; only the user can allow it (BEA_ALLOW_ANTI_CHEAT=1 /
 * attach.allow_anti_cheat, or the image sha256 in attach.allow_anti_cheat_images). Machine-wide anti-cheat processes
 * elsewhere never refuse: they become a bea_status note and the ANTI_CHEAT_GLOBAL_PRESENT limitation.
 *
 * Signal codes are BEA-authored: `<source>:<pattern label from the fixed lists below>`, never the target's own file
 * names, so they are safe in error details and evidence.
 *   (a) dir:<label>       components in the image's directory or its parent
 *   (b) import:<label>    anti-cheat DLLs imported by the image (on-disk PE import table, before spawn/attach)
 *       module:<label>    anti-cheat DLLs loaded in an attached process (checked right after injection, before any use)
 *   (c) ancestor:<label>  an anti-cheat client or launcher as the parent or grandparent (attach)
 */
interface Pattern {
  readonly label: string;
  readonly test: (lowerName: string) => boolean;
}

const exact = (name: string): Pattern => ({ label: name, test: (n) => n === name.toLowerCase() });
const prefixSuffix = (prefix: string, suffix: string, label: string): Pattern => ({
  label,
  test: (n) => n.startsWith(prefix.toLowerCase()) && n.endsWith(suffix.toLowerCase()),
});

/** (a): directory entries (folders and files) next to the image or one level up. */
const DIRECTORY_PATTERNS: readonly Pattern[] = [
  exact("EasyAntiCheat"),
  exact("EasyAntiCheat_EOS"),
  exact("BattlEye"),
  exact("EAAntiCheat"),
  exact("start_protected_game.exe"),
  prefixSuffix("BEService", ".exe", "BEService*.exe"),
];

/** (b): imported or loaded modules. */
const MODULE_PATTERNS: readonly Pattern[] = [
  exact("EasyAntiCheat_x64.dll"),
  prefixSuffix("EasyAntiCheat_EOS", ".dll", "EasyAntiCheat_EOS*.dll"),
  exact("BEClient_x64.dll"),
  prefixSuffix("EAAntiCheat", ".dll", "EAAntiCheat*.dll"),
  prefixSuffix("GameGuard", "", "GameGuard*"),
  prefixSuffix("npggNT", "", "npggNT*"),
  prefixSuffix("xhunter", "", "xhunter*"),
  prefixSuffix("mhyprot", "", "mhyprot*"),
];

/** (c): anti-cheat clients and launchers in the ancestry (attach). */
const ANCESTOR_PATTERNS: readonly Pattern[] = [
  prefixSuffix("EasyAntiCheat", ".exe", "EasyAntiCheat*.exe"),
  exact("start_protected_game.exe"),
  prefixSuffix("BEService", ".exe", "BEService*.exe"),
  prefixSuffix("EAAntiCheat", ".exe", "EAAntiCheat*.exe"),
  exact("vgc.exe"),
  prefixSuffix("FACEIT", ".exe", "FACEIT*.exe"),
];

/** Machine-wide services/clients whose presence is only a status note (never a refusal). */
const MACHINE_WIDE_PATTERNS: readonly Pattern[] = [
  exact("vgc.exe"),
  exact("vgtray.exe"),
  prefixSuffix("FACEIT", ".exe", "FACEIT*.exe"),
  prefixSuffix("EasyAntiCheat", ".exe", "EasyAntiCheat*.exe"),
  prefixSuffix("BEService", ".exe", "BEService*.exe"),
  prefixSuffix("EAAntiCheat", ".exe", "EAAntiCheat*.exe"),
  exact("PnkBstrA.exe"),
  exact("PnkBstrB.exe"),
];

const matchLabels = (names: readonly string[], patterns: readonly Pattern[]): string[] => {
  const labels = new Set<string>();
  for (const name of names) {
    const lower = basenameOf(name).toLowerCase();
    for (const pattern of patterns) if (pattern.test(lower)) labels.add(pattern.label);
  }
  return [...labels].sort();
};

export const basenameOf = (path: string): string => {
  const cut = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return cut < 0 ? path : path.slice(cut + 1);
};

/** (a) — `entries` are the names found in the image directory and its parent (the caller lists them). */
export const directorySignals = (entries: readonly string[]): string[] =>
  matchLabels(entries, DIRECTORY_PATTERNS).map((label) => `dir:${label}`);

/** (b) — imported DLL names from the image's PE import table (static and delay-load). */
export const importSignals = (importedDlls: readonly string[]): string[] =>
  matchLabels(importedDlls, MODULE_PATTERNS).map((label) => `import:${label}`);

/** (b) for attach — module names or paths loaded in the live process. */
export const moduleSignals = (moduleNames: readonly string[]): string[] =>
  matchLabels(moduleNames, MODULE_PATTERNS).map((label) => `module:${label}`);

export interface ProcessNode {
  readonly pid: number;
  readonly name: string;
  readonly ppid: number | null;
}

/** (c) — the parent and the grandparent of `pid` in a process listing. */
export const ancestrySignals = (pid: number, processes: readonly ProcessNode[]): string[] => {
  const byPid = new Map(processes.map((p) => [p.pid, p]));
  const ancestors: string[] = [];
  let current = byPid.get(pid);
  for (let depth = 0; depth < 2 && current?.ppid !== null && current?.ppid !== undefined; depth += 1) {
    const parent = byPid.get(current.ppid);
    if (parent === undefined || parent.pid === current.pid) break;
    ancestors.push(parent.name);
    current = parent;
  }
  return matchLabels(ancestors, ANCESTOR_PATTERNS).map((label) => `ancestor:${label}`);
};

/** Labels of machine-wide anti-cheat processes in a listing (status note + ANTI_CHEAT_GLOBAL_PRESENT). */
export const machineWideAntiCheat = (processNames: readonly string[]): string[] =>
  matchLabels(processNames, MACHINE_WIDE_PATTERNS);

export type AntiCheatVerdict =
  | { readonly kind: "clean" }
  | { readonly kind: "refuse"; readonly signals: readonly string[] }
  | { readonly kind: "allowed"; readonly signals: readonly string[]; readonly by: "global" | "image" };

/** The user's overrides decide a signalled target; `imageSha256` is needed only when signals exist. */
export const antiCheatVerdict = (input: {
  readonly signals: readonly string[];
  readonly allowGlobal: boolean;
  readonly allowedImages: readonly string[];
  readonly imageSha256: string | null;
}): AntiCheatVerdict => {
  if (input.signals.length === 0) return { kind: "clean" };
  if (input.allowGlobal) return { kind: "allowed", signals: input.signals, by: "global" };
  const sha = input.imageSha256?.toLowerCase() ?? null;
  if (sha !== null && input.allowedImages.some((allowed) => allowed.toLowerCase() === sha))
    return { kind: "allowed", signals: input.signals, by: "image" };
  return { kind: "refuse", signals: input.signals };
};

export const machineWideNote = (labels: readonly string[]): string =>
  `A machine-wide anti-cheat service is running (${labels.slice(0, 4).join(", ")}); BEA refuses only targets that show anti-cheat signals themselves.`;
