import { posix, win32 } from "node:path";

import { isDriveAbsolute, type HostPlatform } from "./paths.js";

/**
 * CT-I8: where tools may create files. A prompt injection in target output must not turn `dump_memory {format:"raw"}`
 * (target-chosen bytes) or any other writer into persistence or code execution. Every `out_path` of dump_memory,
 * export_coverage and export_evidence passes checkOutputPath; the default (no out_path) is <run dir>/exports/….
 * Callers then require that the path does not exist (writers never overwrite) and create parents only under
 * exportsDir. Refusal → access_denied {reason:"policy"} with the message below.
 */
export const REFUSED_OUTPUT_EXTENSIONS = [
  ".exe",
  ".dll",
  ".sys",
  ".drv",
  ".ocx",
  ".scr",
  ".com",
  ".pif",
  ".bat",
  ".cmd",
  ".ps1",
  ".psm1",
  ".psd1",
  ".vbs",
  ".vbe",
  ".js",
  ".jse",
  ".mjs",
  ".wsf",
  ".wsh",
  ".hta",
  ".lnk",
  ".url",
  ".msi",
  ".msp",
  ".mst",
  ".reg",
  ".cpl",
  ".inf",
  ".scf",
  ".jar",
  ".py",
  ".pyw",
  ".sh",
  ".appref-ms",
  ".library-ms",
  ".settingcontent-ms",
] as const;

export interface OutputPathPolicy {
  readonly platform: HostPlatform;
  /** BeaLayout.exportsDir(runId) */
  readonly exportsDir: string;
  /** config.json exports.allowed_roots (user-only; never a tool input) */
  readonly allowedRoots: readonly string[];
  /** refused even under an allowed root: %SystemRoot%, %windir% (win32); /etc, /usr, /bin, /sbin, /lib (POSIX) */
  readonly systemRoots: readonly string[];
}

export type OutputPathRefusal =
  | "not-absolute"
  | "traversal"
  | "alternate-stream"
  | "refused-extension"
  | "startup-folder"
  | "system-directory"
  | "outside-roots";

export type OutputPathCheck =
  | { readonly ok: true; readonly path: string }
  | { readonly ok: false; readonly reason: OutputPathRefusal; readonly message: string };

const refuse = (reason: OutputPathRefusal, message: string): OutputPathCheck => ({ ok: false, reason, message });

export const checkOutputPath = (requested: string, policy: OutputPathPolicy): OutputPathCheck => {
  const api = policy.platform === "win32" ? win32 : posix;
  if (!isDriveAbsolute(requested, policy.platform))
    return refuse("not-absolute", "out_path must be a drive-absolute local path.");
  if (requested.split(/[\\/]/u).includes("..")) return refuse("traversal", "out_path must not contain '..' segments.");
  if (policy.platform === "win32" && requested.indexOf(":", 2) !== -1)
    return refuse("alternate-stream", "out_path must not name an NTFS alternate data stream.");
  const normalized = api.normalize(requested);
  const fold = (value: string): string =>
    policy.platform === "win32" ? value.toLowerCase().replaceAll("/", "\\") : value;
  const key = fold(normalized);
  const extension = api.extname(key);
  if ((REFUSED_OUTPUT_EXTENSIONS as readonly string[]).includes(extension))
    return refuse("refused-extension", `out_path must not end in an executable or script extension (${extension}).`);
  if (key.includes(fold(`${api.sep}start menu${api.sep}programs${api.sep}startup`)))
    return refuse("startup-folder", "out_path must not be inside a Startup folder.");
  const under = (root: string): boolean => {
    const base = fold(api.normalize(root)).replace(/[\\/]+$/u, "");
    return key === base || key.startsWith(`${base}${policy.platform === "win32" ? "\\" : "/"}`);
  };
  if (policy.systemRoots.some(under))
    return refuse("system-directory", "out_path must not be inside a system directory.");
  if (under(policy.exportsDir) || policy.allowedRoots.some(under)) return { ok: true, path: normalized };
  return refuse(
    "outside-roots",
    "out_path must be under this run's exports directory or a root listed in BEA_HOME/config.json exports.allowed_roots (set by the user).",
  );
};
