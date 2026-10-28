import { basenameOf } from "./antiCheatSignals.js";

/**
 * spawn_process program policy (D-INT-42, CT-I8; pure). spawn_process runs any x64 program with any arguments, so a
 * prompt-injected spawn of a program that takes a command (a shell, a script interpreter, conhost, a LOLBin) or of a
 * system tool (taskkill) is arbitrary command execution. Refusal is best-effort defence in depth; the real boundary
 * is the user's choice to expose spawn_process. Review fix SEC-1: the old 30-name basename denylist missed conhost,
 * python3.exe aliases and taskkill, so three rules now apply (any one refuses):
 *   1. name      the basename (or its stem) is an interpreter, shell, LOLBin or system tool, or a python/pip variant;
 *   2. location  the image (as given, or its final path with junctions, symlinks and 8.3 names resolved) lies under
 *                %SystemRoot%, the WindowsApps execution aliases, or an interpreter/toolchain install root;
 *   3. version   the PE VERSIONINFO OriginalFilename/InternalName names such a program (renamed or hard-linked copies).
 * Only the USER lifts the refusal: config spawn.allow_interpreters (everything) or spawn.allowed_programs (listed
 * drive-absolute paths or image sha256 digests). BEA's own internal probes (the doctor inject probe) bypass it: they
 * never take model input.
 */
const REFUSED_STEMS: ReadonlySet<string> = new Set([
  // shells, consoles and terminals that run a command line
  "cmd",
  "powershell",
  "powershell_ise",
  "pwsh",
  "conhost",
  "openconsole",
  "wt",
  "windowsterminal",
  "explorer",
  "bash",
  "sh",
  "zsh",
  "dash",
  "ksh",
  "fish",
  "wsl",
  "wslhost",
  "git",
  "git-bash",
  "git-cmd",
  // script interpreters and runtimes
  "wscript",
  "cscript",
  "mshta",
  "node",
  "deno",
  "bun",
  "perl",
  "ruby",
  "php",
  "java",
  "javaw",
  "lua",
  "tclsh",
  "wish",
  "dotnet",
  "csi",
  // build tools and debuggers that execute commands
  "msbuild",
  "make",
  "mingw32-make",
  "nmake",
  "cmake",
  "gdb",
  "lldb",
  "cdb",
  "ntsd",
  "windbg",
  "vbc",
  "csc",
  "jsc",
  // LOLBins and proxies
  "rundll32",
  "regsvr32",
  "msiexec",
  "wmic",
  "certutil",
  "bitsadmin",
  "installutil",
  "regasm",
  "regsvcs",
  "forfiles",
  "schtasks",
  "at",
  "sc",
  "reg",
  "cmstp",
  "odbcconf",
  "mavinject",
  "hh",
  "pcalua",
  "msdt",
  "syncappvpublishingserver",
  "runas",
  "wsmprovhost",
  "winrs",
  "esentutl",
  // process killers and network transfer
  "taskkill",
  "tskill",
  "ssh",
  "scp",
  "sftp",
  "ftp",
  "tftp",
  "curl",
  "wget",
  "tar",
]);

/** python, python3, python3.14-64, pythonw3, py, pyw, pip3.14 … (stems, lower case). */
const REFUSED_STEM_PATTERNS: readonly RegExp[] = [
  /^pythonw?[\d.]*(?:-(?:32|64|arm64))?w?$/u,
  /^pyw?[\d.]*(?:-(?:32|64|arm64))?$/u,
  /^pip[\d.]*$/u,
];

/** Lower case, without a trailing ".mui" (Windows version resources) and ".exe". */
const stemOf = (name: string): string => {
  let lower = name.trim().toLowerCase();
  if (lower.endsWith(".mui")) lower = lower.slice(0, -4);
  return lower.endsWith(".exe") ? lower.slice(0, -4) : lower;
};

const refusedStem = (name: string): boolean => {
  const stem = stemOf(name);
  return stem.length > 0 && (REFUSED_STEMS.has(stem) || REFUSED_STEM_PATTERNS.some((re) => re.test(stem)));
};

/** Rule 1 (name) on the basename alone (pure, case-insensitive). */
export const isInterpreterOrLolbin = (program: string): boolean => refusedStem(basenameOf(program));

const BACKSLASH = "\\";
/** Case-folded, backslash-only, with a trailing backslash (a prefix never matches a sibling such as "C:\Windows2"). */
const folder = (path: string): string => {
  const lower = path.replaceAll("/", BACKSLASH).toLowerCase();
  return lower.endsWith(BACKSLASH) ? lower : `${lower}${BACKSLASH}`;
};

export interface RefusedLocation {
  /** BEA-authored label (never the caller's path) */
  readonly label: string;
  readonly test: (folded: string) => boolean;
}

const lookup = (env: Readonly<Record<string, string | undefined>>, key: string): string | null => {
  const direct = env[key] ?? Object.entries(env).find(([k]) => k.toLowerCase() === key.toLowerCase())?.[1];
  return direct !== undefined && isDriveAbsoluteWin32(direct) ? direct : null;
};

/** Paths whose folded form starts with `<root>\<name>` where `name` matches `child` (one directory level). */
const childLocation = (label: string, root: string, child: RegExp): RefusedLocation => {
  const prefix = folder(root);
  return {
    label,
    test: (p) => {
      if (!p.startsWith(prefix)) return false;
      const rest = p.slice(prefix.length);
      const end = rest.indexOf(BACKSLASH);
      return end > 0 && child.test(rest.slice(0, end));
    },
  };
};

const MSYS_BIN = /^[a-z]:\\msys(?:64|32|2)?\\(?:usr|mingw64|mingw32|ucrt64|clang64|clang32|clangarm64)\\bin\\/u;
const CYGWIN_BIN = /^[a-z]:\\cygwin(?:64)?\\bin\\/u;
const ROOT_PYTHON = /^[a-z]:\\python[^\\]*\\/u;

/** Rule 2 roots from the server environment (pure). */
export const refusedLocations = (env: Readonly<Record<string, string | undefined>>): readonly RefusedLocation[] => {
  const out: RefusedLocation[] = [];
  const under = (label: string, root: string | null): void => {
    if (root === null) return;
    const prefix = folder(root);
    out.push({ label, test: (p) => p.startsWith(prefix) });
  };
  under("system-root", lookup(env, "SystemRoot") ?? lookup(env, "windir") ?? "C:\\Windows");
  const local = lookup(env, "LOCALAPPDATA");
  if (local !== null) {
    under("windowsapps-alias", `${local}\\Microsoft\\WindowsApps`);
    under("python-install", `${local}\\Python`);
    under("python-install", `${local}\\Programs\\Python`);
  }
  const programFiles = new Set(
    ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
      .map((key) => lookup(env, key))
      .filter((v): v is string => v !== null)
      .map((v) => folder(v)),
  );
  for (const root of programFiles) {
    out.push(childLocation("python-install", root, /^python/u));
    under("git-install", `${root}git`);
    under("node-install", `${root}nodejs`);
    under("dotnet-install", `${root}dotnet`);
    under("powershell-install", `${root}powershell`);
  }
  out.push(
    { label: "python-install", test: (p) => ROOT_PYTHON.test(p) },
    { label: "posix-toolchain", test: (p) => MSYS_BIN.test(p) || CYGWIN_BIN.test(p) },
  );
  return out;
};

export type ProgramRefusal =
  | { readonly rule: "name" }
  | { readonly rule: "location"; readonly location: string }
  | { readonly rule: "version-info" };

/**
 * Rules 1 and 2 (pure): `program` is the normalized drive-absolute path, `finalPath` its resolved final path (the
 * same text when it cannot be resolved).
 */
export const programRefusal = (
  program: string,
  finalPath: string,
  locations: readonly RefusedLocation[],
): ProgramRefusal | null => {
  if (isInterpreterOrLolbin(program) || isInterpreterOrLolbin(finalPath)) return { rule: "name" };
  for (const path of new Set([folder(program), folder(finalPath)]))
    for (const location of locations) if (location.test(path)) return { rule: "location", location: location.label };
  return null;
};

/** Rule 3 (pure): the image's VERSIONINFO OriginalFilename / InternalName. */
export const versionInfoRefusal = (versionNames: readonly string[]): ProgramRefusal | null =>
  versionNames.some(refusedStem) ? { rule: "version-info" } : null;

/** config spawn.allowed_programs: drive-absolute paths (case-insensitive) or image sha256 digests. */
export const allowedProgram = (
  allowed: readonly string[],
  paths: readonly string[],
  sha256: string | null,
): boolean => {
  if (allowed.length === 0) return false;
  const folded = new Set(paths.map((p) => folder(p)));
  return allowed.some((entry) =>
    /^[a-f0-9]{64}$/iu.test(entry) ? sha256 !== null && entry.toLowerCase() === sha256 : folded.has(folder(entry)),
  );
};

/** `C:\…` or `C:/…` (no UNC, no device paths, no relative paths). */
export const isDriveAbsoluteWin32 = (path: string): boolean => /^[A-Za-z]:[\\/]/u.test(path);

export const isBatchScript = (program: string): boolean => /\.(?:bat|cmd)$/iu.test(program);

/**
 * Length of the command line msvcrt/CreateProcess would see for [program, ...args] with CRT quoting rules
 * (backslashes before a quote are doubled, quotes escaped, arguments with spaces/tabs/quotes or empty are quoted).
 * Windows caps a command line at 32,767 characters.
 */
export const crtCommandLineLength = (argv: readonly string[]): number => {
  let total = 0;
  for (const [index, arg] of argv.entries()) {
    if (index > 0) total += 1;
    total += quoteCrtArgument(arg).length;
  }
  return total;
};

export const quoteCrtArgument = (arg: string): string => {
  if (arg.length > 0 && !/[\s"]/u.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === "\\") {
      backslashes += 1;
      continue;
    }
    if (ch === '"') {
      out += "\\".repeat(backslashes * 2 + 1);
      out += '"';
    } else {
      out += "\\".repeat(backslashes);
      out += ch;
    }
    backslashes = 0;
  }
  out += "\\".repeat(backslashes * 2);
  return `${out}"`;
};

export const MAX_COMMAND_LINE = 32_767;
