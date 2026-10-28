import { posix, win32 } from "node:path";

export type HostPlatform = "win32" | "linux" | "darwin";

export interface BeaLayout {
  readonly root: string;
  readonly configFile: string;
  readonly runsDir: string;
  readonly runDir: (runId: string) => string;
  /** emulator root: venv/, cache/isa/, .setup.lock (S5 §13) */
  readonly emuDir: string;
  /** BEA-owned emulator venv (bea setup --emulator): <home>/emu/venv */
  readonly venvDir: string;
  /** HTTP connection files (bea mcp --http). */
  readonly httpDir: string;
  /** Reusable, content-keyed host caches (file-sha256.jsonl, agent load checks). ISA scans live in emu/cache/isa (D-INT-28). */
  readonly cacheDir: string;
  /** CT-I8: default out_path root for files tools write: <run dir>/exports */
  readonly exportsDir: (runId: string) => string;
  /** review fix LIFE-3: per-run directories Frida extracts its agent into (<home>/tmp/frida/<run_id>), swept */
  readonly fridaTempDir: string;
}

const pathApi = (platform: HostPlatform) => (platform === "win32" ? win32 : posix);

const nonEmpty = (value: string | undefined): string | undefined =>
  value !== undefined && value.length > 0 ? value : undefined;

/**
 * CT-M7: win32 requires a drive-absolute local path ("C:\x"); win32.isAbsolute also accepts drive-relative
 * ("\bea") and UNC ("\\host\share") forms, which BEA refuses for its home and output roots. POSIX: absolute.
 */
export const isDriveAbsolute = (value: string, platform: HostPlatform): boolean =>
  platform === "win32" ? /^[A-Za-z]:[\\/]/u.test(value) && !value.includes("\u0000") : posix.isAbsolute(value);

/** REA's home lookup (src/config/homeDirectory.ts): the caller's selection before the account. */
export const homeFromEnvironment = (
  env: Readonly<Record<string, string | undefined>>,
  platform: HostPlatform,
  accountHome: string,
): string => {
  const drive = nonEmpty(env["HOMEDRIVE"]);
  const homePath = nonEmpty(env["HOMEPATH"]);
  const windowsDriveHome = drive !== undefined && homePath !== undefined ? `${drive}${homePath}` : undefined;
  const selected =
    platform === "win32"
      ? (nonEmpty(env["USERPROFILE"]) ?? windowsDriveHome ?? nonEmpty(env["HOME"]))
      : (nonEmpty(env["HOME"]) ?? nonEmpty(env["USERPROFILE"]));
  return selected ?? accountHome;
};

export type BeaHomeResolution =
  | { readonly ok: true; readonly root: string; readonly source: "env" | "default" }
  | { readonly ok: false; readonly constraint: string };

/**
 * BEA_HOME (absolute) > platform default:
 * win32 %LOCALAPPDATA%\bea (fallback <home>\AppData\Local\bea);
 * linux $XDG_DATA_HOME/bea when absolute, else ~/.local/share/bea;
 * darwin ~/Library/Application Support/bea (not a v0.1 target).
 */
export const resolveBeaHome = (
  env: Readonly<Record<string, string | undefined>>,
  platform: HostPlatform,
  home: string,
): BeaHomeResolution => {
  const api = pathApi(platform);
  const explicit = nonEmpty(env["BEA_HOME"]);
  if (explicit !== undefined) {
    return isDriveAbsolute(explicit, platform)
      ? { ok: true, root: api.normalize(explicit), source: "env" }
      : {
          ok: false,
          constraint:
            platform === "win32"
              ? "BEA_HOME must be a drive-absolute local path such as C:\\bea (no UNC or drive-relative paths)."
              : "BEA_HOME must be an absolute path.",
        };
  }
  if (platform === "win32") {
    const local = nonEmpty(env["LOCALAPPDATA"]);
    return {
      ok: true,
      root: api.join(local !== undefined && api.isAbsolute(local) ? local : api.join(home, "AppData", "Local"), "bea"),
      source: "default",
    };
  }
  if (platform === "linux") {
    const xdg = nonEmpty(env["XDG_DATA_HOME"]);
    return {
      ok: true,
      root: api.join(xdg !== undefined && api.isAbsolute(xdg) ? xdg : api.join(home, ".local", "share"), "bea"),
      source: "default",
    };
  }
  return { ok: true, root: api.join(home, "Library", "Application Support", "bea"), source: "default" };
};

export const beaLayout = (root: string, platform: HostPlatform): BeaLayout => {
  const api = pathApi(platform);
  const runsDir = api.join(root, "runs");
  return {
    root,
    configFile: api.join(root, "config.json"),
    runsDir,
    runDir: (runId) => api.join(runsDir, runId),
    emuDir: api.join(root, "emu"),
    venvDir: api.join(root, "emu", "venv"),
    httpDir: api.join(root, "http"),
    cacheDir: api.join(root, "cache"),
    exportsDir: (runId) => api.join(runsDir, runId, "exports"),
    fridaTempDir: api.join(root, "tmp", "frida"),
  };
};
