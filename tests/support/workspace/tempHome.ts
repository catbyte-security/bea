import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * A throwaway home for one test, test file or server (S1 §8): HOME, USERPROFILE, APPDATA, LOCALAPPDATA, TEMP, TMP,
 * XDG_* and BEA_HOME all point inside one fresh directory under the OS temp dir, so no test ever touches the real
 * %LOCALAPPDATA%\bea or another test's state.
 */
export interface TempHome {
  readonly root: string;
  /** BEA_HOME: <root>/bea-home */
  readonly beaHome: string;
  /** The account-like home: <root>/home */
  readonly home: string;
  /** Scratch space for test outputs: <root>/work */
  readonly work: string;
  /** Environment variables pointing inside root, for a child BEA process or loadConfig. */
  readonly env: Readonly<Record<string, string>>;
  /** Best-effort recursive removal; returns false when something stayed (a file still held by a process). */
  readonly cleanup: () => Promise<boolean>;
}

export const createTempHome = async (label = "home"): Promise<TempHome> => {
  const root = await mkdtemp(join(tmpdir(), `bea-test-${label.replace(/[^A-Za-z0-9_-]/gu, "_")}-`));
  const home = join(root, "home");
  const dirs = {
    home,
    appData: join(home, "AppData", "Roaming"),
    localAppData: join(home, "AppData", "Local"),
    temp: join(root, "tmp"),
    beaHome: join(root, "bea-home"),
    work: join(root, "work"),
  };
  await Promise.all(Object.values(dirs).map((dir) => mkdir(dir, { recursive: true })));
  const env = {
    HOME: home,
    USERPROFILE: home,
    APPDATA: dirs.appData,
    LOCALAPPDATA: dirs.localAppData,
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_DATA_HOME: join(home, ".local", "share"),
    TEMP: dirs.temp,
    TMP: dirs.temp,
    BEA_HOME: dirs.beaHome,
  };
  return {
    root,
    beaHome: dirs.beaHome,
    home,
    work: dirs.work,
    env,
    cleanup: async () => {
      try {
        await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        return true;
      } catch {
        return false;
      }
    },
  };
};
