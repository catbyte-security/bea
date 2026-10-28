/**
 * The spawned target's environment (CT-I7, D-INT-41). Default "allowlist": the OS allowlist below (version 1) taken
 * from the server environment plus the caller's `env` entries; "inherit" (user config spawn.env_mode only): the server
 * environment. Every `BEA_*` key is stripped from both sources. The result is passed to Frida as `envp`, which REPLACES
 * the environment (`env` would merge into the server's, ext-frida §1.4). Evidence records the mode, the allowlist
 * version and counts, never names or values.
 */
const ENV_ALLOWLIST_VERSION = 1 as const;

const WINDOWS_ALLOWLIST: readonly string[] = [
  "SystemRoot",
  "windir",
  "SystemDrive",
  "ComSpec",
  "PATHEXT",
  "PATH",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "USERNAME",
  "USERDOMAIN",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "ProgramData",
  "ProgramFiles",
  "ProgramFiles(x86)",
  "ProgramW6432",
  "CommonProgramFiles",
  "CommonProgramFiles(x86)",
  "CommonProgramW6432",
  "PUBLIC",
  "COMPUTERNAME",
  "NUMBER_OF_PROCESSORS",
  "OS",
  "ALLUSERSPROFILE",
  "DriverData",
];
const WINDOWS_PREFIXES: readonly string[] = ["PROCESSOR_"];
const LINUX_ALLOWLIST: readonly string[] = [
  "PATH",
  "HOME",
  "USER",
  "LANG",
  "TMPDIR",
  "XDG_RUNTIME_DIR",
  "DISPLAY",
  "WAYLAND_DISPLAY",
];
const LINUX_PREFIXES: readonly string[] = ["LC_"];

export type EnvMode = "allowlist" | "inherit";

export interface TargetEnvironment {
  /** what Frida receives as envp */
  readonly env: Readonly<Record<string, string>>;
  readonly mode: EnvMode;
  readonly allowlistVersion: typeof ENV_ALLOWLIST_VERSION;
  /** server variables NOT passed to the target (non-allowlisted ones and every BEA_*) */
  readonly droppedKeys: number;
  /** caller entries passed (BEA_* entries are dropped) */
  readonly callerKeys: number;
  /** caller BEA_* entries dropped */
  readonly callerDropped: number;
}

const isBeaKey = (key: string): boolean => key.toUpperCase().startsWith("BEA_");

export const isAllowlisted = (key: string, platform: "win32" | "linux"): boolean => {
  if (platform === "win32") {
    const upper = key.toUpperCase();
    return (
      WINDOWS_ALLOWLIST.some((name) => name.toUpperCase() === upper) ||
      WINDOWS_PREFIXES.some((prefix) => upper.startsWith(prefix))
    );
  }
  return LINUX_ALLOWLIST.includes(key) || LINUX_PREFIXES.some((prefix) => key.startsWith(prefix));
};

/**
 * Windows environment names are case-insensitive: a caller entry replaces a server entry with any casing of the same
 * name (the caller's casing wins). Linux names are case-sensitive.
 */
export const buildTargetEnvironment = (input: {
  readonly server: Readonly<Record<string, string | undefined>>;
  readonly caller: Readonly<Record<string, string>>;
  readonly mode: EnvMode;
  readonly platform: "win32" | "linux";
}): TargetEnvironment => {
  const env = new Map<string, readonly [string, string]>();
  const keyOf = (name: string): string => (input.platform === "win32" ? name.toUpperCase() : name);
  let droppedKeys = 0;
  for (const [name, value] of Object.entries(input.server)) {
    if (value === undefined) continue;
    const keep = !isBeaKey(name) && (input.mode === "inherit" || isAllowlisted(name, input.platform));
    if (keep) env.set(keyOf(name), [name, value]);
    else droppedKeys += 1;
  }
  let callerKeys = 0;
  let callerDropped = 0;
  for (const [name, value] of Object.entries(input.caller)) {
    if (isBeaKey(name)) {
      callerDropped += 1;
      continue;
    }
    env.set(keyOf(name), [name, value]);
    callerKeys += 1;
  }
  return {
    env: Object.fromEntries(env.values()),
    mode: input.mode,
    allowlistVersion: ENV_ALLOWLIST_VERSION,
    droppedKeys,
    callerKeys,
    callerDropped,
  };
};

/** "KEY=VALUE" entries → a record (the tool schema guarantees the "=" and a non-empty key). Later entries win. */
export const parseEnvEntries = (entries: readonly string[]): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const entry of entries) {
    const eq = entry.indexOf("=");
    if (eq <= 0) continue;
    out[entry.slice(0, eq)] = entry.slice(eq + 1);
  }
  return out;
};
