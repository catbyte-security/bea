import { posix, win32 } from "node:path";

import { z } from "zod";

import type { BeaErrorOf } from "./errors/beaError.js";
import { GATE_IDS, GATE_SPECS, type GateId } from "./gates.js";
import {
  beaLayout,
  homeFromEnvironment,
  isDriveAbsolute,
  resolveBeaHome,
  type BeaLayout,
  type HostPlatform,
} from "./paths.js";
import { err, ok, type Result } from "./result.js";

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

export const LOG_LEVELS = ["silent", "error", "warn", "info", "debug"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/** Fixed by the orchestrator. This release has no runtime override for these. */
export const HARD_LIMITS = {
  maxWaitMs: 60_000,
  maxToolCallMs: 120_000,
  recommendedClientToolTimeoutSeconds: 180,
  shutdownBudgetMs: 2_000,
  /** SDK STDIO_DEFAULT_MAX_BUFFER_SIZE (VERIFIED 10485760): SDK clients read responses with this buffer. */
  defaultResponseBytes: 10 * MiB,
  /**
   * CT-B3: the stdio transport's read buffer (StdioServerTransport maxBufferSize). The SDK default of 10 MiB CLOSES
   * the transport on a larger request line, which shut the server down (VERIFIED E12).
   */
  maxStdioRequestBytes: 64 * MiB,
  /** CT-B3: no contract may accept more than this (serialized arguments); leaves 64 KiB for the JSON-RPC envelope. */
  maxToolInputBytes: 64 * MiB - 64 * 1024,
  /** CT-B3: default ToolContract.maxInputBytes. */
  defaultToolInputBytes: 1 * MiB,
  /** D-INT-6 / CT-I3: the hard-exit safety timer is armed at the FIRST shutdown trigger, not after cleanup. */
  hardExitAfterMs: 1_900,
} as const;

/** Quotas per run (orchestrator + S2 §9.7), MiB. */
export const QUOTA_DEFAULTS = {
  ledgerMb: 512,
  ledgerReserveMb: 8,
  streamMb: 256,
  streamTotalMb: 4096,
  blobMb: 4096,
} as const;

const QUOTA_BOUNDS = {
  ledgerMb: { min: 16, max: 65_536 },
  ledgerReserveMb: { min: 1, max: 256 },
  streamMb: { min: 1, max: 65_536 },
  streamTotalMb: { min: 16, max: 1_048_576 },
  blobMb: { min: 16, max: 1_048_576 },
} as const;

/** S3 §3 host limits and S5 §13 emulator settings that are configurable (everything else is fixed). */
const LIMIT_BOUNDS = {
  maxLiveSessions: { min: 1, max: 8 },
  rpcDefaultTimeoutMs: { min: 1000, max: 115_000 },
  emuMaxSessions: { min: 1, max: 16 },
  emuMemoryLimitMb: { min: 256, max: 65_536 },
  emuSnapshotBytesLimitMb: { min: 16, max: 8192 },
  emuDumpMaxMb: { min: 16, max: 32_768 },
  emuStartupTimeoutMs: { min: 2000, max: 60_000 },
} as const;

const RESPONSE_BOUNDS = { min: 10 * MiB, max: 256 * MiB } as const;

export type SettingSource = "default" | "config-file" | "env";
export interface Setting<T> {
  readonly value: T;
  readonly source: SettingSource;
}

export interface BeaConfig {
  readonly platform: HostPlatform;
  readonly home: Setting<string>;
  readonly layout: BeaLayout;
  readonly logLevel: Setting<LogLevel>;
  readonly gates: { readonly [G in GateId]: Setting<boolean> };
  readonly quotas: {
    readonly ledgerMb: Setting<number>;
    readonly ledgerReserveMb: Setting<number>;
    readonly streamMb: Setting<number>;
    readonly streamTotalMb: Setting<number>;
    readonly blobMb: Setting<number>;
  };
  readonly limits: {
    readonly maxLiveSessions: Setting<number>;
    readonly rpcDefaultTimeoutMs: Setting<number>;
  };
  readonly attach: {
    /** S3 rule 7 */
    readonly allowSession0: Setting<boolean>;
    /** extra image basenames refused like rule 9 */
    readonly extraDenylist: Setting<readonly string[]>;
    /** DESIGN D-INT-1: TARGET-SCOPED anti-cheat signals refuse spawn/attach unless the USER sets this */
    readonly allowAntiCheat: Setting<boolean>;
    /** CT-I11: per-image override (lowercase sha256 of the target image); config file only */
    readonly allowAntiCheatImages: Setting<readonly string[]>;
  };
  /** CT-I7 / CT-I8: spawn policy; config file only (never env, never a tool input) */
  readonly spawn: {
    /** "allowlist" (default): OS allowlist + caller env, BEA_* stripped; "inherit": the server environment minus BEA_* */
    readonly envMode: Setting<"allowlist" | "inherit">;
    /** refuse script interpreters and LOLBins as spawn_process programs unless true */
    readonly allowInterpreters: Setting<boolean>;
    /**
     * Review fix SEC-1: programs the user allows despite the interpreter/LOLBin/location refusal (drive-absolute paths
     * or lowercase image sha256 digests); config file only
     */
    readonly allowedPrograms: Setting<readonly string[]>;
  };
  /** CT-I8: extra absolute roots where tools may write out_path files; config file only */
  readonly exports: {
    readonly allowedRoots: Setting<readonly string[]>;
  };
  readonly emu: {
    readonly maxSessions: Setting<number>;
    readonly memoryLimitMb: Setting<number>;
    readonly snapshotBytesLimitMb: Setting<number>;
    readonly dumpMaxMb: Setting<number>;
    readonly startupTimeoutMs: Setting<number>;
    readonly isaCache: Setting<boolean>;
    readonly selftest: Setting<"auto" | "always" | "never">;
  };
  /** server-level sensitive literals file (S2 §15.1): UTF-8, one literal per line, ≤ 256 */
  readonly sensitiveValuesFile: Setting<string | null>;
  /** Absolute python executable for the emulator bridge, or null (resolve later). */
  readonly python: Setting<string | null>;
  readonly mcpMaxResponseBytes: Setting<number>;
  /** Present only for `bea mcp --http`; never reported by status or logs. */
  readonly httpToken: Setting<string | null>;
  /** BEA_* variables that BEA does not know (likely typos). Doctor reports them. */
  readonly unknownEnv: readonly string[];
}

export const KNOWN_ENV = [
  "BEA_HOME",
  "BEA_LOG_LEVEL",
  ...GATE_IDS.map((gate) => GATE_SPECS[gate].env),
  "BEA_LEDGER_QUOTA_MB",
  "BEA_LEDGER_RESERVE_MB",
  "BEA_STREAM_QUOTA_MB",
  "BEA_STREAM_TOTAL_QUOTA_MB",
  "BEA_BLOB_QUOTA_MB",
  "BEA_MAX_LIVE_SESSIONS",
  "BEA_RPC_TIMEOUT_MS",
  "BEA_ALLOW_ANTI_CHEAT",
  "BEA_EMU_MAX_SESSIONS",
  "BEA_EMU_MEMORY_LIMIT_MB",
  "BEA_EMU_ISA_CACHE",
  "BEA_EMU_SELFTEST",
  "BEA_SENSITIVE_VALUES_FILE",
  "BEA_PYTHON",
  "BEA_MCP_MAX_RESPONSE_BYTES",
  "BEA_HTTP_TOKEN",
  "BEA_PACKAGE_VERSION",
] as const;

const boundedBytes = (bounds: { readonly min: number; readonly max: number }) =>
  z.number().int().min(bounds.min).max(bounds.max);
const boundedInt = boundedBytes;

/** BEA_HOME/config.json. Unknown keys are errors so typos never silently do nothing. */
export const configFileSchema = z.strictObject({
  schema: z.literal("bea.config/1"),
  log_level: z.enum(LOG_LEVELS).optional(),
  gates: z
    .strictObject({
      write_memory: z.boolean().optional(),
      override_function: z.boolean().optional(),
      run_script: z.boolean().optional(),
      call_attached: z.boolean().optional(),
    })
    .optional(),
  quotas: z
    .strictObject({
      ledger_mb: boundedInt(QUOTA_BOUNDS.ledgerMb).optional(),
      ledger_reserve_mb: boundedInt(QUOTA_BOUNDS.ledgerReserveMb).optional(),
      stream_mb: boundedInt(QUOTA_BOUNDS.streamMb).optional(),
      stream_total_mb: boundedInt(QUOTA_BOUNDS.streamTotalMb).optional(),
      blob_mb: boundedInt(QUOTA_BOUNDS.blobMb).optional(),
    })
    .optional(),
  limits: z
    .strictObject({
      max_live_sessions: boundedInt(LIMIT_BOUNDS.maxLiveSessions).optional(),
      rpc_default_timeout_ms: boundedInt(LIMIT_BOUNDS.rpcDefaultTimeoutMs).optional(),
    })
    .optional(),
  attach: z
    .strictObject({
      allow_session0: z.boolean().optional(),
      extra_denylist: z.array(z.string().min(1).max(260)).max(64).optional(),
      allow_anti_cheat: z.boolean().optional(),
      allow_anti_cheat_images: z
        .array(z.string().regex(/^[a-f0-9]{64}$/u))
        .max(64)
        .optional(),
    })
    .optional(),
  spawn: z
    .strictObject({
      env_mode: z.enum(["allowlist", "inherit"]).optional(),
      allow_interpreters: z.boolean().optional(),
      allowed_programs: z.array(z.string().min(3).max(1024)).max(64).optional(),
    })
    .optional(),
  exports: z
    .strictObject({
      allowed_roots: z.array(z.string().min(3).max(1024)).max(16).optional(),
    })
    .optional(),
  emu: z
    .strictObject({
      max_sessions: boundedInt(LIMIT_BOUNDS.emuMaxSessions).optional(),
      memory_limit_mb: boundedInt(LIMIT_BOUNDS.emuMemoryLimitMb).optional(),
      snapshot_bytes_limit_mb: boundedInt(LIMIT_BOUNDS.emuSnapshotBytesLimitMb).optional(),
      dump_max_mb: boundedInt(LIMIT_BOUNDS.emuDumpMaxMb).optional(),
      startup_timeout_ms: boundedInt(LIMIT_BOUNDS.emuStartupTimeoutMs).optional(),
      isa_cache: z.boolean().optional(),
      selftest: z.enum(["auto", "always", "never"]).optional(),
    })
    .optional(),
  sensitive_values_file: z.string().min(1).max(4096).optional(),
  python: z.string().min(1).max(4096).optional(),
  mcp_max_response_bytes: boundedBytes(RESPONSE_BOUNDS).optional(),
});
export type ConfigFile = z.infer<typeof configFileSchema>;

export interface ConfigSources {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly platform: HostPlatform;
  /** os.userInfo().homedir; used only when no home variable is set. */
  readonly accountHome: string;
  /** Returns null when the file does not exist. Throws only on I/O failure. */
  readonly readConfigFile: (path: string) => Promise<string | null>;
}

type SettingIssue = BeaErrorOf<"ConfigurationError">["settings"][number];

const TRUE = new Set(["1", "true", "yes", "on"]);
const FALSE = new Set(["0", "false", "no", "off"]);

const envBoolean = (env: ConfigSources["env"], name: string, issues: SettingIssue[]): boolean | undefined => {
  const raw = env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = raw.trim().toLowerCase();
  if (TRUE.has(value)) return true;
  if (FALSE.has(value)) return false;
  issues.push({
    setting: name,
    constraint: `${name} must be one of 1, true, yes, on, 0, false, no, off.`,
    source: "env",
  });
  return undefined;
};

const envInt = (
  env: ConfigSources["env"],
  name: string,
  bounds: { readonly min: number; readonly max: number },
  issues: SettingIssue[],
  unit = "",
): number | undefined => {
  const raw = env[name];
  if (raw === undefined || raw === "") return undefined;
  const value = /^[1-9]\d*$/u.test(raw) ? Number(raw) : Number.NaN;
  if (Number.isSafeInteger(value) && value >= bounds.min && value <= bounds.max) return value;
  issues.push({
    setting: name,
    constraint: `${name} must be a decimal integer from ${String(bounds.min)} to ${String(bounds.max)}${unit}.`,
    source: "env",
  });
  return undefined;
};
const envBytes = (
  env: ConfigSources["env"],
  name: string,
  bounds: { readonly min: number; readonly max: number },
  issues: SettingIssue[],
) => envInt(env, name, bounds, issues, " bytes");

const pick = <T>(envValue: T | undefined, fileValue: T | undefined, fallback: T): Setting<T> =>
  envValue !== undefined
    ? { value: envValue, source: "env" }
    : fileValue !== undefined
      ? { value: fileValue, source: "config-file" }
      : { value: fallback, source: "default" };

const HTTP_TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,256}$/u;

const selftestEnv = (env: ConfigSources["env"], issues: SettingIssue[]): "auto" | "always" | "never" | undefined => {
  const raw = env["BEA_EMU_SELFTEST"];
  if (raw === undefined || raw === "") return undefined;
  if (raw === "auto" || raw === "always" || raw === "never") return raw;
  issues.push({
    setting: "BEA_EMU_SELFTEST",
    constraint: "BEA_EMU_SELFTEST must be auto, always or never.",
    source: "env",
  });
  return undefined;
};
const absoluteEnv = (
  env: ConfigSources["env"],
  name: string,
  api: typeof win32,
  issues: SettingIssue[],
): string | undefined => {
  const raw = env[name];
  if (raw === undefined || raw === "") return undefined;
  if (api.isAbsolute(raw)) return raw;
  issues.push({ setting: name, constraint: `${name} must be an absolute path.`, source: "env" });
  return undefined;
};

/** Parse every setting once, at the boundary. Collects all problems before failing. */
export const loadConfig = async (
  sources: ConfigSources,
): Promise<Result<BeaConfig, BeaErrorOf<"ConfigurationError">>> => {
  const { env, platform } = sources;
  const issues: SettingIssue[] = [];
  const home = homeFromEnvironment(env, platform, sources.accountHome);
  const resolved = resolveBeaHome(env, platform, home);
  if (!resolved.ok) {
    return err({
      _tag: "ConfigurationError",
      operation: "load_config",
      settings: [{ setting: "BEA_HOME", constraint: resolved.constraint, source: "env" }],
    });
  }
  const layout = beaLayout(resolved.root, platform);

  let file: ConfigFile | undefined;
  const text = await sources.readConfigFile(layout.configFile);
  if (text !== null) {
    let json: unknown;
    try {
      json = JSON.parse(text.replace(/^﻿/u, ""));
    } catch {
      issues.push({ setting: layout.configFile, constraint: "config.json must be valid JSON.", source: "config-file" });
    }
    if (json !== undefined) {
      const parsed = configFileSchema.safeParse(json);
      if (parsed.success) file = parsed.data;
      else
        for (const issue of parsed.error.issues)
          issues.push({
            setting: `config.json:${issue.path.map(String).join(".") || "(root)"}`,
            constraint: issue.message,
            source: "config-file",
          });
    }
  }

  const logEnv = env["BEA_LOG_LEVEL"];
  let logLevel: LogLevel | undefined;
  if (logEnv !== undefined && logEnv !== "") {
    if ((LOG_LEVELS as readonly string[]).includes(logEnv)) logLevel = logEnv as LogLevel;
    else
      issues.push({
        setting: "BEA_LOG_LEVEL",
        constraint: `BEA_LOG_LEVEL must be one of ${LOG_LEVELS.join(", ")}.`,
        source: "env",
      });
  }

  const gates = Object.fromEntries(
    GATE_IDS.map((gate) => [gate, pick(envBoolean(env, GATE_SPECS[gate].env, issues), file?.gates?.[gate], false)]),
  ) as { [G in GateId]: Setting<boolean> };

  const api = platform === "win32" ? win32 : posix;
  const pythonEnv = env["BEA_PYTHON"];
  let python: string | undefined;
  if (pythonEnv !== undefined && pythonEnv !== "") {
    if (api.isAbsolute(pythonEnv)) python = pythonEnv;
    else
      issues.push({
        setting: "BEA_PYTHON",
        constraint: "BEA_PYTHON must be an absolute path to a python executable.",
        source: "env",
      });
  }
  if (file?.python !== undefined && !api.isAbsolute(file.python))
    issues.push({
      setting: "config.json:python",
      constraint: "python must be an absolute path.",
      source: "config-file",
    });
  for (const program of file?.spawn?.allowed_programs ?? [])
    if (!isDriveAbsolute(program, platform) && !/^[a-f0-9]{64}$/u.test(program))
      issues.push({
        setting: "config.json:spawn.allowed_programs",
        constraint: "allowed_programs entries must be drive-absolute local paths or lowercase sha256 digests.",
        source: "config-file",
      });
  for (const root of file?.exports?.allowed_roots ?? [])
    if (!isDriveAbsolute(root, platform))
      issues.push({
        setting: "config.json:exports.allowed_roots",
        constraint: "allowed_roots entries must be drive-absolute local paths.",
        source: "config-file",
      });

  const tokenEnv = env["BEA_HTTP_TOKEN"];
  let httpToken: string | undefined;
  if (tokenEnv !== undefined && tokenEnv !== "") {
    if (HTTP_TOKEN_PATTERN.test(tokenEnv)) httpToken = tokenEnv;
    // The value is a secret: the constraint never repeats it.
    else
      issues.push({
        setting: "BEA_HTTP_TOKEN",
        constraint: "BEA_HTTP_TOKEN must be 32-256 characters of [A-Za-z0-9_-].",
        source: "env",
      });
  }

  const config: BeaConfig = {
    platform,
    home: { value: resolved.root, source: resolved.source === "env" ? "env" : "default" },
    layout,
    logLevel: pick(logLevel, file?.log_level, "warn"),
    gates,
    quotas: {
      ledgerMb: pick(
        envInt(env, "BEA_LEDGER_QUOTA_MB", QUOTA_BOUNDS.ledgerMb, issues, " MiB"),
        file?.quotas?.ledger_mb,
        QUOTA_DEFAULTS.ledgerMb,
      ),
      ledgerReserveMb: pick(
        envInt(env, "BEA_LEDGER_RESERVE_MB", QUOTA_BOUNDS.ledgerReserveMb, issues, " MiB"),
        file?.quotas?.ledger_reserve_mb,
        QUOTA_DEFAULTS.ledgerReserveMb,
      ),
      streamMb: pick(
        envInt(env, "BEA_STREAM_QUOTA_MB", QUOTA_BOUNDS.streamMb, issues, " MiB"),
        file?.quotas?.stream_mb,
        QUOTA_DEFAULTS.streamMb,
      ),
      streamTotalMb: pick(
        envInt(env, "BEA_STREAM_TOTAL_QUOTA_MB", QUOTA_BOUNDS.streamTotalMb, issues, " MiB"),
        file?.quotas?.stream_total_mb,
        QUOTA_DEFAULTS.streamTotalMb,
      ),
      blobMb: pick(
        envInt(env, "BEA_BLOB_QUOTA_MB", QUOTA_BOUNDS.blobMb, issues, " MiB"),
        file?.quotas?.blob_mb,
        QUOTA_DEFAULTS.blobMb,
      ),
    },
    limits: {
      maxLiveSessions: pick(
        envInt(env, "BEA_MAX_LIVE_SESSIONS", LIMIT_BOUNDS.maxLiveSessions, issues),
        file?.limits?.max_live_sessions,
        4,
      ),
      rpcDefaultTimeoutMs: pick(
        envInt(env, "BEA_RPC_TIMEOUT_MS", LIMIT_BOUNDS.rpcDefaultTimeoutMs, issues, " ms"),
        file?.limits?.rpc_default_timeout_ms,
        10_000,
      ),
    },
    attach: {
      allowSession0: pick(undefined, file?.attach?.allow_session0, false),
      extraDenylist: pick<readonly string[]>(undefined, file?.attach?.extra_denylist, []),
      allowAntiCheat: pick(envBoolean(env, "BEA_ALLOW_ANTI_CHEAT", issues), file?.attach?.allow_anti_cheat, false),
      allowAntiCheatImages: pick<readonly string[]>(undefined, file?.attach?.allow_anti_cheat_images, []),
    },
    spawn: {
      envMode: pick<"allowlist" | "inherit">(undefined, file?.spawn?.env_mode, "allowlist"),
      allowInterpreters: pick(undefined, file?.spawn?.allow_interpreters, false),
      allowedPrograms: pick<readonly string[]>(undefined, file?.spawn?.allowed_programs, []),
    },
    exports: {
      allowedRoots: pick<readonly string[]>(undefined, file?.exports?.allowed_roots, []),
    },
    emu: {
      maxSessions: pick(
        envInt(env, "BEA_EMU_MAX_SESSIONS", LIMIT_BOUNDS.emuMaxSessions, issues),
        file?.emu?.max_sessions,
        4,
      ),
      memoryLimitMb: pick(
        envInt(env, "BEA_EMU_MEMORY_LIMIT_MB", LIMIT_BOUNDS.emuMemoryLimitMb, issues, " MiB"),
        file?.emu?.memory_limit_mb,
        4096,
      ),
      snapshotBytesLimitMb: pick(undefined, file?.emu?.snapshot_bytes_limit_mb, 512),
      dumpMaxMb: pick(undefined, file?.emu?.dump_max_mb, 2048),
      startupTimeoutMs: pick(undefined, file?.emu?.startup_timeout_ms, 15_000),
      isaCache: pick(envBoolean(env, "BEA_EMU_ISA_CACHE", issues), file?.emu?.isa_cache, true),
      selftest: pick(selftestEnv(env, issues), file?.emu?.selftest, "auto"),
    },
    sensitiveValuesFile: pick<string | null>(
      absoluteEnv(env, "BEA_SENSITIVE_VALUES_FILE", api, issues),
      file?.sensitive_values_file,
      null,
    ),
    python: pick<string | null>(python, file?.python, null),
    mcpMaxResponseBytes: pick(
      envBytes(env, "BEA_MCP_MAX_RESPONSE_BYTES", RESPONSE_BOUNDS, issues),
      file?.mcp_max_response_bytes,
      HARD_LIMITS.defaultResponseBytes,
    ),
    httpToken: pick<string | null>(httpToken, undefined, null),
    unknownEnv: Object.keys(env)
      .filter((name) => name.startsWith("BEA_") && !(KNOWN_ENV as readonly string[]).includes(name))
      .sort(),
  };
  return issues.length === 0
    ? ok(config)
    : err({ _tag: "ConfigurationError", operation: "load_config", settings: issues });
};
