import { realpath } from "node:fs/promises";
import { posix, win32 } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { parse as parseJsonc } from "jsonc-parser";
import { parse as parseToml } from "smol-toml";

import type { HostPlatform } from "../../domain/paths.js";
import { isJsonObject } from "../../domain/json.js";
import {
  CLIENTS,
  CODEX_STARTUP_TIMEOUT_SEC,
  CODEX_TOOL_TIMEOUT_SEC,
  plannedJsonEntry,
  type ClientContext,
  type ClientId,
  type RegisteredCommand,
} from "./clients.js";
import { editCodexToml, editJsonEntry, type EditOutcome } from "./configDocument.js";
import { snapshotFile, type FileSnapshot } from "./transaction.js";

/** S1 §7.9.2 per-client states. Only missing (create) and stale (update) are ever edited. */
export type RegistrationState =
  | "missing"
  | "aligned"
  | "stale"
  | "foreign"
  | "unknown"
  | "invalid"
  | "manual"
  | "symlink";

/** States that block the whole setup before any write (S1 §7.9.3 pre-validation, [rea-cli §5.3 step 5]). */
export const NEEDS_HUMAN_STATES: readonly RegistrationState[] = ["foreign", "unknown", "invalid", "manual", "symlink"];

export interface ClientInspection {
  readonly client: ClientId;
  readonly path: string;
  readonly detected: boolean;
  readonly state: RegistrationState;
  readonly snapshot: FileSnapshot | null;
  /** The edited file text for missing/stale; null otherwise. */
  readonly next: string | null;
  /** The planned entry as written (JSON object or the Codex table values). */
  readonly planned: Readonly<Record<string, unknown>>;
  readonly reason: string | null;
}

/** The registered command plus the realpath used for ownership checks. */
export interface CommandIdentity extends RegisteredCommand {
  readonly dispatcherReal: string;
}

const PACKAGE_REFERENCE = /^bea-agents(?:@latest|@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)?$/u;

const samePath = (a: string, b: string, platform: HostPlatform): boolean =>
  platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;

/**
 * `[process.execPath, realpath(<package>/scripts/bea.mjs), "mcp"]` while the package is private (S1 §7.9.1). Refuses a
 * dispatcher inside npm's `_npx` cache: that path disappears when npm prunes its cache.
 */
export const resolveRegisteredCommand = async (
  execPath: string,
  dispatcher: string,
): Promise<
  { readonly ok: true; readonly value: CommandIdentity } | { readonly ok: false; readonly reason: string }
> => {
  let real: string;
  try {
    real = await realpath(dispatcher);
  } catch {
    return { ok: false, reason: `BEA's dispatcher ${dispatcher} does not exist; build or reinstall BEA first.` };
  }
  if (real.split(/[\\/]/u).some((part) => part.toLowerCase() === "_npx"))
    return {
      ok: false,
      reason:
        "BEA is running from npm's _npx cache; install it (or use a checkout) before registering it with clients.",
    };
  return { ok: true, value: { command: execPath, args: [real, "mcp"], dispatcherReal: real } };
};

export type Ownership = "owned" | "foreign" | "unknown";

/**
 * S1 §7.9.2: owned when a command/arg resolves to our scripts/bea.mjs or names the package (`bea-agents[@ver]`);
 * unknown when some `bea.mjs` resolves elsewhere or is gone (another checkout: ownership cannot be proven); else foreign.
 */
export const classifyEntry = async (
  entry: unknown,
  identity: CommandIdentity,
  platform: HostPlatform,
): Promise<Ownership> => {
  if (!isJsonObject(entry)) return "foreign";
  const args = Array.isArray(entry["args"]) ? entry["args"] : [];
  const candidates = [entry["command"], ...args].filter((value): value is string => typeof value === "string");
  let sawOtherDispatcher = false;
  for (const candidate of candidates) {
    if (PACKAGE_REFERENCE.test(candidate)) return "owned";
    const base = (platform === "win32" ? win32 : posix).basename(candidate);
    if (!samePath(base, "bea.mjs", platform)) continue;
    let resolved: string;
    try {
      resolved = await realpath(candidate);
    } catch {
      sawOtherDispatcher = true;
      continue;
    }
    if (samePath(resolved, identity.dispatcherReal, platform)) return "owned";
    sawOtherDispatcher = true;
  }
  return sawOtherDispatcher ? "unknown" : "foreign";
};

/** BEA_* keys of an owned entry's env survive an update; the ambient environment is never copied. */
const preservedEnv = (entry: unknown): Record<string, string> => {
  if (!isJsonObject(entry) || !isJsonObject(entry["env"])) return {};
  return Object.fromEntries(
    Object.entries(entry["env"]).filter(
      (pair): pair is [string, string] => pair[0].startsWith("BEA_") && typeof pair[1] === "string",
    ),
  );
};

const codexEntry = (command: RegisteredCommand) => ({
  command: command.command,
  args: command.args,
  startup_timeout_sec: CODEX_STARTUP_TIMEOUT_SEC,
  tool_timeout_sec: CODEX_TOOL_TIMEOUT_SEC,
});

const editFor = (
  client: ClientId,
  text: string | null,
  identity: CommandIdentity,
  env: Readonly<Record<string, string>>,
): { readonly edit: EditOutcome; readonly planned: Readonly<Record<string, unknown>> } => {
  const spec = CLIENTS[client];
  if (spec.format === "toml") {
    const planned = codexEntry(identity);
    return { edit: editCodexToml(text, planned), planned };
  }
  const planned = plannedJsonEntry(client, identity, env);
  return { edit: editJsonEntry(text, spec.keyPath, planned, spec.format), planned };
};

const getAt = (root: unknown, path: readonly string[]): unknown => {
  let value = root;
  for (const key of path) {
    if (!isJsonObject(value)) return undefined;
    value = value[key];
  }
  return value;
};

/** Read-back check after publishing (and doctor's view): the file parses and holds the planned entry. */
export const fileHoldsEntry = (client: ClientId, text: string, planned: Readonly<Record<string, unknown>>): boolean => {
  const spec = CLIENTS[client];
  try {
    const root: unknown =
      spec.format === "toml"
        ? parseToml(text.replace(/^﻿/u, ""))
        : parseJsonc(text.replace(/^﻿/u, ""), [], { allowTrailingComma: true });
    const entry = getAt(root, spec.keyPath);
    if (spec.format !== "toml") return isDeepStrictEqual(entry, planned);
    return (
      isJsonObject(entry) &&
      entry["command"] === planned["command"] &&
      isDeepStrictEqual(entry["args"], [...((planned["args"] as readonly string[] | undefined) ?? [])])
    );
  } catch {
    return false;
  }
};

/**
 * S1 §7.9.2 "aligned" = owned and deep-equal to the planned entry. Codex compares command and args and accepts
 * timeouts at or above BEA's minimums (editCodexToml keeps a larger user value).
 */
const entryAligned = (client: ClientId, previous: unknown, planned: Readonly<Record<string, unknown>>): boolean => {
  if (CLIENTS[client].format !== "toml") return isDeepStrictEqual(previous, planned);
  if (!isJsonObject(previous)) return false;
  const atLeast = (key: string, minimum: number): boolean => {
    const value = previous[key];
    return typeof value === "number" && Number.isInteger(value) && value >= minimum;
  };
  return (
    previous["command"] === planned["command"] &&
    isDeepStrictEqual(previous["args"], [...((planned["args"] as readonly string[] | undefined) ?? [])]) &&
    atLeast("startup_timeout_sec", CODEX_STARTUP_TIMEOUT_SEC) &&
    atLeast("tool_timeout_sec", CODEX_TOOL_TIMEOUT_SEC)
  );
};

/** Inspect one client's registration without writing anything (setup plan, doctor, uninstall). */
export const inspectClient = async (
  client: ClientId,
  ctx: ClientContext,
  identity: CommandIdentity,
): Promise<ClientInspection> => {
  const location = await CLIENTS[client].locate(ctx);
  const base = { client, path: location.path, detected: location.detected };
  let snapshot: Awaited<ReturnType<typeof snapshotFile>>;
  try {
    snapshot = await snapshotFile(location.path);
  } catch {
    return { ...base, state: "invalid", snapshot: null, next: null, planned: {}, reason: "The file cannot be read." };
  }
  if (snapshot === "symlink")
    return {
      ...base,
      state: "symlink",
      snapshot: null,
      next: null,
      planned: {},
      reason: "The configuration file is a symbolic link; BEA never edits through a link.",
    };
  const text = snapshot === null ? null : snapshot.bytes.toString("utf8");
  const first = editFor(client, text, identity, {});
  if (first.edit.kind !== "edited")
    return { ...base, state: first.edit.kind, snapshot, next: null, planned: first.planned, reason: first.edit.reason };
  const previous = first.edit.previous;
  if (previous === undefined)
    return { ...base, state: "missing", snapshot, next: first.edit.text, planned: first.planned, reason: null };
  const ownership = await classifyEntry(previous, identity, ctx.platform);
  if (ownership !== "owned")
    return {
      ...base,
      state: ownership,
      snapshot,
      next: null,
      planned: first.planned,
      reason:
        ownership === "foreign"
          ? "A `bea` entry exists that BEA did not write; rename or remove it, then rerun setup."
          : "A `bea` entry points at a bea.mjs that is missing or belongs to another BEA checkout.",
    };
  const env = preservedEnv(previous);
  const final = Object.keys(env).length === 0 ? first : editFor(client, text, identity, env);
  if (final.edit.kind !== "edited")
    return { ...base, state: final.edit.kind, snapshot, next: null, planned: final.planned, reason: final.edit.reason };
  const aligned = text !== null && entryAligned(client, previous, final.planned);
  return {
    ...base,
    state: aligned ? "aligned" : "stale",
    snapshot,
    next: aligned ? null : final.edit.text,
    planned: final.planned,
    reason: null,
  };
};
