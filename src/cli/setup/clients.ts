import { stat } from "node:fs/promises";
import { posix, win32 } from "node:path";

import { homeFromEnvironment, type HostPlatform } from "../../domain/paths.js";
import type { JsonObject } from "../../domain/json.js";

/** Supported MCP clients (S1 §7.9.1; paths and keys are REA's VERIFIED-src table [rea-cli §5.6]). */
export const CLIENT_IDS = ["claude_code", "codex", "cursor", "vscode", "claude_desktop", "gemini_cli"] as const;
export type ClientId = (typeof CLIENT_IDS)[number];

export const isClientId = (value: string): value is ClientId => (CLIENT_IDS as readonly string[]).includes(value);

export type DocumentKind = "json-strict" | "jsonc" | "toml";

/** The command every registration launches: `[node, realpath(<package>/scripts/bea.mjs), "mcp"]` (S1 §7.9.1). */
export interface RegisteredCommand {
  readonly command: string;
  readonly args: readonly string[];
}

/** Codex `[mcp_servers.bea]` timeouts: the 120 s maximum call plus 120 s headroom (≥ 180 s, OI-5). */
export const CODEX_STARTUP_TIMEOUT_SEC = 30;
export const CODEX_TOOL_TIMEOUT_SEC = 240;

export interface ClientContext {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly platform: HostPlatform;
  readonly accountHome: string;
}

export interface ClientLocation {
  readonly path: string;
  /** The config file or the client's marker directory exists. Detection is context, never permission. */
  readonly detected: boolean;
}

export interface ClientSpec {
  readonly id: ClientId;
  readonly label: string;
  readonly format: DocumentKind;
  /** JSON key path of the entry (TOML: mcp_servers.bea). */
  readonly keyPath: readonly string[];
  /** Extra plan notes shown before approval. */
  readonly notes: readonly string[];
  readonly locate: (ctx: ClientContext) => Promise<ClientLocation>;
}

const exists = async (path: string): Promise<boolean> => {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
};

const api = (ctx: ClientContext) => (ctx.platform === "win32" ? win32 : posix);

const nonEmpty = (value: string | undefined): string | undefined =>
  value !== undefined && value.length > 0 ? value : undefined;

export const clientHome = (ctx: ClientContext): string => homeFromEnvironment(ctx.env, ctx.platform, ctx.accountHome);

const absoluteEnv = (ctx: ClientContext, name: string): string | undefined => {
  const value = nonEmpty(ctx.env[name]);
  return value !== undefined && api(ctx).isAbsolute(value) ? value : undefined;
};

/** %APPDATA% (win32) or ~/.config (POSIX). */
const roamingConfig = (ctx: ClientContext): string =>
  ctx.platform === "win32"
    ? (absoluteEnv(ctx, "APPDATA") ?? win32.join(clientHome(ctx), "AppData", "Roaming"))
    : ctx.platform === "darwin"
      ? posix.join(clientHome(ctx), "Library", "Application Support")
      : (absoluteEnv(ctx, "XDG_CONFIG_HOME") ?? posix.join(clientHome(ctx), ".config"));

const localAppData = (ctx: ClientContext): string =>
  absoluteEnv(ctx, "LOCALAPPDATA") ?? win32.join(clientHome(ctx), "AppData", "Local");

/** `<CLAUDE_CONFIG_DIR or ~/.claude>`: Claude Code's directory (skills live under it). */
export const claudeConfigDir = (ctx: ClientContext): string =>
  absoluteEnv(ctx, "CLAUDE_CONFIG_DIR") ?? api(ctx).join(clientHome(ctx), ".claude");

const located = async (path: string, ...markers: string[]): Promise<ClientLocation> => {
  for (const candidate of [path, ...markers]) if (await exists(candidate)) return { path, detected: true };
  return { path, detected: false };
};

const CLAUDE_DESKTOP_MSIX = "Claude_pzs8sxrjxfjjc";

export const CLIENTS: { readonly [C in ClientId]: ClientSpec } = {
  claude_code: {
    id: "claude_code",
    label: "Claude Code",
    format: "json-strict",
    keyPath: ["mcpServers", "bea"],
    notes: ["Claude Code may rewrite ~/.claude.json while it runs; close it before applying."],
    locate: (ctx) => {
      const dir = absoluteEnv(ctx, "CLAUDE_CONFIG_DIR");
      return dir !== undefined
        ? located(api(ctx).join(dir, ".claude.json"), dir)
        : located(api(ctx).join(clientHome(ctx), ".claude.json"), api(ctx).join(clientHome(ctx), ".claude"));
    },
  },
  codex: {
    id: "codex",
    label: "Codex",
    format: "toml",
    keyPath: ["mcp_servers", "bea"],
    notes: [`tool_timeout_sec = ${String(CODEX_TOOL_TIMEOUT_SEC)} (a larger existing value is kept).`],
    locate: (ctx) => {
      const dir = absoluteEnv(ctx, "CODEX_HOME") ?? api(ctx).join(clientHome(ctx), ".codex");
      return located(api(ctx).join(dir, "config.toml"), dir);
    },
  },
  cursor: {
    id: "cursor",
    label: "Cursor",
    format: "jsonc",
    keyPath: ["mcpServers", "bea"],
    notes: [],
    locate: (ctx) => {
      const dir = api(ctx).join(clientHome(ctx), ".cursor");
      return located(api(ctx).join(dir, "mcp.json"), dir);
    },
  },
  vscode: {
    id: "vscode",
    label: "VS Code",
    format: "jsonc",
    keyPath: ["servers", "bea"],
    notes: [],
    locate: (ctx) => {
      const dir = api(ctx).join(roamingConfig(ctx), "Code", "User");
      return located(api(ctx).join(dir, "mcp.json"), dir);
    },
  },
  claude_desktop: {
    id: "claude_desktop",
    label: "Claude Desktop",
    format: "json-strict",
    keyPath: ["mcpServers", "bea"],
    notes: ["Quit Claude Desktop fully before approving."],
    locate: async (ctx) => {
      if (ctx.platform === "win32") {
        const msix = win32.join(localAppData(ctx), "Packages", CLAUDE_DESKTOP_MSIX);
        if (await exists(msix))
          return {
            path: win32.join(msix, "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"),
            detected: true,
          };
      }
      const dir = api(ctx).join(roamingConfig(ctx), "Claude");
      return located(api(ctx).join(dir, "claude_desktop_config.json"), dir);
    },
  },
  gemini_cli: {
    id: "gemini_cli",
    label: "Gemini CLI",
    format: "jsonc",
    keyPath: ["mcpServers", "bea"],
    notes: ["Set Gemini CLI's tool timeout to at least 180 s (BEA calls may run 120 s)."],
    locate: (ctx) => {
      const dir = api(ctx).join(absoluteEnv(ctx, "GEMINI_CLI_HOME") ?? clientHome(ctx), ".gemini");
      return located(api(ctx).join(dir, "settings.json"), dir);
    },
  },
};

/** The planned JSON entry (VS Code adds `type: "stdio"`); `env` only carries preserved BEA_* keys. */
export const plannedJsonEntry = (
  client: ClientId,
  command: RegisteredCommand,
  preservedEnv: Readonly<Record<string, string>>,
): JsonObject => ({
  ...(client === "vscode" ? { type: "stdio" } : {}),
  command: command.command,
  args: [...command.args],
  ...(Object.keys(preservedEnv).length === 0 ? {} : { env: { ...preservedEnv } }),
});
