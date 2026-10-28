import type { BeaApplication, BeaCore } from "../application/BeaApplication.js";
import type { DistLayout } from "../application/distLayout.js";
import type { HandlerLookup } from "../application/invokeTool.js";
import type { BeaServices } from "../application/services/index.js";
import type { ToolContract } from "../contracts/toolContract.js";
import type { BeaConfig } from "../domain/config.js";
import type { HostPlatform } from "../domain/paths.js";
import type { EmulatorProvisioner } from "../ports/provisioner.js";

/** stdout as the dispatcher hands it over (scripts/bea.mjs guards EPIPE and maps it to exit 141). */
export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly stdoutIsTty: boolean;
}

export type CliSignal = "SIGINT" | "SIGTERM";

/** The subset of `process` the CLI listens on; tests pass an EventEmitter. */
export interface CliSignalSource {
  on(event: CliSignal, listener: () => void): unknown;
  off(event: CliSignal, listener: () => void): unknown;
}

/**
 * Everything the CLI takes from its host process. src/main/cli.ts fills it from `process`; tests fill it with temp
 * directories and captured streams, so no CLI module reads process.env, process.cwd() or the real home directly.
 */
export interface CliHost {
  readonly io: CliIo;
  /** Progress, logs, prompts and human messages. Never the result document. */
  readonly stderr: (text: string) => void;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly platform: HostPlatform;
  readonly arch: string;
  /** process.versions.node */
  readonly nodeVersion: string;
  /** os.userInfo().homedir (used only when no home variable is set) */
  readonly accountHome: string;
  readonly cwd: string;
  /** process.execPath: the node binary registered in client configurations */
  readonly execPath: string;
  readonly isTty: { readonly stdin: boolean; readonly stderr: boolean };
  /** Reads all of stdin; null when it is larger than maxBytes. Called at most once per command. */
  readonly readStdin: (maxBytes: number) => Promise<Buffer | null>;
  /** Interactive question on stderr (setup approval); resolves with the typed line. */
  readonly prompt: (question: string) => Promise<string>;
  readonly signals: CliSignalSource;
  /** Where this build's outputs are (dispatcher, skills, …). */
  readonly layout: DistLayout;
}

/** The product pieces the CLI drives. Production: TOOL_CONTRACTS, createToolHandlers, composeServices. */
export interface CliCatalog {
  readonly contracts: readonly ToolContract[];
  readonly createHandlers: (app: BeaApplication) => HandlerLookup;
  readonly services: (core: BeaCore) => Promise<BeaServices>;
  /** CI-I7: `bea setup --emulator` provisions through this port; built without an application. */
  readonly provisioner: (config: BeaConfig) => EmulatorProvisioner;
}

export interface CliDeps extends CliHost, CliCatalog {}

export type OutputFormat = "toon" | "json";
