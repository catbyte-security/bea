import type { BeaConfig } from "../domain/config.js";
import type { BeaError } from "../domain/errors/beaError.js";
import type { Result } from "../domain/result.js";

/**
 * CI-I7: S1 §7.9 EmulatorProvisioner as a WP0 port, so WP-CLI (wave 1, `bea setup --emulator`) and
 * WP-EMU (wave 5, src/providers/emulator/venvProvisioner.ts) build against one frozen type. Paths per D-INT-28.
 */
export interface ProvisionEmulatorAction {
  readonly id: string;
  readonly kind: "provision_emulator";
  /** <BEA_HOME>/emu/venv */
  readonly venv: string;
  readonly tool: "uv" | "venv+pip";
  readonly python: string;
  /** exact pins from bridge/emu/requirements.lock (unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26) */
  readonly packages: readonly string[];
  readonly network_origins: readonly string[];
  readonly commands: readonly (readonly string[])[];
}

export interface EmulatorProvisioner {
  plan(config: BeaConfig, signal: AbortSignal): Promise<Result<ProvisionEmulatorAction, BeaError>>;
  apply(
    action: ProvisionEmulatorAction,
    signal: AbortSignal,
  ): Promise<Result<{ readonly python: string; readonly versions: Readonly<Record<string, string>> }, BeaError>>;
}
