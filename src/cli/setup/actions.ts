import type { ProvisionEmulatorAction } from "../../ports/provisioner.js";
import type { ClientId } from "./clients.js";

/** S1 §7.9.7 action union (the emulator action is the frozen port type, CI-I7) plus the uninstall removals. */
export type SetupAction =
  | {
      readonly id: string;
      readonly kind: "configure_client";
      readonly client: ClientId;
      readonly path: string;
      readonly operation: "create" | "update" | "unchanged";
      readonly backup_path: string | null;
      readonly entry_preview: string;
      readonly notes: readonly string[];
    }
  | {
      readonly id: string;
      readonly kind: "install_skill";
      readonly path: string;
      readonly operation: "create" | "update" | "unchanged";
      readonly files: readonly string[];
    }
  | ProvisionEmulatorAction
  | {
      readonly id: string;
      readonly kind: "remove_client";
      readonly client: ClientId;
      readonly path: string;
      readonly backup_path: string;
    }
  | { readonly id: string; readonly kind: "remove_skill"; readonly path: string };

/** True when applying the action changes something on disk. */
export const isChange = (action: SetupAction): boolean => !("operation" in action) || action.operation !== "unchanged";

export type SetupStatus = "planned" | "cancelled" | "needs_confirmation" | "ready" | "needs_human";

export interface ClientOutcome {
  readonly state_before: string;
  readonly outcome: "unchanged" | "configured" | "removed" | "skipped" | "failed";
  readonly reason?: string;
}

/** Exit codes per S1 §7.6: planned/cancelled/ready → 0; needs_confirmation/needs_human → 1. */
export const statusExit = (status: SetupStatus): number =>
  status === "needs_confirmation" || status === "needs_human" ? 1 : 0;

/** One human-readable plan line (printed to stderr before the interactive approval). */
export const describeAction = (action: SetupAction): string => {
  switch (action.kind) {
    case "configure_client":
      return `${action.operation} bea in ${action.path}${action.backup_path === null ? "" : ` (backup ${action.backup_path})`}${action.notes.map((note) => `\n      note: ${note}`).join("")}`;
    case "install_skill":
      return `${action.operation} skill ${action.path} (${String(action.files.length)} files)`;
    case "provision_emulator":
      return `create emulator venv ${action.venv} with ${action.tool}: ${action.packages.join(", ")}\n      network: ${action.network_origins.join(", ")}${action.commands.map((c) => `\n      $ ${c.join(" ")}`).join("")}`;
    case "remove_client":
      return `remove bea from ${action.path} (backup ${action.backup_path})`;
    case "remove_skill":
      return `remove skill ${action.path}`;
  }
};
