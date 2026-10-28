import { parseArgs, type ParseArgsConfig } from "node:util";

import type { BeaErrorOf } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { CliHost } from "../io.js";
import { describeAction, type SetupAction } from "./actions.js";
import { isClientId, type ClientContext, type ClientId } from "./clients.js";

export interface ApprovalFlags {
  readonly dryRun: boolean;
  readonly yes: boolean;
  readonly json: boolean;
}

export type Approval = "apply" | "planned" | "cancelled" | "needs_confirmation";

/**
 * S1 §7.9.3: `--dry-run` plans; `--yes` applies; an interactive approval happens only when stdin, stdout and stderr
 * are all TTYs and none of --yes/--dry-run/--json was given (plan and prompt on stderr); otherwise
 * needs_confirmation.
 */
export const decideApproval = async (
  host: CliHost,
  flags: ApprovalFlags,
  changes: readonly SetupAction[],
): Promise<Approval> => {
  if (flags.dryRun) return "planned";
  if (flags.yes) return "apply";
  const interactive = host.isTty.stdin && host.io.stdoutIsTty && host.isTty.stderr && !flags.json;
  if (!interactive) return "needs_confirmation";
  host.stderr(`BEA will make these changes:\n${changes.map((a) => `  - ${describeAction(a)}`).join("\n")}\n`);
  const answer = (await host.prompt(`Apply these ${String(changes.length)} changes? [y/N] `)).trim().toLowerCase();
  return answer === "y" || answer === "yes" ? "apply" : "cancelled";
};

export const clientContext = (host: CliHost): ClientContext => ({
  env: host.env,
  platform: host.platform,
  accountHome: host.accountHome,
});

/** parseArgs for setup/uninstall, mapped to invalid_request issues; validates every --client id. */
export const parseSetupArgs = (
  operation: string,
  argv: readonly string[],
  options: NonNullable<ParseArgsConfig["options"]>,
): Result<
  { readonly values: Readonly<Record<string, unknown>>; readonly clients: readonly ClientId[] },
  BeaErrorOf<"InputError">
> => {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({ args: [...argv], options, strict: true, allowPositionals: false, allowNegative: true });
  } catch (cause: unknown) {
    return err(
      inputError(operation, [
        { path: "argv", reason: "unknown_argument", message: cause instanceof Error ? cause.message : String(cause) },
      ]),
    );
  }
  const raw = parsed.values["client"];
  const requested = Array.isArray(raw) ? raw.filter((v): v is string => typeof v === "string") : [];
  const bad = requested.filter((id) => !isClientId(id));
  if (bad.length > 0)
    return err(
      inputError(operation, [
        {
          path: "--client",
          reason: "invalid_value",
          message: `Unknown client ${bad.join(", ")}. Supported: claude_code, codex, cursor, vscode, claude_desktop, gemini_cli.`,
        },
      ]),
    );
  return ok({ values: parsed.values, clients: [...new Set(requested as ClientId[])] });
};
