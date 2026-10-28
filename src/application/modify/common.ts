import type { AddressRef } from "../../domain/address/addressRef.js";
import type { BeaError, BeaErrorOf, InputIssue } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import type { EvidenceDraft } from "../../ports/evidence.js";
import type { LiveSession } from "../../ports/sessions.js";
import { formatHex } from "../../shared/hex.js";

/** Shared bits of the three modify services (WP12). */

/** Provider identity of live observations. The Frida version is not exposed on LiveSession, so it stays null. */
export const FRIDA_PROVIDER: EvidenceDraft<null>["provider"] = { id: "frida", name: "frida", version: null };

export const issueError = (operation: string, issue: InputIssue): BeaErrorOf<"InputError"> =>
  inputError(operation, [issue]);

export const addressUnmapped = (
  operation: string,
  va: bigint,
  ref: AddressRef | null,
): BeaErrorOf<"AddressUnmapped"> => ({
  _tag: "AddressUnmapped",
  operation,
  address: formatHex(va),
  module_map_id: ref?.module_map_id ?? null,
});

/** Attach the session's instance id to an error that has none (callers see which process failed). */
export const withInstance = (error: BeaError, session: LiveSession): BeaError =>
  error.instance_id !== undefined ? error : { ...error, instance_id: session.instanceId };

/** `display_target` of an effect: BEA-formatted module+rva when known, else the VA. Display only (not in the id). */
export const displayTarget = (ref: AddressRef): string =>
  ref.module !== null && ref.rva !== null ? `${ref.module}+${ref.rva}` : ref.va;

/** Is the BeaError an agent error of the given tag (agentErrorMap keeps the tag in diagnostics.agent_tag)? */
export const isAgentTag = (error: BeaError, tag: string): boolean => error.diagnostics?.["agent_tag"] === tag;
