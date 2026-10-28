import { moduleTokenLabel, type AddressIssue, type ModuleToken } from "../../domain/address/grammar.js";
import type { BeaError, BeaErrorOf, InputIssue } from "../../domain/errors/beaError.js";
import { formatHex } from "../../domain/hex.js";
import type { MmId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";

/**
 * The S2 §16.2 resolution error table as BeaErrors (normative; S2 wins over the S6 summary column). Reason details
 * travel in `diagnostics` (projected as details.diagnostics); messages are BEA-authored, the token is caller input.
 */
export const inputIssue = (
  operation: string,
  path: string,
  reason: InputIssue["reason"],
  message: string,
  diagnostics?: JsonObject,
): BeaErrorOf<"InputError"> => ({
  _tag: "InputError",
  operation,
  issues: [{ path, reason, message: message.slice(0, 600) }],
  ...(diagnostics === undefined ? {} : { diagnostics }),
});

/** A grammar issue (invalid_format / out_of_range) at `path`. */
export const issueError = (operation: string, path: string, issue: AddressIssue): BeaErrorOf<"InputError"> => ({
  _tag: "InputError",
  operation,
  issues: [
    {
      path,
      reason: issue.reason,
      message: issue.message,
      ...(issue.expected === undefined ? {} : { expected: issue.expected }),
    },
  ],
});

/** module not loaded → address_unmapped{module_not_loaded} with recovery refresh_module_map. */
export const notLoadedError = (
  operation: string,
  token: ModuleToken,
  moduleMapId: MmId | null,
  suggestions: readonly string[],
): BeaErrorOf<"AddressUnmapped"> => ({
  _tag: "AddressUnmapped",
  operation,
  address: moduleTokenLabel(token),
  module_map_id: moduleMapId,
  message: `No loaded module matches ${moduleTokenLabel(token).slice(0, 120)}.`,
  remediation:
    "Check the module name with list_modules (the module may load later); qualify a duplicate basename with @0x<base> or quote the full path.",
  diagnostics: { reason: "module_not_loaded", token: moduleTokenLabel(token), suggestions: [...suggestions] },
});

export const moduleAmbiguous = (
  operation: string,
  path: string,
  candidates: readonly { readonly name: string; readonly path: string | null; readonly base: bigint }[],
): BeaErrorOf<"InputError"> =>
  inputIssue(
    operation,
    path,
    "invalid_value",
    "Several loaded modules share this name; qualify it with @0x<base> or quote the full path.",
    {
      reason: "module_ambiguous",
      candidates: candidates.map((c) => ({ name: c.name, path: c.path, base: formatHex(c.base) })),
    },
  );

export const rvaOutOfImage = (operation: string, path: string, sizeOfImage: number): BeaErrorOf<"InputError"> =>
  inputIssue(operation, path, "out_of_range", "The RVA is outside the module image (≥ SizeOfImage).", {
    reason: "rva_out_of_image",
    size_of_image: sizeOfImage,
  });

export const staticOutOfImage = (
  operation: string,
  path: string,
  staticBase: bigint,
  sizeOfImage: number,
): BeaErrorOf<"InputError"> =>
  inputIssue(
    operation,
    path,
    "out_of_range",
    "The static VA is outside the module image for this static base; check the Ghidra/REA image base and pass /0xBASE.",
    { reason: "static_out_of_image", static_base: formatHex(staticBase), size_of_image: sizeOfImage },
  );

export const forwarderUnresolved = (operation: string, forwarder: string, moduleMapId: MmId | null): BeaError => ({
  _tag: "AddressUnmapped",
  operation,
  address: forwarder.slice(0, 300),
  module_map_id: moduleMapId,
  message: "The export is forwarded to a module or API set that could not be resolved.",
  remediation: "Load the forwarder's target module first, or address the target module's export directly.",
  diagnostics: { reason: "forwarder_unresolved", forwarder: forwarder.slice(0, 300) },
});
