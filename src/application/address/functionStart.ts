import type { BeaErrorOf } from "../../domain/errors/beaError.js";
import type { AddressService, AddressSpace } from "../../ports/address.js";
import { inputIssue } from "./resolveErrors.js";

/**
 * Review fix UX-1: entry-style instruments (hook_function without probe, trace_execution on_call, override_function)
 * attach an Interceptor listener whose onLeave swaps *[rsp] for Frida's return trampoline. At a function start [rsp]
 * is the return address; inside a function body it is whatever the prologue pushed (a saved register, a local), so
 * the swap corrupts the target while the tool reports success. The enclosing `.pdata` function is the evidence: an
 * address inside a known function but not at its primary start is refused before anything is installed. Leaf code
 * without unwind data, non-module memory and unreadable images are not refused (leaf functions never move rsp, so
 * [rsp] stays the return address there).
 */
export interface FunctionInterior {
  /** "module+0xRVA" of the enclosing function's primary start (pasteable as an AddrExpr) */
  readonly start: string;
  /** bytes from that start to the address (negative for a chained fragment placed before it) */
  readonly offset: number;
}

const rvaOf = (text: string): number | null => {
  const at = text.lastIndexOf("+0x");
  if (at < 0) return null;
  const value = Number.parseInt(text.slice(at + 3), 16);
  return Number.isFinite(value) ? value : null;
};

/** The enclosing `.pdata` function when `va` lies inside it but not at its start; null otherwise. */
export const functionInterior = async (
  address: AddressService,
  space: AddressSpace,
  va: bigint,
): Promise<FunctionInterior | null> => {
  const loc = await address.describeCode(space, va);
  if (loc.func === null || loc.at === null || loc.func === loc.at) return null;
  const start = rvaOf(loc.func);
  const here = rvaOf(loc.at);
  if (start === null || here === null || start === here) return null;
  return { start: loc.func, offset: here - start };
};

/** invalid_request at `path`: the address is inside a function; names its start and the probe alternative. */
export const notFunctionStart = (
  operation: string,
  path: string,
  interior: FunctionInterior,
  alternative: string,
): BeaErrorOf<"InputError"> =>
  inputIssue(
    operation,
    path,
    "invalid_value",
    `The address is ${interior.offset < 0 ? "in a fragment of" : `${String(interior.offset)} bytes into`} the function that starts at ${interior.start}; an entry-style instrument there would overwrite the stack slot it takes for the return address and corrupt the target. Use ${interior.start}${alternative}.`,
    { reason: "not_function_start", function_start: interior.start, offset: interior.offset },
  );
