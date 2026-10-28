import type { Addr, AddressRef, Loc } from "../domain/address/addressRef.js";
import type { BeaError } from "../domain/errors/beaError.js";
import type { MmId } from "../domain/ids.js";
import type { Result } from "../domain/result.js";
import type { Hex } from "../shared/hex.js";
import type { LiveSession, OperationContext } from "./sessions.js";

/** CI-I10: S2 §18.3 byte verification of one range (map_address rows, hook_function.bytes_match_file). */
export interface ByteVerification {
  readonly status: "match" | "mismatch" | "partial" | "not-applicable" | "skipped";
  readonly compared: number;
  readonly equal: number;
  readonly excluded_loader: number;
  readonly own_effects_restored: number;
  readonly differences: readonly {
    readonly rva: Hex;
    readonly size: number;
    readonly class: "unexplained" | "foreign-or-agent-patch";
  }[];
}

/**
 * Address resolution for every address-taking tool (S2 §16 + S6 §2.1 AddrExpr). Implemented by
 * src/application/address/AddressService.ts (WP-ADDR) over the PE reader, the module-map tracker and the agent.
 * Input grammar (one string): 0xVA | module+0xRVA | +0xRVA | module!export[+0xN] | module!#ord |
 * module:0xSTATIC_VA[/0xSTATIC_BASE] | $main:… ; module tokens may be quoted and carry @0xRUNTIME_BASE.
 */
export type AddressSpace =
  | { readonly kind: "live"; readonly session: LiveSession }
  | { readonly kind: "emulation"; readonly sessionId: string }
  | { readonly kind: "file"; readonly imagePath: string; readonly runtimeBase: bigint | null };

export interface ResolvedAddress {
  readonly ref: AddressRef;
  /** module map the address was resolved against (live) */
  readonly moduleMapId: MmId | null;
  /** convenience for agent RPCs */
  readonly va: bigint;
}

export interface AddressService {
  /**
   * grammar errors -> invalid_request issue at `path`; resolution errors per S2 §16.2. With `expectedImageSha256`, a
   * module whose on-disk digest differs fails closed: invalid_request with diagnostics {reason:"image_mismatch",
   * expected, actual}; a digest that cannot be computed is not a mismatch (integrator note, WP5 change request).
   */
  resolve(
    space: AddressSpace,
    expr: string,
    op: OperationContext,
    opts?: { readonly path?: string; readonly expectedImageSha256?: string },
  ): Promise<Result<ResolvedAddress, BeaError>>;
  /** grammar-only validation (no session), used by contract refines and scenario pre-validation */
  validate(
    expr: string,
  ): Result<true, { readonly reason: "invalid_format" | "out_of_range"; readonly message: string }>;
  /** VA -> compact forms for rows/frames (module legend handled by the caller) */
  describe(space: AddressSpace, va: bigint): Addr;
  describeCode(space: AddressSpace, va: bigint): Promise<Loc>;
  /** "module+0xrva" text emitted by the agent (backtrace FrameRef) -> Loc */
  fromFrameRef(space: AddressSpace, frame: string): Promise<Loc>;
  /**
   * CI-I10: describe() is synchronous, but `static` needs each module's PREFERRED base from disk. Callers that emit
   * rows call prepare() once per page/summary; describe() returns `static:null` for modules not prepared.
   */
  prepare(space: AddressSpace, vas: readonly bigint[], op: OperationContext): Promise<void>;
  /**
   * Review fix UX-10: the preferred base prepare() (or describeCode) already read for this module path; null when not
   * prepared. Synchronous and cache-only: recording decoders use it for the `static` form of their frames.
   */
  preferredBaseOf?(path: string): bigint | null;
  /** CI-I10 */
  verify(
    space: AddressSpace,
    va: bigint,
    len: number,
    op: OperationContext,
  ): Promise<Result<ByteVerification, BeaError>>;
}
