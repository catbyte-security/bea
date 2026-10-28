import type { InputIssue } from "../errors/beaError.js";
import { err, ok, type Result } from "../result.js";

/**
 * FP environment of an oracle/emulated call (CT-I9, D-INT-43; DESIGN §5.3.1 rule 6). Resolution order, field by
 * field: explicit `mxcsr`/`fpcw` > `source:"thread"`/`"auto"` with a KNOWN thread (`fp.thread_id`, else the call's
 * thread_id / thread_at tid / a recording's hook thread) read with captureThreadState > the dump's primary thread
 * (dump-backed emulation, `auto` only) > the Windows default 0x1F80/0x027F (limitation CALL_FP_DEFAULT). MXCSR status
 * bits 0..5 are always cleared. Pure: the caller reads the thread state (an agent RPC) and passes it in, so
 * call_function and diff_function (which resolves ONCE for both legs) share exactly this logic.
 */
export const WINDOWS_DEFAULT_MXCSR = 0x1f80;
export const WINDOWS_DEFAULT_FPCW = 0x027f;
export const MXCSR_STATUS_BITS = 0x3f;

export interface FpRequest {
  readonly source: "auto" | "thread" | "windows-default";
  readonly thread_id?: number | undefined;
  /** "0x…" (≤ 4 hex digits, schema-checked) */
  readonly mxcsr?: string | undefined;
  readonly fpcw?: string | undefined;
}
export interface FpThreadEnv {
  readonly mxcsr: number;
  readonly fpcw: number;
}
/** Same members as ports/emu.ts ResolvedFpEnv (structurally assignable; the domain may not import ports). */
export interface FpEnvResolution {
  readonly mxcsr: number;
  readonly fpcw: number;
  readonly source: "explicit" | "thread" | "dump-thread" | "windows-default";
  readonly threadId: number | null;
  /** limitation keys of area call (CALL_FP_DEFAULT) */
  readonly limitations: readonly "CALL_FP_DEFAULT"[];
}

const explicitOf = (text: string | undefined): number | null => (text === undefined ? null : Number.parseInt(text, 16));

/** The thread whose environment must be read before resolveFpEnv (null: none needed). */
export const fpThreadToRead = (request: FpRequest | undefined, knownThreadId: number | null): number | null => {
  const fp = request ?? { source: "auto" as const };
  if (fp.source === "windows-default") return null;
  if (fp.mxcsr !== undefined && fp.fpcw !== undefined) return null;
  return fp.thread_id ?? knownThreadId;
};

export interface FpObservation {
  /** the thread fpThreadToRead named, with its environment (null when the read failed or nothing was read) */
  readonly threadId: number | null;
  readonly env: FpThreadEnv | null;
  /** dump-backed emulation: the dump's primary thread */
  readonly dumpThread?: FpThreadEnv | null;
}

export const resolveFpEnv = (
  request: FpRequest | undefined,
  observed: FpObservation,
): Result<FpEnvResolution, InputIssue> => {
  const fp = request ?? { source: "auto" as const };
  const mxcsrExplicit = explicitOf(fp.mxcsr);
  const fpcwExplicit = explicitOf(fp.fpcw);
  let base: { mxcsr: number; fpcw: number; source: FpEnvResolution["source"]; threadId: number | null };
  const windows = {
    mxcsr: WINDOWS_DEFAULT_MXCSR,
    fpcw: WINDOWS_DEFAULT_FPCW,
    source: "windows-default" as const,
    threadId: null,
  };
  const bothExplicit = mxcsrExplicit !== null && fpcwExplicit !== null;
  if (fp.source === "windows-default" || bothExplicit) base = windows;
  else if (observed.threadId !== null && observed.env !== null)
    base = { ...observed.env, source: "thread", threadId: observed.threadId };
  else if (fp.source === "thread")
    return err({
      path: "fp.source",
      reason: "invalid_value",
      message:
        observed.threadId === null
          ? 'fp.source "thread" needs fp.thread_id, thread_id or thread_at with a thread id.'
          : "The thread's FP environment could not be read; pass fp.mxcsr/fp.fpcw or use fp.source auto.",
    });
  else if (observed.dumpThread !== undefined && observed.dumpThread !== null)
    base = { ...observed.dumpThread, source: "dump-thread", threadId: null };
  else base = windows;
  const mxcsr = (mxcsrExplicit ?? base.mxcsr) & ~MXCSR_STATUS_BITS & 0xffff;
  const fpcw = (fpcwExplicit ?? base.fpcw) & 0xffff;
  const source = bothExplicit ? "explicit" : base.source;
  return ok({
    mxcsr,
    fpcw,
    source,
    threadId: base.threadId,
    limitations: source === "windows-default" && mxcsrExplicit === null ? ["CALL_FP_DEFAULT"] : [],
  });
};

/** "0x…" display of an FP control word (outputs and evidence). */
export const fpHex = (value: number): `0x${string}` => `0x${value.toString(16)}`;
