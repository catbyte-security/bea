// =================================================================================================
// src/domain/jobhostProtocol.ts — bea-jobhost protocol 1 status lines (S3 §5.2, verbatim). 64-bit values are
// decimal strings. A line that fails this schema is a protocol violation (the wrapper kills the helper).
// =================================================================================================
import { z } from "zod";
const u32 = z.number().int().min(0).max(0xffff_ffff);
const dec64 = z.string().regex(/^\d{1,20}$/u);
const jobPolicy = z.strictObject({
  killOnClose: z.literal(true),
  dieOnUnhandledException: z.literal(true),
  breakawayAllowed: z.literal(false),
  memLimitBytes: z.number().int().positive().nullable(),
});
/** One GetProcessMitigationPolicy read: the policy's DWORD of flags, or null with the Win32 error when the read failed. */
const mitigationRead = z.strictObject({ flags: u32.nullable(), win32: u32 });
/**
 * `inspect.mitigations` (BEA-FEEDBACK item 1; protocol 1, additive): raw flags of the four policies the helper reads.
 * `access`: the inspect handle (PROCESS_QUERY_LIMITED_INFORMATION) or a second PROCESS_QUERY_INFORMATION handle opened
 * because the first was refused. Optional on the wire so a helper built before the field still parses (unknown).
 */
const mitigationsWire = z.strictObject({
  access: z.enum(["limited", "query"]),
  signature: mitigationRead,
  dynamicCode: mitigationRead,
  userShadowStack: mitigationRead,
  imageLoad: mitigationRead,
});
export type MitigationsWire = z.infer<typeof mitigationsWire>;
const inspectFields = {
  pid: u32,
  access: z.enum(["limited", "limited+synchronize"]),
  exited: z.boolean().nullable(),
  exitCode: u32.nullable(),
  creationTime100ns: dec64.nullable(),
  imagePath: z.string().nullable(),
  parentPid: u32.nullable(),
  sessionId: u32.nullable(),
  critical: z.boolean().nullable(),
  protectionLevel: u32.nullable(),
  protected: z.boolean().nullable(),
  wow64: z.boolean().nullable(),
  processMachine: u32.nullable(),
  nativeMachine: u32.nullable(),
  inJob: z.boolean().nullable(),
  elevated: z.boolean().nullable(),
  integrityRid: u32.nullable(),
  sameUser: z.boolean().nullable(),
  mitigations: mitigationsWire.optional(),
};
export const jobHostErrorStage = z.enum([
  "usage",
  "open",
  "identity",
  "job-create",
  "job-policy",
  "job-port",
  "assign",
  "membership",
  "create",
  "resume",
  "control",
  "status",
]);
export const jobHostEventSchema = z.discriminatedUnion("event", [
  z.strictObject({
    event: z.literal("hello"),
    protocol: z.literal(1),
    version: z.string(),
    mode: z.enum(["none", "adopt", "spawn", "watch", "inspect", "probe", "version"]),
    helperPid: u32,
    helperInJob: z.boolean(),
    statusFd3: z.boolean(),
  }),
  z.strictObject({
    event: z.literal("adopted"),
    pid: u32,
    creationTime100ns: dec64,
    wasInJob: z.boolean(),
    imagePath: z.string().nullable(),
    active: u32,
    policy: jobPolicy,
  }),
  z.strictObject({
    event: z.literal("started"),
    pid: u32,
    tid: u32,
    creationTime100ns: dec64,
    suspended: z.boolean(),
    imagePath: z.string().nullable(),
    policy: jobPolicy,
  }),
  z.strictObject({
    event: z.literal("watching"),
    pid: u32,
    creationTime100ns: dec64,
    imagePath: z.string().nullable(),
  }),
  z.strictObject({ event: z.literal("resumed"), previousSuspendCount: u32 }),
  z.strictObject({ event: z.literal("proc-start"), pid: u32 }),
  z.strictObject({ event: z.literal("proc-exit"), pid: u32, abnormal: z.boolean() }),
  z.strictObject({ event: z.literal("proc-events-truncated"), limit: u32 }),
  z.strictObject({ event: z.literal("memory-limit"), pid: u32 }),
  z.strictObject({
    event: z.literal("root-exit"),
    pid: u32,
    code: u32,
    codeHex: z.string(),
    activeAfterRoot: u32.nullable(),
    byKill: z.boolean(),
  }),
  z.strictObject({
    event: z.literal("killed"),
    reason: z.enum(["control", "eof", "root-exit-policy"]),
    activeBefore: u32,
    ok: z.boolean(),
    win32: u32,
  }),
  z.strictObject({
    event: z.literal("settled"),
    active: u32,
    timedOut: z.boolean(),
    peakJobMemoryBytes: z.number().int().nonnegative(),
    elapsedMs: u32,
  }),
  z.strictObject({ event: z.literal("status"), rootAlive: z.boolean(), active: u32, elapsedMs: u32 }),
  z.strictObject({ event: z.literal("watch-ended"), reason: z.literal("eof") }),
  z.strictObject({ event: z.literal("inspect"), ...inspectFields }),
  z.strictObject({
    event: z.literal("probe"),
    ok: z.boolean(),
    jobPolicyVerified: z.boolean(),
    jobListAttribute: z.boolean(),
    assignedBeforeFirstInstruction: z.boolean(),
    adoptAssign: z.boolean(),
    terminateJob: z.boolean(),
    helperInJob: z.boolean(),
    statusFd3: z.boolean(),
  }),
  z.strictObject({
    event: z.literal("error"),
    stage: jobHostErrorStage,
    win32: u32,
    detail: z.string(),
    expected: dec64.optional(),
    actual: dec64.optional(),
    wasInJob: z.boolean().optional(),
  }),
]);
export type JobHostEvent = z.infer<typeof jobHostEventSchema>;

// ------------------------------------------------- decoded `inspect.mitigations` (ProcessInspection.mitigations)
// Bit layouts are the Windows SDK's (winnt.h PROCESS_MITIGATION_*_POLICY); `flags` keeps the raw DWORD, so bits this
// release does not name stay visible. Decoded by src/providers/process/ProcessInspector.ts.

/** ProcessSignaturePolicy (Code Integrity Guard): which signers an image needs to load. */
export interface SignaturePolicy {
  readonly flags: number;
  readonly microsoftSignedOnly: boolean;
  readonly storeSignedOnly: boolean;
  /** set alongside MicrosoftSignedOnly by a runtime opt-in; alone it does not block unsigned images (lab) */
  readonly mitigationOptIn: boolean;
  readonly auditMicrosoftSignedOnly: boolean;
  readonly auditStoreSignedOnly: boolean;
}
/** ProcessDynamicCodePolicy (Arbitrary Code Guard): no new executable memory, no changes to code pages. */
export interface DynamicCodePolicy {
  readonly flags: number;
  readonly prohibitDynamicCode: boolean;
  readonly allowThreadOptOut: boolean;
  readonly allowRemoteDowngrade: boolean;
  readonly auditProhibitDynamicCode: boolean;
}
/** ProcessUserShadowStackPolicy (hardware-enforced stack protection, CET). */
export interface UserShadowStackPolicy {
  readonly flags: number;
  readonly enableUserShadowStack: boolean;
  readonly auditUserShadowStack: boolean;
  readonly setContextIpValidation: boolean;
  readonly auditSetContextIpValidation: boolean;
  readonly enableUserShadowStackStrictMode: boolean;
  readonly blockNonCetBinaries: boolean;
  readonly blockNonCetBinariesNonEhcont: boolean;
  readonly auditBlockNonCetBinaries: boolean;
  readonly cetDynamicApisOutOfProcOnly: boolean;
  readonly setContextIpValidationRelaxedMode: boolean;
}
/** ProcessImageLoadPolicy: where images may load from. */
export interface ImageLoadPolicy {
  readonly flags: number;
  readonly noRemoteImages: boolean;
  readonly noLowMandatoryLabelImages: boolean;
  readonly preferSystem32Images: boolean;
  readonly auditNoRemoteImages: boolean;
  readonly auditNoLowMandatoryLabelImages: boolean;
}
export type MitigationPolicyName = keyof Omit<MitigationsWire, "access">;
/**
 * The target's mitigation policies as read by `bea-jobhost inspect`. A policy that could not be read is null (unknown,
 * never guessed) and listed in `unreadable` with GetLastError (for example ERROR_INVALID_PARAMETER for a policy the
 * Windows build does not know).
 */
export interface ProcessMitigations {
  readonly access: MitigationsWire["access"];
  readonly signature: SignaturePolicy | null;
  readonly dynamicCode: DynamicCodePolicy | null;
  readonly userShadowStack: UserShadowStackPolicy | null;
  readonly imageLoad: ImageLoadPolicy | null;
  readonly unreadable: readonly { readonly policy: MitigationPolicyName; readonly win32: number }[];
}
