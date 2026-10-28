import type { Authority, Confidence } from "./record.js";

/**
 * The closed predicate registry (S2 §7.3, extended with S5 §11.1 and the crash/dump/list predicates the final
 * catalog records). The Recorder refuses an unregistered predicate. `owner` is the WP that produces it.
 */
export interface PredicateSpec {
  readonly subjects: readonly ("process-instance" | "image" | "emulation" | "none")[];
  readonly confidence: Confidence | "per-call";
  readonly authority: Authority | "weakest-parent" | "per-call";
  readonly anchor: "required" | "none" | "per-call";
  readonly untrusted: boolean;
  /** JSON-pointer patterns of hex/base64 byte fields in `result` (redaction scans them as bytes). */
  readonly byteFields: readonly string[];
  readonly linkless?: true;
  readonly owner:
    | "WP-EVID"
    | "WP-ADDR"
    | "WP-SESS"
    | "WP-INSPECT"
    | "WP-SCAN"
    | "WP-HOOK"
    | "WP-BEHAVIOR"
    | "WP-WATCH"
    | "WP-CALL"
    | "WP-MODIFY"
    | "WP-DUMP"
    | "WP-EMU";
}

const live = {
  subjects: ["process-instance"],
  confidence: "observed",
  authority: "live-process",
  anchor: "required",
  untrusted: true,
} as const;

export const PREDICATES = {
  "bea.process.instance": { ...live, byteFields: [], owner: "WP-SESS" },
  "bea.process.exit": { ...live, byteFields: [], owner: "WP-SESS" },
  "bea.exception.report": { ...live, byteFields: ["/stack/hex", "/instruction/bytes"], owner: "WP-SESS" },
  "bea.process.crash": {
    subjects: ["process-instance"],
    confidence: "derived",
    authority: "weakest-parent",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    owner: "WP-SESS",
  },
  "bea.session.status": { ...live, byteFields: [], owner: "WP-SESS" },
  "bea.modules.map": { ...live, untrusted: false, byteFields: [], owner: "WP-EVID" },
  "bea.modules.list": { ...live, byteFields: [], owner: "WP-INSPECT" },
  "bea.image.pe": {
    subjects: ["image"],
    confidence: "observed",
    authority: "static-artifact",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    owner: "WP-ADDR",
  },
  "bea.symbols.module": {
    subjects: ["image", "process-instance"],
    confidence: "per-call",
    authority: "static-artifact",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    owner: "WP-ADDR",
  },
  "bea.symbols.caller": {
    subjects: ["image"],
    confidence: "inferred",
    authority: "per-call",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    linkless: true,
    owner: "WP-ADDR",
  },
  "bea.address.map": {
    subjects: ["process-instance", "image", "emulation"],
    confidence: "per-call",
    authority: "weakest-parent",
    anchor: "per-call",
    untrusted: true,
    byteFields: ["/rows/*/verify/differences/*/live_hex"],
    owner: "WP-ADDR",
  },
  "bea.memory.ranges": { ...live, byteFields: [], owner: "WP-INSPECT" },
  "bea.threads.list": { ...live, byteFields: [], owner: "WP-INSPECT" },
  "bea.memory.read": { ...live, byteFields: ["/data"], owner: "WP-INSPECT" },
  "bea.code.disassembly": {
    subjects: ["process-instance", "emulation", "image"],
    confidence: "observed",
    authority: "per-call",
    anchor: "per-call",
    untrusted: true,
    byteFields: ["/rows/*/b"],
    owner: "WP-INSPECT",
  },
  "bea.memory.write": { ...live, byteFields: ["/before_hex", "/after_hex"], owner: "WP-MODIFY" },
  "bea.memory.dump": { ...live, byteFields: [], owner: "WP-DUMP" },
  "bea.dump.capture": { ...live, byteFields: [], owner: "WP-DUMP" },
  "bea.scan.result": { ...live, byteFields: [], owner: "WP-SCAN" },
  "bea.instrument.install": { ...live, byteFields: [], owner: "WP-HOOK" },
  "bea.instrument.stop": { ...live, byteFields: [], owner: "WP-HOOK" },
  "bea.stream.manifest": { ...live, byteFields: [], owner: "WP-EVID" },
  "bea.events.query": {
    subjects: ["process-instance", "emulation"],
    confidence: "derived",
    authority: "weakest-parent",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    owner: "WP-HOOK",
  },
  "bea.coverage.export": {
    subjects: ["process-instance", "emulation"],
    confidence: "derived",
    authority: "weakest-parent",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    owner: "WP-WATCH",
  },
  "bea.call.oracle": { ...live, byteFields: [], owner: "WP-CALL" },
  "bea.script.run": { ...live, byteFields: [], owner: "WP-MODIFY" },
  "bea.emu.session": {
    subjects: ["emulation"],
    confidence: "observed",
    authority: "emulation",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    owner: "WP-EMU",
  },
  "bea.emu.run": {
    subjects: ["emulation"],
    confidence: "observed",
    authority: "emulation",
    anchor: "per-call",
    untrusted: true,
    byteFields: [],
    owner: "WP-EMU",
  },
  "bea.emu.batch": {
    subjects: ["emulation"],
    confidence: "observed",
    authority: "emulation",
    anchor: "per-call",
    untrusted: true,
    byteFields: [],
    owner: "WP-EMU",
  },
  "bea.emu.sweep": {
    subjects: ["emulation"],
    confidence: "observed",
    authority: "emulation",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    owner: "WP-EMU",
  },
  "bea.emu.memory.read": {
    subjects: ["emulation"],
    confidence: "observed",
    authority: "emulation",
    anchor: "per-call",
    untrusted: true,
    byteFields: ["/data"],
    owner: "WP-EMU",
  },
  "bea.diff": {
    subjects: ["process-instance", "emulation"],
    confidence: "derived",
    authority: "weakest-parent",
    anchor: "none",
    untrusted: true,
    byteFields: [],
    owner: "WP-EMU",
  },
  "bea.unknown.mutation": {
    subjects: ["none"],
    confidence: "derived",
    authority: "analyst-inference",
    anchor: "none",
    untrusted: false,
    byteFields: [],
    linkless: true,
    owner: "WP-EVID",
  },
} as const satisfies Record<string, PredicateSpec>;

export type PredicateType = keyof typeof PREDICATES;
export const isPredicateType = (value: string): value is PredicateType => Object.hasOwn(PREDICATES, value);
