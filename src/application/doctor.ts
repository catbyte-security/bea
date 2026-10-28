/**
 * Doctor checks contributed at runtime by service factories (like lifecycle closers and status contributors), so
 * `bea doctor` (WP-CLI) never imports providers. Report shape: S1 §7.8 (bea.doctor/1).
 */
export type DoctorClassification =
  | "healthy"
  | "missing_dependency"
  | "runtime_failure"
  | "unsupported_host"
  | "configuration_invalid"
  | "config_drift"
  | "unknown";
export interface DoctorCheckResult {
  readonly name: string;
  readonly ok: boolean;
  readonly classification: DoctorClassification;
  readonly detail?: string;
  readonly remediation?: string;
}
export interface DoctorCheckDefinition {
  /** e.g. "frida:binding", "jobhost:probe", "emulation:python" */
  readonly name: string;
  readonly scope: "always" | "backend:frida" | "backend:emulation" | "probe" | "informational";
  readonly run: (signal: AbortSignal) => Promise<DoctorCheckResult>;
}
export class DoctorRegistry {
  readonly #checks: DoctorCheckDefinition[] = [];
  add(check: DoctorCheckDefinition): void {
    this.#checks.push(check);
  }
  list(): readonly DoctorCheckDefinition[] {
    return [...this.#checks];
  }
}
