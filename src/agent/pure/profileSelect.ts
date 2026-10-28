// Catalog selection for profileInstall (S4 §10.6 Install step 1) and the memory-map diff of the memmap watcher
// (S4 §10.7). Pure.
import type { ApiProfileName, ProfileOptions } from "../../shared/agentProtocol.js";
import { API_CATALOG, HOOK_DENY_LIST, apiName, type ApiSpec, type ApiSub } from "../../shared/apiProfiles.js";
import type { Hex } from "../../shared/hex.js";

const subOption = (options: ProfileOptions, profile: ApiProfileName, sub: ApiSub): boolean | undefined => {
  switch (sub) {
    case "io":
      return options.file?.io;
    case "track_handles":
      return options.file?.track_handles;
    case "query_key":
      return profile === "registry" ? options.registry?.query_key : undefined;
    case "enumerate":
      return options.registry?.enumerate;
    case "dns":
      return options.network?.dns;
    case "http":
      return options.network?.http;
    case "cross_process_memory":
      return options.process?.cross_process_memory;
    case "apc_and_context":
      return options.process?.apc_and_context;
    case "resolve_procedures":
      return options.module_load?.resolve_procedures;
    case "frees":
      return options.memory_protection?.frees;
    case "sections":
      return options.memory_protection?.sections;
    case "core":
      return true;
  }
};

export interface Selection {
  readonly specs: readonly ApiSpec[];
  readonly denied: readonly { readonly api: string; readonly reason: string }[];
}

/** Entries of the selected profiles: core always, other subs per option (else default_on). NtClose (handle
 *  tracking) comes in with file or registry unless file.track_handles is false. Deny-listed names never pass. */
export const selectApis = (profiles: readonly ApiProfileName[], options: ProfileOptions): Selection => {
  const wanted = new Set(profiles);
  const deny = new Map(HOOK_DENY_LIST.map((d) => [d.api.toLowerCase(), d.reason]));
  const specs: ApiSpec[] = [];
  const denied: { api: string; reason: string }[] = [];
  for (const spec of API_CATALOG) {
    let on: boolean;
    if (spec.sub === "track_handles")
      on = (wanted.has("file") || wanted.has("registry")) && (options.file?.track_handles ?? spec.default_on);
    else if (!wanted.has(spec.profile)) on = false;
    else on = subOption(options, spec.profile, spec.sub) ?? spec.default_on;
    if (!on) continue;
    const reason = deny.get(apiName(spec).toLowerCase());
    if (reason !== undefined) denied.push({ api: apiName(spec), reason });
    else specs.push(spec);
  }
  return { specs, denied };
};

// ---------------------------------------------------------------------------------------------- memmap
export interface RangeView {
  readonly base: Hex;
  readonly size: number;
  /** Frida protection text, "rwx" style */
  readonly protection: string;
  readonly module: string | null;
}
export interface MemmapEvent {
  readonly ev: "new-exec" | "new-rwx" | "gone" | "prot-change";
  readonly base: Hex;
  readonly size: number;
  readonly protection: string;
  readonly module: string | null;
}

/**
 * One watcher tick (S4 §10.7): `current` = executable ranges now. New non-module regions → new-exec/new-rwx;
 * tracked regions that left the executable set → prot-change (still mapped, per `lookup`) or gone; tracked regions
 * whose protection or size changed → prot-change. Mutates `tracked` to the new state. Module ranges are ignored.
 */
export const diffExecRanges = (
  tracked: Map<Hex, RangeView>,
  current: readonly RangeView[],
  lookup: (base: Hex) => RangeView | null,
): MemmapEvent[] => {
  const events: MemmapEvent[] = [];
  const seen = new Set<Hex>();
  for (const r of current) {
    if (r.module !== null) continue;
    seen.add(r.base);
    const before = tracked.get(r.base);
    if (before === undefined) {
      events.push({ ...r, ev: r.protection.includes("w") ? "new-rwx" : "new-exec" });
      tracked.set(r.base, r);
    } else if (before.protection !== r.protection || before.size !== r.size) {
      events.push({ ...r, ev: "prot-change" });
      tracked.set(r.base, r);
    }
  }
  for (const [base, before] of [...tracked]) {
    if (seen.has(base)) continue;
    tracked.delete(base);
    const now = lookup(base);
    if (now !== null && now.base === base) events.push({ ...now, ev: "prot-change" });
    else events.push({ ...before, ev: "gone" });
  }
  return events;
};
