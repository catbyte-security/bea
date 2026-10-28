import type { RecordingKind, RecordingKindSpec } from "../../../ports/recordings.js";
import { API_KIND } from "./api.js";
import { EXCEPTIONS_KIND } from "./exceptions.js";
import { HOOK_KIND } from "./hook.js";
import { MODULES_KIND } from "./modules.js";
import { OUTPUT_KIND } from "./output.js";
import { OVERRIDE_KIND } from "./override.js";
import { POLL_KIND } from "./poll.js";
import { TRACE_KIND } from "./trace.js";
import { WATCH_KIND } from "./watch.js";

/** PRE-WIRED recording-kind registry (WP0; never edited later). A null entry means the kind is not implemented yet. */
export const RECORDING_KINDS: { readonly [K in RecordingKind]: RecordingKindSpec | null } = {
  hook: HOOK_KIND,
  api: API_KIND,
  watch: WATCH_KIND,
  poll: POLL_KIND,
  trace: TRACE_KIND,
  override: OVERRIDE_KIND,
  exceptions: EXCEPTIONS_KIND,
  modules: MODULES_KIND,
  output: OUTPUT_KIND,
};
