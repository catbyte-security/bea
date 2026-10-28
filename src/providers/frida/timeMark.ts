import type { Clock } from "../../domain/clock.js";
import type { TimeMark } from "../../domain/time.js";

/** S3 TimeMark: a host-side instant before S2 assigns seq and epochs. */
export const TimeMarkOf = (clock: Clock): TimeMark => ({ monoNs: clock.monoNs().toString(), wall: clock.wallIso() });
