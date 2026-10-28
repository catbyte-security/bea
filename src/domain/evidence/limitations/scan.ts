/** Limitation sentences of area scan (CI-I5). Owned by WP10-SCAN.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const SCAN_LIMITATIONS = {
  SCAN_SCOPE:
    "Only committed ranges with the requested protection (and module or kind filter) were scanned; BEA's own agent memory is never scanned. No hit says nothing about memory outside those ranges.",
  SCAN_RUNNING: (scanId: string) =>
    `The scan is still running in the target; count and scanned bytes are partial. Wait for it with wait {"ids":["${scanId}"]}.`,
  SCAN_TRUNCATED: (cap: number) =>
    `The scan stopped at its hit cap (${String(cap)}); later matches were not kept. Narrow it with scan_next, or rescan with a narrower type, value or region.`,
  SCAN_CANCELLED: "The scan job was cancelled; its hit list is partial (unexamined candidates were kept).",
  SCAN_FAULTED: (n: number) =>
    `${String(n)} candidate(s) were dropped because their memory page became unreadable since the previous scan.`,
  SCAN_FLOAT_EQUALITY:
    "Float exact compares use IEEE equality (-0 equals +0, NaN never matches) unless the value is given as 0x… bits.",
  SCAN_STORED_VALUES:
    "values:false: value is null and prev is the value stored by the last scan; current memory was not read.",
  SCAN_VALUE_UNREADABLE: (n: number) =>
    `${String(n)} hit(s) could not be read now (their page is gone or unreadable); their value is null.`,
  SCAN_HOST_STORE:
    "The target has exited; rows come from BEA's host hit store of the last scan iteration and carry no current values.",
  SCAN_SNAPSHOT:
    "An unknown-value scan holds a snapshot of the scanned memory in the target; narrow it with scan_next before paging hits.",
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
