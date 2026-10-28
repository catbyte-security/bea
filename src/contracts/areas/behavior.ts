import { z } from "zod";

import { fx } from "../effects.js";
import { recordedOutput } from "../schemas/envelope.js";
import { maxEventsSchema, sessionIdSchema } from "../schemas/primitives.js";
import { instrumentStateSchema, lifetimeShape } from "../schemas/shared.js";
import { defineTool, type ToolContract } from "../toolContract.js";

/** Area behavior (WP-BEHAVIOR): trace_api (S6 §4.21 + DESIGN §6.2 #22). */

const API_PROFILE_NAMES = ["file", "registry", "network", "process", "module_load", "memory_protection"] as const;

const traceApiInput = z
  .strictObject({
    session_id: sessionIdSchema,
    profiles: z
      .array(z.enum(API_PROFILE_NAMES))
      .min(1)
      .max(6)
      .describe("Profiles to trace: file, registry, network, process, module_load, memory_protection."),
    include_failed: z
      .boolean()
      .default(true)
      .describe("Record failed calls too (probes such as STATUS_OBJECT_NAME_NOT_FOUND matter)."),
    caller: z.boolean().default(true).describe("Report the first caller outside system modules."),
    backtrace: z.number().int().min(0).max(16).default(0).describe("Backtrace frames per event (0..16)."),
    duration_ms: lifetimeShape.duration_ms,
    max_events: maxEventsSchema(10_000_000, 200_000),
    wait_ms: lifetimeShape.wait_ms,
  })
  .refine((v) => new Set(v.profiles).size === v.profiles.length, {
    message: 'profiles must be unique. Example: {"profiles":["file","registry"]}',
    path: ["profiles"],
  });

const traceApiOutput = recordedOutput({
  instrument: instrumentStateSchema,
  hooks_installed: z.number().int().min(0).max(1024),
  /** catalog APIs in modules that are not loaded yet; installed when the module loads */
  hooks_pending: z.number().int().min(0).max(1024),
  hooks_failed: z.array(z.strictObject({ api: z.string().max(128), reason: z.string().max(64) })).max(64),
});

export const BEHAVIOR_TOOLS = [
  defineTool({
    name: "trace_api",
    area: "behavior",
    phase: "P1",
    title: "Trace API",
    description:
      "Trace what the program touches using predefined typed Win32/NT API profiles: file, registry, network, process, module_load, memory_protection. Decodes paths, keys, endpoints, command lines, statuses and byte counts into one recording whose summary lists behavior per profile (query_events view summary). Install before resume_process to see startup. Observation only; BEA/Frida's own threads are filtered out.",
    inputSchema: traceApiInput,
    outputSchema: traceApiOutput,
    effects: fx({ instrumentsTarget: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "instrument-oneshot", command: "trace-api", positional: [] },
    evidence: { predicate: "bea.instrument.install", recorded: "always", identityExclude: ["wait_ms"] },
    errors: ["instrumentation_failed", "resource_constraint", "target_exited", "capability_unavailable"],
    maxBlockingMs: 90_000,
    examples: [
      {
        title: "Trace file and registry activity of a paused target before resume",
        input: { session_id: "3f2b8c1e-5d4a-4e6b-9c7d-1a2b3c4d5e6f", profiles: ["file", "registry"] },
      },
      {
        title: "Everything for 30 s",
        input: {
          session_id: "3f2b8c1e-5d4a-4e6b-9c7d-1a2b3c4d5e6f",
          profiles: ["file", "registry", "network", "process", "module_load", "memory_protection"],
          duration_ms: 30_000,
        },
      },
    ],
  }),
] as const satisfies readonly ToolContract[];
