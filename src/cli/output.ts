import { encode } from "@toon-format/toon";

import type { BeaError } from "../domain/errors/beaError.js";
import { projectBeaError } from "../domain/errors/projection.js";

export const EXIT = { ok: 0, failed: 1, sigint: 130, sigterm: 143, sigpipe: 141 } as const;

/**
 * stdout carries exactly one document: the result or {"error": projection}.
 * TOON by default (VERIFIED round trip incl. Windows paths); --json is
 * indented on a TTY and compact when piped. Progress/logs go to stderr.
 */
export const renderDocument = (value: unknown, format: "toon" | "json", stdoutIsTty: boolean): string =>
  format === "toon"
    ? `${encode(value)}\n`
    : `${stdoutIsTty ? JSON.stringify(value, null, 2) : JSON.stringify(value)}\n`;

export const renderError = (error: BeaError, format: "toon" | "json", stdoutIsTty: boolean): string =>
  renderDocument({ error: projectBeaError(error) }, format, stdoutIsTty);

/** JSON-lines progress on stderr, opt-in per command (--progress), always on for `bea run`. */
export const progressLine = (tool: string, sequence: number, phase: string, message: string): string =>
  `${JSON.stringify({ bea_progress: { tool, seq: sequence, phase, message } })}\n`;
