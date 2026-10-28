import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

import { z } from "zod";

import type { BeaError, BeaErrorOf } from "../domain/errors/beaError.js";
import { inputError } from "../domain/errors/constructors.js";
import { isJsonObject } from "../domain/json.js";
import { err, ok, type Result } from "../domain/result.js";
import type { DerivedCommand, ParsedCommand } from "./argv.js";
import type { CliHost } from "./io.js";

type FileError = BeaErrorOf<"FileOperationFailed">;

const fsReason = (cause: unknown): FileError["reason"] => {
  const code = typeof cause === "object" && cause !== null ? Reflect.get(cause, "code") : undefined;
  if (code === "ENOENT" || code === "ENOTDIR") return "missing";
  if (code === "EACCES" || code === "EPERM") return "permission";
  if (code === "EISDIR") return "not-file";
  return "io";
};

const fileError = (operation: string, path: string, reason: FileError["reason"]): FileError => ({
  _tag: "FileOperationFailed",
  operation,
  file_operation: "read",
  path,
  reason,
});

/**
 * Reads a file the user named on the command line ("-" = stdin), at most `maxBytes`. Larger inputs are refused before
 * they are read in full (an `out_of_range` issue at `field`), so a mistaken path to a large binary costs nothing.
 */
export const readCliFile = async (
  host: CliHost,
  operation: string,
  field: string,
  path: string,
  maxBytes: number,
): Promise<Result<Buffer, BeaError>> => {
  const tooLarge = (): Result<never, BeaError> =>
    err(
      inputError(operation, [
        {
          path: field,
          reason: "out_of_range",
          message: `${path === "-" ? "stdin" : path} is larger than ${String(maxBytes)} bytes, the limit for ${field}.`,
          maximum: maxBytes,
        },
      ]),
    );
  if (path === "-") {
    const bytes = await host.readStdin(maxBytes);
    return bytes === null ? tooLarge() : ok(bytes);
  }
  const absolute = resolve(host.cwd, path);
  try {
    const info = await stat(absolute);
    if (!info.isFile()) return err(fileError(operation, absolute, "not-file"));
    if (info.size > maxBytes) return tooLarge();
    return ok(await readFile(absolute));
  } catch (cause: unknown) {
    return err(fileError(operation, absolute, fsReason(cause)));
  }
};

/** `--input FILE|-`: a JSON object, at most the contract's maxInputBytes. */
export const readInputDocument = async (
  host: CliHost,
  operation: string,
  path: string,
  maxBytes: number,
): Promise<Result<Record<string, unknown>, BeaError>> => {
  const bytes = await readCliFile(host, operation, "--input", path, maxBytes);
  if (!bytes.ok) return bytes;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.value.toString("utf8").replace(/^﻿/u, ""));
  } catch {
    return err({ ...fileError(operation, path === "-" ? "-" : resolve(host.cwd, path), "invalid-json") });
  }
  if (!isJsonObject(parsed))
    return err(
      inputError(operation, [
        { path: "--input", reason: "invalid_type", message: "--input must contain a JSON object.", expected: "object" },
      ]),
    );
  return ok({ ...parsed });
};

/** The JSON Schema maxLength of a string field (fileFields are read up to it). */
const maxLengthOf = (command: DerivedCommand, field: string): number | undefined => {
  const schema = z.toJSONSchema(command.contract.inputSchema, {
    io: "input",
    target: "draft-2020-12",
    unrepresentable: "any",
  }) as { readonly properties?: Readonly<Record<string, { readonly maxLength?: number }>> };
  return schema.properties?.[field]?.maxLength;
};

/**
 * The raw tool input of one generated command: `--input` document, then the shorthand fragment, then flags and
 * positionals, then the CI-I11 file fields (read here; never a global `@file` convention). Later sources win.
 */
export const assembleInput = async (
  host: CliHost,
  command: DerivedCommand,
  parsed: ParsedCommand,
  shorthand: Readonly<Record<string, unknown>>,
): Promise<Result<Record<string, unknown>, BeaError>> => {
  const operation = command.contract.name;
  const stdinUsers = [
    ...(parsed.inputFile === "-" ? ["--input"] : []),
    ...parsed.fileInputs.filter((f) => f.path === "-").map((f) => f.field),
  ];
  if (stdinUsers.length > 1)
    return err(
      inputError(operation, [
        {
          path: stdinUsers.join("|"),
          reason: "conflicting_arguments",
          message: `Only one argument may read stdin ("-"); got ${stdinUsers.join(" and ")}.`,
        },
      ]),
    );
  let base: Record<string, unknown> = {};
  if (parsed.inputFile !== null) {
    const document = await readInputDocument(host, operation, parsed.inputFile, command.contract.maxInputBytes);
    if (!document.ok) return document;
    base = document.value;
  }
  const input: Record<string, unknown> = { ...base, ...shorthand, ...parsed.input };
  for (const file of parsed.fileInputs) {
    const limit = Math.min(
      command.contract.maxInputBytes,
      // A UTF-8 character is at most 4 bytes; zod then enforces the exact character limit.
      (maxLengthOf(command, file.field) ?? command.contract.maxInputBytes) * 4,
    );
    const bytes = await readCliFile(host, operation, file.field, file.path, limit);
    if (!bytes.ok) return bytes;
    input[file.field] = bytes.value.toString("utf8").replace(/^﻿/u, "");
  }
  return ok(input);
};
