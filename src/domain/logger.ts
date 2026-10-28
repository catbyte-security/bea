import { systemClock, type Clock } from "./clock.js";
import type { LogLevel } from "./config.js";
import type { JsonValue } from "./json.js";

/**
 * JSON-lines logger on stderr. stdout is the stdio JSON-RPC channel and the CLI
 * result channel, so nothing here may ever write to stdout. Policy: log tool name,
 * duration and outcome code only; never caller input, target bytes or tokens.
 */
export interface Logger {
  readonly level: LogLevel;
  readonly error: (msg: string, fields?: LogFields) => void;
  readonly warn: (msg: string, fields?: LogFields) => void;
  readonly info: (msg: string, fields?: LogFields) => void;
  readonly debug: (msg: string, fields?: LogFields) => void;
  readonly child: (bindings: LogFields) => Logger;
}

export type LogFields = Readonly<Record<string, JsonValue | Error | undefined>>;

const RANK: { readonly [L in LogLevel]: number } = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };
const MAX_STRING = 2048;

const safe = (value: JsonValue | Error | undefined): JsonValue | undefined => {
  if (value === undefined) return undefined;
  if (value instanceof Error) return { name: value.name, message: value.message.slice(0, MAX_STRING) };
  if (typeof value === "string") return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  return value;
};

export interface LoggerOptions {
  readonly level: LogLevel;
  readonly write?: (line: string) => void;
  readonly clock?: Clock;
  readonly bindings?: LogFields;
}

export const createLogger = (options: LoggerOptions): Logger => {
  const write = options.write ?? ((line: string) => void process.stderr.write(line));
  const clock = options.clock ?? systemClock;
  const bindings = options.bindings ?? {};
  const emit =
    (level: Exclude<LogLevel, "silent">) =>
    (msg: string, fields: LogFields = {}): void => {
      if (RANK[options.level] < RANK[level]) return;
      const record: Record<string, JsonValue> = { t: clock.wallIso(), level, msg };
      for (const source of [bindings, fields])
        for (const [key, value] of Object.entries(source)) {
          const projected = safe(value);
          if (projected !== undefined && !(key in record)) record[key] = projected;
        }
      try {
        write(`${JSON.stringify(record)}\n`);
      } catch {
        // Logging never fails an operation.
      }
    };
  return {
    level: options.level,
    error: emit("error"),
    warn: emit("warn"),
    info: emit("info"),
    debug: emit("debug"),
    child: (more) => createLogger({ ...options, bindings: { ...bindings, ...more } }),
  };
};

export const silentLogger: Logger = createLogger({ level: "silent", write: () => undefined });
