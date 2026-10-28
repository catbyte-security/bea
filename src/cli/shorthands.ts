import type { ToolContract } from "../contracts/toolContract.js";
import type { BeaErrorOf, InputIssue } from "../domain/errors/beaError.js";
import { inputError } from "../domain/errors/constructors.js";
import { err, ok, type Result } from "../domain/result.js";
import { REGISTERS, VALUE_TYPES } from "../contracts/schemas/shared.js";

/** What a shorthand expansion hands back to the CLI router (WP-CLI). */
export interface ShorthandExpansion {
  /** argv with every shorthand flag removed (what parseCommandArgs receives) */
  readonly argv: readonly string[];
  /** input fields produced by the shorthands; merged over --input FILE and under explicit flags */
  readonly input: Readonly<Record<string, unknown>>;
}

/** One hook_function capture as the shorthand produces it (S6 §5.1 CaptureSpec). */
export interface CaptureShorthand {
  readonly name?: string;
  readonly arg?: number;
  readonly reg?: string;
  readonly type: string;
  readonly deref?: readonly number[];
  readonly when?: "enter" | "leave" | "both";
}

const CAPTURE_FLAG = "--capture";
export const CAPTURE_GRAMMAR =
  'name=argN:type[+0xOFF…][@leave|@both] or name=reg:type, e.g. --capture "speed=arg0:f32+0x8@both" --capture "x=xmm1:f32"';

const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,31}$/u;
const OFFSET = /([+-])(0x[0-9a-fA-F]+|\d+)/gu;

/** Parse one `--capture` value (S6 §8.1). Returns the capture or a caller-safe problem text. */
export function parseCaptureShorthand(
  text: string,
): { readonly ok: true; readonly value: CaptureShorthand } | { readonly ok: false; readonly problem: string } {
  const bad = (why: string) => ({ ok: false as const, problem: `${why}. Expected ${CAPTURE_GRAMMAR}` });
  let rest = text.trim();
  let name: string | undefined;
  const eq = rest.indexOf("=");
  if (eq >= 0) {
    name = rest.slice(0, eq);
    rest = rest.slice(eq + 1);
    if (!NAME.test(name)) return bad(`"${name.slice(0, 40)}" is not a capture name ([A-Za-z_][A-Za-z0-9_]{0,31})`);
  }
  let when: CaptureShorthand["when"];
  const at = rest.lastIndexOf("@");
  if (at >= 0) {
    const suffix = rest.slice(at + 1).toLowerCase();
    if (suffix !== "leave" && suffix !== "both" && suffix !== "enter")
      return bad(`"@${suffix.slice(0, 20)}" is not @leave or @both`);
    when = suffix;
    rest = rest.slice(0, at);
  }
  const colon = rest.indexOf(":");
  if (colon < 0) return bad('missing ":type"');
  const source = rest.slice(0, colon).toLowerCase();
  let typeAndOffsets = rest.slice(colon + 1);
  const firstOffset = typeAndOffsets.search(/[+-]/u);
  const type = (firstOffset < 0 ? typeAndOffsets : typeAndOffsets.slice(0, firstOffset)).toLowerCase();
  typeAndOffsets = firstOffset < 0 ? "" : typeAndOffsets.slice(firstOffset);
  if (!(VALUE_TYPES as readonly string[]).includes(type))
    return bad(`"${type.slice(0, 20)}" is not a value type (${VALUE_TYPES.join(", ")})`);
  const deref: number[] = [];
  let consumed = 0;
  for (const m of typeAndOffsets.matchAll(OFFSET)) {
    if (m.index !== consumed) break;
    const magnitude = Number.parseInt(m[2] ?? "0", (m[2] ?? "").startsWith("0x") ? 16 : 10);
    deref.push(m[1] === "-" ? -magnitude : magnitude);
    consumed += m[0].length;
  }
  if (consumed !== typeAndOffsets.length)
    return bad(`"${typeAndOffsets.slice(consumed, consumed + 20)}" is not a +0xOFFSET`);
  if (deref.length > 4) return bad("at most 4 deref offsets");
  if (deref.some((d) => d < -65_536 || d > 16_777_216)) return bad("deref offsets are -65536..16777216");
  const argMatch = /^arg(\d{1,2})$/u.exec(source);
  const base: { arg?: number; reg?: string } = {};
  if (argMatch !== null) {
    const n = Number(argMatch[1]);
    if (n > 15) return bad("arg is 0..15");
    base.arg = n;
  } else if ((REGISTERS as readonly string[]).includes(source)) base.reg = source;
  else return bad(`"${source.slice(0, 20)}" is neither argN nor a register name`);
  return {
    ok: true,
    value: {
      ...(name !== undefined ? { name } : {}),
      ...base,
      type,
      ...(deref.length > 0 ? { deref } : {}),
      ...(when !== undefined ? { when } : {}),
    },
  };
}

/**
 * CLI shorthands (S6 §8.1; WP7-HOOK fills the WP0 stub). For hook_function it expands every
 * `--capture name=argN:type[+0xOFF…][@leave|@both]` / `--capture name=reg:type` (also `--capture=…`) into the
 * `capture` array and removes the flags from argv; tokens after a bare `--` (the spawned program's arguments) are
 * never touched. Every other command passes through unchanged.
 */
export const expandCliShorthands = (
  contract: ToolContract,
  argv: readonly string[],
): Result<ShorthandExpansion, BeaErrorOf<"InputError">> => {
  if (contract.name !== "hook_function") return ok({ argv, input: {} });
  const out: string[] = [];
  const captures: CaptureShorthand[] = [];
  const issues: InputIssue[] = [];
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i] ?? "";
    if (token === "--") {
      out.push(...argv.slice(i));
      break;
    }
    let value: string | undefined;
    if (token === CAPTURE_FLAG) {
      value = argv[i + 1];
      i++;
      if (value === undefined) {
        issues.push({
          path: "capture",
          reason: "missing_argument",
          message: `--capture needs a value: ${CAPTURE_GRAMMAR}`,
        });
        continue;
      }
    } else if (token.startsWith(`${CAPTURE_FLAG}=`)) value = token.slice(CAPTURE_FLAG.length + 1);
    else {
      out.push(token);
      continue;
    }
    const parsed = parseCaptureShorthand(value);
    if (parsed.ok) captures.push(parsed.value);
    else
      issues.push({
        path: `capture[${String(captures.length + issues.length)}]`,
        reason: "invalid_format",
        message: parsed.problem,
      });
  }
  if (issues.length > 0) return err(inputError(contract.name, issues));
  return ok({ argv: out, input: captures.length > 0 ? { capture: captures } : {} });
};
