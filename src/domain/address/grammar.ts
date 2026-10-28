import { err, ok, type Result } from "../result.js";

/**
 * AddrExpr: the ONE address input string of every tool (S2 §16.1 grammar + S6 §2.1 static form and `$main`;
 * DESIGN D-INT-15, §5.5). Pure: no I/O, no module map. Resolution lives in src/application/address/AddressService.ts.
 *
 *   expr     := va | modrva | mainrva | export | ordinal | static
 *   va       := "0x" HEX{1,16}                         ; ≤ 0x7fffffffffff (user mode), else out_of_range
 *   modrva   := module "+0x" HEX{1,8}
 *   mainrva  := "+0x" HEX{1,8}                         ; main module
 *   export   := module "!" name ["+0x" HEX{1,8}]
 *   ordinal  := module "!#" DEC{1,5} ["+0x" HEX{1,8}]
 *   static   := module ":0x" HEX{1,16} ["/0x" HEX{1,16}]
 *   module   := '"' JSON-string '"' ["@0x" HEX] | bare ["@0x" HEX] | "$main"
 *   bare     := 1*(any char except whitespace, '"', '+', '!', ':')
 *
 * Every string formatAddrExpr() produces parses back to the same value (round-trip property test).
 */
export const USER_VA_MAX = 0x7fff_ffff_ffffn;
const U32_MAX = 0xffff_ffffn;
const U64_MAX = (1n << 64n) - 1n;

export const ADDR_EXPR_GRAMMAR =
  '0xVA | module+0xRVA | +0xRVA | module!export[+0xN] | module!#ordinal[+0xN] | module:0xSTATIC_VA[/0xSTATIC_BASE] | $main:0xSTATIC_VA; module = name, "quoted name or path", name@0xBASE or $main';

export type ModuleToken =
  | { readonly kind: "main" }
  | { readonly kind: "name"; readonly name: string; readonly base: bigint | null }
  | { readonly kind: "path"; readonly path: string; readonly base: bigint | null };

export type ExportRef =
  | { readonly kind: "name"; readonly name: string }
  | { readonly kind: "ordinal"; readonly ordinal: number };

export type ParsedAddress =
  | { readonly form: "va"; readonly va: bigint }
  | { readonly form: "module-rva"; readonly module: ModuleToken; readonly rva: number }
  | {
      readonly form: "export";
      readonly module: ModuleToken;
      readonly export: ExportRef;
      readonly displacement: number;
    }
  | {
      readonly form: "static";
      readonly module: ModuleToken;
      readonly static_va: bigint;
      readonly static_base: bigint | null;
    };

export interface AddressIssue {
  readonly reason: "invalid_format" | "out_of_range";
  readonly message: string;
  readonly expected?: string;
}

const formatIssue = (message: string): AddressIssue => ({
  reason: "invalid_format",
  message,
  expected: ADDR_EXPR_GRAMMAR,
});
const rangeIssue = (message: string): AddressIssue => ({ reason: "out_of_range", message });

/** A "0x"-prefixed hex number of 1..64 digits (longer numbers are range errors, not format errors). */
const HEX_AT = /^0[xX]([0-9a-fA-F]{1,64})/u;

const readHex = (text: string): { readonly value: bigint; readonly digits: number; readonly length: number } | null => {
  const match = HEX_AT.exec(text);
  if (match === null) return null;
  const digits = match[1] ?? "";
  return { value: BigInt(`0x${digits}`), digits: digits.length, length: match[0].length };
};

/** Bounded unsigned value of a whole hex token. */
const hexValue = (text: string, max: bigint, what: string): Result<bigint, AddressIssue> | null => {
  const hex = readHex(text);
  if (hex === null || hex.length !== text.length) return null;
  if (hex.digits > 16 || hex.value > max)
    return err(rangeIssue(`${what} ${text.slice(0, 40)} is above the maximum 0x${max.toString(16)}.`));
  return ok(hex.value);
};

const BARE_STOP = /[\s"+!:]/u;
const EXPORT_STOP = /[\s"+]/u;

/** Scan a JSON string literal starting at text[0] === '"'; returns its parsed value and length. */
const readQuoted = (text: string): { readonly value: string; readonly length: number } | null => {
  for (let i = 1; i < text.length; i++) {
    const ch = text[i];
    if (ch === "\\") {
      i++;
      continue;
    }
    if (ch === '"') {
      try {
        const value: unknown = JSON.parse(text.slice(0, i + 1));
        return typeof value === "string" ? { value, length: i + 1 } : null;
      } catch {
        return null;
      }
    }
  }
  return null;
};

const isPathLike = (value: string): boolean => value.includes("\\") || value.includes("/");

/** Optional "@0xBASE" runtime-base qualifier at text[0]. */
const readBaseQualifier = (
  text: string,
): Result<{ readonly base: bigint | null; readonly length: number }, AddressIssue> => {
  if (!text.startsWith("@")) return ok({ base: null, length: 0 });
  const hex = readHex(text.slice(1));
  if (hex === null) return err(formatIssue("A module base qualifier must be @0x<hex runtime base>."));
  if (hex.digits > 16 || hex.value > USER_VA_MAX)
    return err(rangeIssue("The @0x module base qualifier is above the user-mode limit 0x7fffffffffff."));
  return ok({ base: hex.value, length: 1 + hex.length });
};

/** Module token at the start of text (never empty input). */
const readModule = (text: string): Result<{ readonly module: ModuleToken; readonly length: number }, AddressIssue> => {
  if (text.startsWith('"')) {
    const quoted = readQuoted(text);
    if (quoted === null) return err(formatIssue("Unterminated or invalid quoted module name (JSON string syntax)."));
    if (quoted.value.length === 0) return err(formatIssue("The quoted module name is empty."));
    const qualifier = readBaseQualifier(text.slice(quoted.length));
    if (!qualifier.ok) return qualifier;
    const { base } = qualifier.value;
    const module: ModuleToken = isPathLike(quoted.value)
      ? { kind: "path", path: quoted.value, base }
      : { kind: "name", name: quoted.value, base };
    return ok({ module, length: quoted.length + qualifier.value.length });
  }
  let end = 0;
  while (end < text.length && !BARE_STOP.test(text[end] ?? "")) end++;
  const raw = text.slice(0, end);
  if (raw.length === 0) return err(formatIssue("Expected a module name before +0x, !, or :0x."));
  if (raw === "$main") return ok({ module: { kind: "main" }, length: end });
  const at = /^(.*)@0[xX]([0-9a-fA-F]{1,64})$/u.exec(raw);
  let name = raw;
  let base: bigint | null = null;
  if (at !== null) {
    name = at[1] ?? "";
    const qualifier = readBaseQualifier(raw.slice(name.length));
    if (!qualifier.ok) return qualifier;
    base = qualifier.value.base;
  }
  if (name.length === 0) return err(formatIssue("Expected a module name before the @0x base qualifier."));
  if (name === "$main") return err(formatIssue("$main cannot carry an @0x base qualifier."));
  const module: ModuleToken = isPathLike(name) ? { kind: "path", path: name, base } : { kind: "name", name, base };
  return ok({ module, length: end });
};

/** Optional "+0xN" displacement filling the rest of text. */
const readDisplacement = (text: string, what: string): Result<number, AddressIssue> | null => {
  if (text.length === 0) return ok(0);
  if (!text.startsWith("+")) return null;
  const value = hexValue(text.slice(1), U32_MAX, what);
  if (value === null) return null;
  return value.ok ? ok(Number(value.value)) : value;
};

const parseRemainder = (module: ModuleToken, rest: string): Result<ParsedAddress, AddressIssue> => {
  const unexpected = (): Result<never, AddressIssue> =>
    err(formatIssue("After the module token expected +0x<rva>, !export[+0x<n>], !#ordinal or :0x<static VA>."));
  if (rest.startsWith("+")) {
    const rva = hexValue(rest.slice(1), U32_MAX, "RVA");
    if (rva === null) return err(formatIssue("A module-relative address must be module+0x<rva>."));
    return rva.ok ? ok({ form: "module-rva", module, rva: Number(rva.value) }) : rva;
  }
  if (rest.startsWith(":")) {
    const body = rest.slice(1);
    const slash = body.indexOf("/");
    const vaText = slash === -1 ? body : body.slice(0, slash);
    const staticVa = hexValue(vaText, U64_MAX, "static VA");
    if (staticVa === null) return err(formatIssue("A static address must be module:0x<static VA>[/0x<static base>]."));
    if (!staticVa.ok) return staticVa;
    let staticBase: bigint | null = null;
    if (slash !== -1) {
      const baseValue = hexValue(body.slice(slash + 1), U64_MAX, "static base");
      if (baseValue === null) return err(formatIssue("A static base must be /0x<hex image base>."));
      if (!baseValue.ok) return baseValue;
      staticBase = baseValue.value;
    }
    return ok({ form: "static", module, static_va: staticVa.value, static_base: staticBase });
  }
  if (!rest.startsWith("!")) return unexpected();
  const exportText = rest.slice(1);
  if (exportText.startsWith("#")) {
    const ordinal = /^#(\d+)/u.exec(exportText);
    if (ordinal === null) return err(formatIssue("An ordinal export must be module!#<decimal ordinal>."));
    const digits = ordinal[1] ?? "";
    if (digits.length > 5 || Number(digits) > 65_535) return err(rangeIssue("Export ordinals are at most 65535."));
    const displacement = readDisplacement(exportText.slice(ordinal[0].length), "displacement");
    if (displacement === null) return unexpected();
    return displacement.ok
      ? ok({
          form: "export",
          module,
          export: { kind: "ordinal", ordinal: Number(digits) },
          displacement: displacement.value,
        })
      : displacement;
  }
  let name: string;
  let consumed: number;
  if (exportText.startsWith('"')) {
    const quoted = readQuoted(exportText);
    if (quoted === null || quoted.value.length === 0)
      return err(formatIssue("Invalid quoted export name (JSON string syntax)."));
    name = quoted.value;
    consumed = quoted.length;
  } else {
    let end = 0;
    while (end < exportText.length && !EXPORT_STOP.test(exportText[end] ?? "")) end++;
    if (end === 0) return err(formatIssue("Expected an export name after !."));
    name = exportText.slice(0, end);
    consumed = end;
  }
  const displacement = readDisplacement(exportText.slice(consumed), "displacement");
  if (displacement === null) return unexpected();
  return displacement.ok
    ? ok({ form: "export", module, export: { kind: "name", name }, displacement: displacement.value })
    : displacement;
};

/** Parse one AddrExpr (S2 §16.1 algorithm + S6 §2.1). Leading/trailing whitespace is ignored. */
export const parseAddrExpr = (input: string): Result<ParsedAddress, AddressIssue> => {
  const text = input.trim();
  if (text.length === 0) return err(formatIssue("The address is empty."));
  if (/^\d+$/u.test(text)) return err(formatIssue("Addresses are hexadecimal with a 0x prefix (e.g. 0x7ff6a1b21760)."));
  if (/^0[xX]/u.test(text) && !text.includes(":") && !text.includes("!") && !text.includes("+")) {
    const va = hexValue(text, USER_VA_MAX, "VA");
    if (va === null) return err(formatIssue("A runtime address must be 0x<1..16 hex digits>."));
    if (!va.ok)
      return err(rangeIssue("The address is above 0x7fffffffffff (kernel or non-canonical); BEA is user-mode only."));
    return ok({ form: "va", va: va.value });
  }
  if (text.startsWith("+")) {
    const rva = hexValue(text.slice(1), U32_MAX, "RVA");
    if (rva === null) return err(formatIssue("The main-module shorthand requires +0x<rva>."));
    return rva.ok ? ok({ form: "module-rva", module: { kind: "main" }, rva: Number(rva.value) }) : rva;
  }
  const module = readModule(text);
  if (!module.ok) return module;
  return parseRemainder(module.value.module, text.slice(module.value.length));
};

/** A whole string that is only a module token (map_address.symbols_module, list_module_symbols.module). */
export const parseModuleToken = (input: string): Result<ModuleToken, AddressIssue> => {
  const text = input.trim();
  if (text.length === 0) return err(formatIssue("The module name is empty."));
  // a standalone module field may name an unquoted path ("C:\\Games\\x.dll"): nothing else follows the token
  if (!text.startsWith('"') && isPathLike(text)) return ok({ kind: "path", path: text, base: null });
  const module = readModule(text);
  if (!module.ok) return module;
  return module.value.length === text.length
    ? ok(module.value.module)
    : err(formatIssue('Expected only a module token (name, "quoted name or path", name@0xBASE or $main).'));
};

// ---------------------------------------------------------------- formatting (outputs and round trip)

const hex = (value: bigint | number): string => `0x${value.toString(16)}`;

/** True when a module name can be written bare (no quoting needed to parse back to the same name). */
const bareSafeModule = (name: string): boolean =>
  name.length > 0 &&
  !BARE_STOP.test(name) &&
  !isPathLike(name) &&
  name !== "$main" &&
  !/^0[xX]/u.test(name) &&
  !/^\d+$/u.test(name) &&
  !/@0[xX][0-9a-fA-F]+$/u.test(name);

/** Module token text: bare when safe, else a JSON string; `@0x<base>` when a qualifier is needed. */
export const formatModuleToken = (module: ModuleToken): string => {
  if (module.kind === "main") return "$main";
  const text =
    module.kind === "path"
      ? JSON.stringify(module.path)
      : bareSafeModule(module.name)
        ? module.name
        : JSON.stringify(module.name);
  return module.base === null ? text : `${text}@${hex(module.base)}`;
};

const formatExportName = (name: string): string =>
  name.length > 0 && !/[\s"+]/u.test(name) && !name.startsWith("#") ? name : JSON.stringify(name);

/** Canonical text of a parsed address; parseAddrExpr(formatAddrExpr(p)) deep-equals p. */
export const formatAddrExpr = (parsed: ParsedAddress): string => {
  switch (parsed.form) {
    case "va":
      return hex(parsed.va);
    case "module-rva":
      return parsed.module.kind === "main"
        ? `+${hex(parsed.rva)}`
        : `${formatModuleToken(parsed.module)}+${hex(parsed.rva)}`;
    case "export": {
      const target =
        parsed.export.kind === "ordinal" ? `#${String(parsed.export.ordinal)}` : formatExportName(parsed.export.name);
      const displacement = parsed.displacement === 0 ? "" : `+${hex(parsed.displacement)}`;
      return `${formatModuleToken(parsed.module)}!${target}${displacement}`;
    }
    case "static":
      return `${formatModuleToken(parsed.module)}:${hex(parsed.static_va)}${parsed.static_base === null ? "" : `/${hex(parsed.static_base)}`}`;
  }
};

/** Compact `at` text (S6 §2.2): "name+0xrva", or "name@0xbase+0xrva" when the basename is ambiguous. */
export const atText = (name: string, rva: number, ambiguousBase: bigint | null = null): string =>
  `${formatModuleToken({ kind: "name", name, base: ambiguousBase })}+${hex(rva)}`;

/** Compact `static` text (S6 §2.2): "name:0x<preferred base + rva>" — pasteable back as an AddrExpr. */
export const staticText = (name: string, staticVa: bigint, ambiguousBase: bigint | null = null): string =>
  `${formatModuleToken({ kind: "name", name, base: ambiguousBase })}:${hex(staticVa)}`;

/** Display text of a module token for messages and diagnostics (caller input, bounded). */
export const moduleTokenLabel = (module: ModuleToken): string => formatModuleToken(module).slice(0, 300);
