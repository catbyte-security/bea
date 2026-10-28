import { fc, test as propertyTest } from "@fast-check/vitest";
import { describe, expect, it } from "vitest";

import { addrSchema } from "../../../src/domain/address/addressRef.js";
import {
  atText,
  formatAddrExpr,
  formatModuleToken,
  parseAddrExpr,
  parseModuleToken,
  staticText,
  type ModuleToken,
  type ParsedAddress,
} from "../../../src/domain/address/grammar.js";
import { compactAddr, rvaOfStatic, staticOfRva, symText, vaOfRva } from "../../../src/domain/address/rebase.js";

/** S2 §22 "address grammar": table-driven valid/invalid cases + the AddrExpr / AddressText round-trip property. */
const name = (n: string, base: bigint | null = null): ModuleToken => ({ kind: "name", name: n, base });

const VALID: readonly (readonly [string, ParsedAddress])[] = [
  ["0x7ff7a8a11760", { form: "va", va: 0x7ff7a8a11760n }],
  ["0X00001000", { form: "va", va: 0x1000n }],
  ["  0x10  ", { form: "va", va: 0x10n }],
  ["0x7fffffffffff", { form: "va", va: 0x7fff_ffff_ffffn }],
  ["game.exe+0x1a2b3c", { form: "module-rva", module: name("game.exe"), rva: 0x1a2b3c }],
  ["+0x1760", { form: "module-rva", module: { kind: "main" }, rva: 0x1760 }],
  ["$main+0x10", { form: "module-rva", module: { kind: "main" }, rva: 0x10 }],
  ["+0xffffffff", { form: "module-rva", module: { kind: "main" }, rva: 0xffffffff }],
  [
    "kernel32.dll!Sleep",
    { form: "export", module: name("kernel32.dll"), export: { kind: "name", name: "Sleep" }, displacement: 0 },
  ],
  [
    "kernel32.dll!Sleep+0x10",
    { form: "export", module: name("kernel32.dll"), export: { kind: "name", name: "Sleep" }, displacement: 0x10 },
  ],
  [
    "ws2_32.dll!#115",
    { form: "export", module: name("ws2_32.dll"), export: { kind: "ordinal", ordinal: 115 }, displacement: 0 },
  ],
  [
    "ws2_32.dll!#65535+0x4",
    { form: "export", module: name("ws2_32.dll"), export: { kind: "ordinal", ordinal: 65535 }, displacement: 4 },
  ],
  [
    "msvcp140.dll!?_Xlength_error@std@@YAXPEBD@Z",
    {
      form: "export",
      module: name("msvcp140.dll"),
      export: { kind: "name", name: "?_Xlength_error@std@@YAXPEBD@Z" },
      displacement: 0,
    },
  ],
  [
    'game.exe!"weird name+x"+0x2',
    { form: "export", module: name("game.exe"), export: { kind: "name", name: "weird name+x" }, displacement: 2 },
  ],
  ['"notepad++.exe"+0x1000', { form: "module-rva", module: name("notepad++.exe"), rva: 0x1000 }],
  [
    '"C:\\\\Games\\\\x\\\\msvcp140.dll"+0x10',
    { form: "module-rva", module: { kind: "path", path: "C:\\Games\\x\\msvcp140.dll", base: null }, rva: 0x10 },
  ],
  [
    "msvcp140.dll@0x7ffa10000000+0x1234",
    { form: "module-rva", module: name("msvcp140.dll", 0x7ffa10000000n), rva: 0x1234 },
  ],
  [
    '"my lib.dll"@0x7ffa10000000!Init',
    {
      form: "export",
      module: name("my lib.dll", 0x7ffa10000000n),
      export: { kind: "name", name: "Init" },
      displacement: 0,
    },
  ],
  ["game.exe:0x1401234ab", { form: "static", module: name("game.exe"), static_va: 0x1401234abn, static_base: null }],
  [
    "game.exe:0x1401234ab/0x140000000",
    { form: "static", module: name("game.exe"), static_va: 0x1401234abn, static_base: 0x140000000n },
  ],
  ["$main:0x140001760", { form: "static", module: { kind: "main" }, static_va: 0x140001760n, static_base: null }],
  [
    '"My Game.exe":0x140001760',
    { form: "static", module: name("My Game.exe"), static_va: 0x140001760n, static_base: null },
  ],
  [
    "game.exe:0xffffffffffffffff",
    { form: "static", module: name("game.exe"), static_va: 0xffff_ffff_ffff_ffffn, static_base: null },
  ],
  ["mathlib+0x10", { form: "module-rva", module: name("mathlib"), rva: 0x10 }],
  // '@' is a name character unless "@0x<hex>" ends the bare token (S2 §16.1)
  ["game.exe@0xZZ+0x10", { form: "module-rva", module: name("game.exe@0xZZ"), rva: 0x10 }],
];

const INVALID: readonly (readonly [string, "invalid_format" | "out_of_range", RegExp?])[] = [
  ["", "invalid_format"],
  ["   ", "invalid_format"],
  ["1234", "invalid_format", /hexadecimal with a 0x prefix/u],
  ["0x", "invalid_format"],
  ["0xZZ", "invalid_format"],
  ["0x800000000000", "out_of_range", /user-mode/u],
  ["0x12345678901234567", "out_of_range"],
  ["+1760", "invalid_format", /\+0x<rva>/u],
  ["+0x100000000", "out_of_range"],
  ["game.exe+0x100000000", "out_of_range"],
  ["game.exe+1000", "invalid_format"],
  ["game.exe", "invalid_format"],
  ["game.exe!", "invalid_format"],
  ["game.exe!#", "invalid_format"],
  ["game.exe!#65536", "out_of_range"],
  ["game.exe!#123456", "out_of_range"],
  ["game.exe!Sleep+10", "invalid_format"],
  ["game.exe:0x", "invalid_format"],
  ["game.exe:0x1000/", "invalid_format"],
  ["game.exe:0x1000/0x", "invalid_format"],
  ["game.exe:1000", "invalid_format"],
  ['"unterminated+0x10', "invalid_format"],
  ['""+0x10', "invalid_format"],
  ["@0x1000+0x10", "invalid_format"],
  ["$main@0x1000+0x10", "invalid_format"],
  ["game.exe@0x800000000000+0x10", "out_of_range"],
  ["game.exe +0x10", "invalid_format"],
  ["game.exe+0x10 extra", "invalid_format"],
];

describe("AddrExpr grammar (S2 §16.1 + S6 §2.1)", () => {
  it.each(VALID)("parses %s", (text, expected) => {
    expect(parseAddrExpr(text)).toEqual({ ok: true, value: expected });
  });

  it.each(INVALID.map(([text, reason, message]) => ({ text, reason, message })))(
    "rejects $text as $reason",
    ({ text, reason, message }) => {
      const parsed = parseAddrExpr(text);
      expect(parsed.ok).toBe(false);
      if (parsed.ok) return;
      expect(parsed.error.reason).toBe(reason);
      if (message !== undefined) expect(parsed.error.message).toMatch(message);
      if (reason === "invalid_format") expect(parsed.error.expected).toContain("module!export");
    },
  );

  it("formats canonically and re-parses every table case", () => {
    for (const [, value] of VALID) expect(parseAddrExpr(formatAddrExpr(value))).toEqual({ ok: true, value });
    expect(formatAddrExpr({ form: "va", va: 0x1000n })).toBe("0x1000");
    expect(formatAddrExpr({ form: "module-rva", module: { kind: "main" }, rva: 0x10 })).toBe("+0x10");
    expect(formatModuleToken(name("notepad++.exe"))).toBe('"notepad++.exe"');
    expect(formatModuleToken(name("$main"))).toBe('"$main"');
    expect(formatModuleToken(name("0x10.dll"))).toBe('"0x10.dll"');
    expect(formatModuleToken(name("a@0x10"))).toBe('"a@0x10"');
    expect(formatModuleToken({ kind: "path", path: "C:\\a.dll", base: 0x10n })).toBe('"C:\\\\a.dll"@0x10');
  });

  it("parses standalone module tokens (symbols_module, list_module_symbols.module)", () => {
    expect(parseModuleToken("game.exe")).toEqual({ ok: true, value: name("game.exe") });
    expect(parseModuleToken("$main")).toEqual({ ok: true, value: { kind: "main" } });
    expect(parseModuleToken("C:\\Games\\game.exe")).toEqual({
      ok: true,
      value: { kind: "path", path: "C:\\Games\\game.exe", base: null },
    });
    expect(parseModuleToken("x.dll@0x7ff600000000")).toEqual({ ok: true, value: name("x.dll", 0x7ff600000000n) });
    expect(parseModuleToken("game.exe+0x10").ok).toBe(false);
    expect(parseModuleToken("").ok).toBe(false);
  });

  // ---------------------------------------------------------------- round-trip property (S2 §16.5, DESIGN §8.4)
  const moduleName = fc.string({ minLength: 1, maxLength: 24 }).filter((s) => !s.includes("\\") && !s.includes("/"));
  const pathToken = fc
    .tuple(fc.string({ minLength: 0, maxLength: 12 }), fc.string({ minLength: 1, maxLength: 12 }))
    .map(([dir, file]) => `C:\\${dir}\\${file}`);
  const base = fc.option(fc.bigInt({ min: 0n, max: 0x7fff_ffff_ffffn }), { nil: null });
  const token: fc.Arbitrary<ModuleToken> = fc.oneof(
    fc.constant({ kind: "main" } as const),
    fc.record({ kind: fc.constant("name" as const), name: moduleName, base }),
    fc.record({ kind: fc.constant("path" as const), path: pathToken, base }),
  );
  const u32 = fc.integer({ min: 0, max: 0xffffffff });
  const parsedAddress: fc.Arbitrary<ParsedAddress> = fc.oneof(
    fc.record({ form: fc.constant("va" as const), va: fc.bigInt({ min: 0n, max: 0x7fff_ffff_ffffn }) }),
    fc.record({ form: fc.constant("module-rva" as const), module: token, rva: u32 }),
    fc.record({
      form: fc.constant("export" as const),
      module: token,
      export: fc.oneof(
        fc.record({ kind: fc.constant("name" as const), name: fc.string({ minLength: 1, maxLength: 40 }) }),
        fc.record({ kind: fc.constant("ordinal" as const), ordinal: fc.integer({ min: 0, max: 65535 }) }),
      ),
      displacement: u32,
    }),
    fc.record({
      form: fc.constant("static" as const),
      module: token,
      static_va: fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
      static_base: fc.option(fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }), { nil: null }),
    }),
  );

  propertyTest.prop([parsedAddress], { numRuns: 2000 })("parse(format(p)) == p", (p) => {
    expect(parseAddrExpr(formatAddrExpr(p))).toEqual({ ok: true, value: p });
  });

  propertyTest.prop([moduleName, base, u32, fc.bigInt({ min: 0n, max: 0xffff_ffffn })], { numRuns: 1000 })(
    "compact at/static texts are AddrExpr inputs that resolve to the same module + rva",
    (n, qualifier, rva, pref) => {
      const at = parseAddrExpr(atText(n, rva, qualifier));
      expect(at).toEqual({ ok: true, value: { form: "module-rva", module: name(n, qualifier), rva } });
      const staticVa = pref * 0x10000n + BigInt(rva);
      const st = parseAddrExpr(staticText(n, staticVa, qualifier));
      expect(st).toEqual({
        ok: true,
        value: { form: "static", module: name(n, qualifier), static_va: staticVa, static_base: null },
      });
    },
  );
});

describe("ASLR arithmetic (S2 §16.3)", () => {
  it("maps static VAs through the base and bounds rvas to the image", () => {
    // the VERIFIED example: 0x140000000 → 0x7ff7a8a10000 [S2-lab E2]
    const rva = rvaOfStatic(0x140001760n, 0x140000000n, 0x20000);
    expect(rva).toEqual({ ok: true, value: 0x1760 });
    expect(vaOfRva(0x7ff7a8a10000n, 0x1760)).toBe(0x7ff7a8a11760n);
    expect(rvaOfStatic(0x13fffffffn, 0x140000000n, 0x20000)).toEqual({ ok: false, error: "static_out_of_image" });
    expect(rvaOfStatic(0x140020000n, 0x140000000n, 0x20000)).toEqual({ ok: false, error: "static_out_of_image" });
    expect(vaOfRva(0x7fff_ffff_0000n, 0x10000)).toBeNull();
    expect(staticOfRva((1n << 64n) - 1n, 1)).toBeNull();
  });

  it("builds compact Addr texts with a legend-free module name and an @base for duplicate basenames", () => {
    const module = {
      name: "game.exe",
      base: 0x7ff6a0000000n,
      size: 0x10000,
      staticBase: 0x140000000n,
      ambiguous: false,
    };
    expect(compactAddr(0x7ff6a0001760n, module)).toEqual({
      va: "0x7ff6a0001760",
      at: "game.exe+0x1760",
      static: "game.exe:0x140001760",
    });
    expect(compactAddr(0x7ff6a0001760n, { ...module, ambiguous: true, staticBase: null })).toEqual({
      va: "0x7ff6a0001760",
      at: "game.exe@0x7ff6a0000000+0x1760",
      static: null,
    });
    expect(compactAddr(0x1000n, null)).toEqual({ va: "0x1000", at: null, static: null });
    expect(addrSchema.safeParse(compactAddr(0x7ff6a0001760n, module)).success).toBe(true);
    expect(symText("physics_step", 0)).toBe("physics_step");
    expect(symText("physics_step", 0x36)).toBe("physics_step+0x36");
  });
});
