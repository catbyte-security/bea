import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import type * as Frida from "frida";

import { adaptFridaModule } from "./fridaAdapters.js";
import type { FridaModuleLike } from "./fridaPorts.js";

/** The binding version BEA is built and verified against (F13; ext-frida). */
export const EXPECTED_FRIDA_VERSION = "17.23.2";

/**
 * The ONLY runtime import of frida (verify-module-boundaries). Lazy: nothing loads the native addon (~55–95 ms) until
 * a session, a process listing or a doctor check needs it. frida's `exports` map hides package.json, so the version
 * is read by walking up from the resolved entry (the same rule tests/support/acceptance/fixtures.ts uses).
 */
const readFridaBindingVersion = (): string => {
  let dir = dirname(createRequire(import.meta.url).resolve("frida"));
  while (!existsSync(join(dir, "package.json")) && dirname(dir) !== dir) dir = dirname(dir);
  const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { readonly version?: unknown };
  return typeof manifest.version === "string" ? manifest.version : "unknown";
};

export const loadFridaModule = async (): Promise<FridaModuleLike> => {
  const imported = (await import("frida")) as unknown as { readonly default?: typeof Frida } & typeof Frida;
  const frida = imported.default ?? imported;
  return adaptFridaModule(frida, readFridaBindingVersion());
};
