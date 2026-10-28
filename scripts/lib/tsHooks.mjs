// scripts/lib/tsHooks.mjs (WP0): lets plain Node scripts import BEA's TypeScript sources without a build.
// Load with: node --experimental-transform-types --import ./scripts/lib/tsHooks.mjs <script>
//
// The sources use NodeNext specifiers ("./effects.js" for effects.ts); Node's TypeScript support executes .ts files
// but does not map those specifiers, so this resolve hook retries a missing relative "*.js" as "*.ts".
// --experimental-transform-types (not plain type stripping) is required: a few frozen files use parameter
// properties (constructor(readonly x: T)), which stripping alone rejects.
import { registerHooks } from "node:module";

registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context);
    } catch (cause) {
      const relative = specifier.startsWith("./") || specifier.startsWith("../");
      if (!relative || !specifier.endsWith(".js") || cause?.code !== "ERR_MODULE_NOT_FOUND") throw cause;
      return nextResolve(`${specifier.slice(0, -3)}.ts`, context);
    }
  },
});
