/**
 * Subprocess entry for HTTP boundary tests, run from the TypeScript sources (no build):
 *   node --experimental-transform-types --import <repo>/scripts/lib/tsHooks.mjs tests/support/http/serverEntry.ts \
 *     --http --port 0 [--json-response] [--connection-file PATH]
 * The production runHttp with fakeServices() plus the WP16 test tools (testTools.ts). Started by httpServerProcess.ts.
 */
import { runHttp } from "../../../src/main/mcpHttp.js";
import { fakeServices } from "../fakes/fakeServices.js";
import { createHttpTestState, HTTP_TEST_CONTRACTS, httpTestHandlers } from "./testTools.js";

const state = createHttpTestState();
await runHttp(process.argv.slice(2), {
  services: fakeServices(),
  extraContracts: HTTP_TEST_CONTRACTS,
  extraHandlers: httpTestHandlers(state),
});
