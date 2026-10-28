import { PRODUCT_IDENTITY } from "../../identity.js";

/**
 * The package version as the emulator stack uses it: the bridge's expected BRIDGE_VERSION (S5 §4.2), the
 * `bridge.hello` client version and the venv marker's `created_by.version`. Providers may not import src/identity.ts
 * directly (module-boundary table), so the emulator provider reads it through this application module.
 */
export const BEA_PACKAGE_VERSION: string = PRODUCT_IDENTITY.packageVersion;
export const BEA_PACKAGE_NAME: string = PRODUCT_IDENTITY.packageName;
