import { PRODUCT_IDENTITY } from "../../identity.js";

/** BEA's own version as recorded in run headers, bundles and `bea.run/1` (providers may not import identity.ts). */
export const BEA_VERSION: string = PRODUCT_IDENTITY.packageVersion;
