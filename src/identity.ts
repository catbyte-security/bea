import { PACKAGE_METADATA } from "./generated/packageMetadata.js";

/** The only place product names live (REA src/identity.ts pattern). */
export const PRODUCT_IDENTITY = {
  displayName: "BEA",
  tagline: "BEA — Binary Execution Analysis: dynamic binary analysis for agents",
  packageName: PACKAGE_METADATA.name,
  packageVersion: PACKAGE_METADATA.version,
  /** Pinned in client registrations once the package is published. */
  registrationPackageSpecifier: `${PACKAGE_METADATA.name}@${PACKAGE_METADATA.version}`,
  cliBinary: "bea",
  mcpServerKey: "bea",
  skillName: "bea-dynamic-analysis",
  skillVersion: PACKAGE_METADATA.skillVersion,
} as const;
