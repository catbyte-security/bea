import type { TestProject } from "vitest/node";

import { buildFixtures, type FixtureManifest, type FixturesUnavailable } from "../scripts/lib/fixtures.mjs";

/**
 * Acceptance-lane globalSetup (S6 §10.2): builds every fixture once per run (cached in .cache/fixtures/<key>/ under the
 * build lock) and provides the manifest, or {unavailable: reason} without gcc/objdump, to every test through
 * inject("fixtures"). A broken fixture invariant fails the run here.
 */
export default async function setup(project: TestProject): Promise<void> {
  const manifest = await buildFixtures();
  project.provide("fixtures", manifest);
}

declare module "vitest" {
  export interface ProvidedContext {
    fixtures: FixtureManifest | FixturesUnavailable;
  }
}
