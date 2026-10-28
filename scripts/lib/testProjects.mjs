// scripts/lib/testProjects.mjs (WP0; S1 §2.6): the vitest project table as data, for scripts that must know which
// project owns a test file (verify-test-discovery.mjs). vitest.config.ts declares the same table; the verifier fails
// when the two disagree.
export const TEST_PROJECTS = [
  { name: "unit", include: ["src/**/*.test.ts", "tests/unit/**/*.test.ts", "tests/contracts/**/*.test.ts"] },
  { name: "mcp-boundary", include: ["tests/boundary/mcp/**/*.test.ts"] },
  { name: "cli-boundary", include: ["tests/boundary/cli/**/*.test.ts"] },
  { name: "http-boundary", include: ["tests/boundary/http/**/*.test.ts"] },
  { name: "process-boundary", include: ["tests/boundary/process/**/*.test.ts"] },
  { name: "emu-boundary", include: ["tests/boundary/emu/**/*.test.ts"] },
  { name: "acceptance", include: ["tests/acceptance/**/*.test.ts"] },
];

/** Projects run by `npm test` (any OS, no build). */
export const FAST_PROJECTS = ["unit", "mcp-boundary", "cli-boundary", "http-boundary"];
