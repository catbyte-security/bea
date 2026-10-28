import { availableParallelism } from "node:os";
import { defineConfig } from "vitest/config";

const maxWorkers = Math.min(2, availableParallelism());
const serial = { pool: "forks" as const, fileParallelism: false };
export default defineConfig({
  test: {
    retry: 0,
    testTimeout: 30_000,
    hookTimeout: 30_000,
    maxWorkers,
    projects: [
      {
        test: {
          name: "unit",
          include: ["src/**/*.test.ts", "tests/unit/**/*.test.ts", "tests/contracts/**/*.test.ts"],
          pool: "threads",
          isolate: false,
        },
      },
      { test: { name: "mcp-boundary", include: ["tests/boundary/mcp/**/*.test.ts"], pool: "threads", isolate: false } },
      { test: { name: "cli-boundary", include: ["tests/boundary/cli/**/*.test.ts"], pool: "forks" } },
      { test: { name: "http-boundary", include: ["tests/boundary/http/**/*.test.ts"], ...serial } },
      { test: { name: "process-boundary", include: ["tests/boundary/process/**/*.test.ts"], ...serial } },
      { test: { name: "emu-boundary", include: ["tests/boundary/emu/**/*.test.ts"], ...serial, testTimeout: 60_000 } },
      {
        test: {
          name: "acceptance",
          include: ["tests/acceptance/**/*.test.ts"],
          ...serial,
          globalSetup: ["tests/globalSetup.ts"],
          testTimeout: 60_000,
        },
      },
    ],
  },
});
