import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { BeaApplication } from "../../../../src/application/BeaApplication.js";
import { createApplication } from "../../../../src/application/createApplication.js";
import { loadConfig } from "../../../../src/domain/config.js";
import { silentLogger } from "../../../../src/domain/logger.js";
import type { HostPlatform } from "../../../../src/domain/paths.js";
import { fakeServices } from "../../../support/fakes/fakeServices.js";

/** A real BeaCore (lifecycle, status, doctor registries) with every service faked; no filesystem access. */
export const testCore = async (platform: HostPlatform = "win32"): Promise<BeaApplication> => {
  const loaded = await loadConfig({
    env: { BEA_HOME: platform === "win32" ? "C:/bea-test-home" : "/tmp/bea-test-home" },
    platform,
    accountHome: platform === "win32" ? "C:/Users/t" : "/home/t",
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
  return createApplication({
    config: loaded.value,
    logger: silentLogger,
    transport: "stdio",
    services: fakeServices(),
  });
};

/** A stand-in helper binary plus a matching bea.native-build/1 manifest (the locator only hashes it). */
export const writeFakeBinary = async (
  dir: string,
  overrides: Readonly<Record<string, unknown>> = {},
): Promise<{ readonly exePath: string; readonly manifestPath: string; readonly sha256: string }> => {
  await mkdir(dir, { recursive: true });
  const bytes = Buffer.from("MZ fake bea-jobhost for unit tests");
  const exePath = join(dir, "bea-jobhost.exe");
  const manifestPath = join(dir, "bea-jobhost.json");
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  await writeFile(exePath, bytes);
  await writeFile(
    manifestPath,
    JSON.stringify({
      schema: "bea.native-build/1",
      file: "bea-jobhost.exe",
      protocol: 1,
      sha256,
      bytes: bytes.length,
      ...overrides,
    }),
  );
  return { exePath, manifestPath, sha256 };
};
