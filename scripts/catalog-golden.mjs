#!/usr/bin/env node
// scripts/catalog-golden.mjs (WP0; S6 §7.1-§7.2): `npm run catalog:golden` (after build:ts). Registers the BUILT
// contract registry on the production createMcpServer with not-implemented services, lists the tools over an in-memory
// client, measures the catalog (bytes, descriptions, REA depth metric) with scripts/lib/catalogMetrics.mjs, prints the
// per-tool table and rewrites `measured` + `catalog_sha256` in tests/contracts/catalog-budget.json (the ceilings are
// never touched). Exits 1 when a D-INT-10 ceiling is exceeded (the measurement is still written, for review).
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";

import { writeFileAtomic } from "./lib/atomic.mjs";
import { budgetViolations, catalogSha256, formatTable, measureCatalog } from "./lib/catalogMetrics.mjs";
import { formatFiles } from "./lib/format.mjs";
import { withBuildLock } from "./lib/lock.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const budgetPath = "tests/contracts/catalog-budget.json";

await withBuildLock(async () => {
  const dist = (rel) => import(pathToFileURL(join(root, "dist", rel)).href);
  let modules;
  try {
    modules = {
      ...(await dist("contracts/index.js")),
      ...(await dist("application/createApplication.js")),
      ...(await dist("application/notImplemented.js")),
      ...(await dist("application/handles/createHandleRegistry.js")),
      ...(await dist("domain/config.js")),
      ...(await dist("domain/logger.js")),
      ...(await dist("server/createMcpServer.js")),
      ...(await dist("server/delivery.js")),
    };
  } catch (cause) {
    process.stderr.write(
      `catalog-golden: cannot load the built registry from dist/ (${cause?.message ?? cause}); run npm run build:ts first.\n`,
    );
    process.exitCode = 1;
    return;
  }
  const {
    TOOL_CONTRACTS,
    createApplication,
    notImplementedPort,
    createHandleRegistry,
    loadConfig,
    silentLogger,
    createMcpServer,
    Delivery,
    HARD_LIMITS,
  } = modules;
  const loaded = await loadConfig({
    env: { BEA_HOME: join(tmpdir(), "bea-catalog-golden-home-never-written") },
    platform: process.platform,
    accountHome: tmpdir(),
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error(`catalog-golden: config failed: ${JSON.stringify(loaded.error)}`);
  const port = (name) => notImplementedPort(name);
  const app = await createApplication({
    config: loaded.value,
    logger: silentLogger,
    transport: "cli",
    services: async () => ({
      evidence: port("evidence"),
      jobhost: port("jobhost"),
      pe: { images: port("pe.images"), hashes: port("pe.hashes") },
      address: port("address"),
      recordings: port("recordings"),
      sessions: port("sessions"),
      handles: createHandleRegistry(),
      oracle: port("oracle"),
      dumps: port("dumps"),
      emulator: port("emulator"),
    }),
  });
  const server = createMcpServer({
    core: app,
    handlers: () => undefined,
    contracts: TOOL_CONTRACTS,
    delivery: new Delivery(HARD_LIMITS.defaultResponseBytes),
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "bea-catalog-golden", version: "1" });
  await client.connect(clientTransport);
  const { tools } = await client.listTools();
  await client.close();
  await server.close();

  const measured = measureCatalog(tools);
  const budget = JSON.parse(await readFile(join(root, budgetPath), "utf8"));
  const violations = budgetViolations(measured, budget);
  budget.measured = measured.totals;
  budget.catalog_sha256 = catalogSha256(tools);
  const formatted = await formatFiles({ [budgetPath]: `${JSON.stringify(budget, null, 2)}\n` }, root);
  await writeFileAtomic(join(root, budgetPath), formatted[budgetPath]);
  process.stdout.write(
    `${formatTable(measured.rows)}\n${JSON.stringify(measured.totals)}\ncatalog_sha256 ${budget.catalog_sha256}\n`,
  );
  if (violations.length > 0) {
    process.stderr.write(
      `catalog-golden: D-INT-10 ceilings exceeded:\n${violations.map((v) => `  ${v}`).join("\n")}\n`,
    );
    process.exitCode = 1;
  }
});
