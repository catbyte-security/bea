// =================================================================================================
// tests/support/agent/coreAgent.ts — WP3-AGENT test agent builds (raw-Frida acceptance lane, no BEA host).
// Stages the agent like scripts/build-agent.mjs (agent/ + shared/, the agent tsconfig at the stage root) and compiles
// it with frida.Compiler (esm, typeCheck "full"). Two modes:
//  - "core": the WP3 core files + the DESIGN §4 day-0 stubs for every feature file, so the core is tested in
//    isolation from feature work in progress (every feature RPC answers Unsupported{not-implemented});
//  - "repo": every file under src/agent (what `npm run build:agent` compiles).
// An optional test entry (a module placed next to index.ts) imports "./index.js" and adds test-only RPCs; it reaches
// the core through `currentCore()`-style hooks it defines itself (see testEntry.ts). Bundles are cached by the
// sha256 of the staged sources in the OS temp directory; nothing is written to dist/.
// =================================================================================================
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";

const repo = resolve(import.meta.dirname, "..", "..", "..");

/** The WP3 core files (DESIGN §9.3 WP3 owned paths) besides index.ts, native/** and pure/core*.ts. */
export const CORE_FILES = [
  "state",
  "rpc",
  "errors",
  "coreRpc",
  "jobs",
  "instruments",
  "inspect",
  "memory",
  "env",
  "encode",
  "win32",
  "events",
  "ack",
  "exceptions",
  "modules",
  "threads",
  "originals",
  "capture",
  "disasm",
  "stalkerCo",
  "fingerprint",
  "guards",
  "calls",
] as const;

/** Feature files and their RPC methods (the DESIGN §4 day-0 stubs). */
export const FEATURE_STUBS: Readonly<Record<string, readonly string[]>> = {
  code: ["disassemble"],
  memwrite: ["writeMemory", "revertWrite"],
  scan: ["scanStart", "scanNext", "scanStatus", "scanResults", "scanClose"],
  hooks: ["hookInstall"],
  profiles: ["profileInstall"],
  watch: ["watchInstall", "debugRegisterState"],
  trace: ["traceStart"],
  override: ["overrideInstall"],
  call: ["callFunction"],
  dump: ["dumpStart", "captureThreadState"],
};

const stubSource = (methods: readonly string[]): string =>
  [
    'import type { AgentRpcImpl } from "../shared/agentProtocol.js";',
    'import { unsupported } from "./errors.js";',
    'import type { AgentCore } from "./state.js";',
    "",
    "export function init(core: AgentCore): void {",
    "  void core;",
    "}",
    "export const rpc = {",
    ...methods.map((m) => `  ${m}: () => unsupported(${JSON.stringify(m)}),`),
    "} satisfies Partial<AgentRpcImpl>;",
    "",
  ].join("\n");

export interface AgentBuildOptions {
  readonly mode: "core" | "repo";
  /** a test entry module (placed at agent/<name>.ts) that imports "./index.js" */
  readonly entry?: { readonly name: string; readonly source: string };
}

export interface AgentBuild {
  readonly bundle: string;
  readonly bytes: number;
  readonly buildId: string;
  readonly diagnostics: readonly string[];
}

export class AgentBuildError extends Error {
  readonly diagnostics: readonly string[];

  constructor(message: string, diagnostics: readonly string[]) {
    super(`${message}\n${diagnostics.join("\n")}`);
    this.name = "AgentBuildError";
    this.diagnostics = diagnostics;
  }
}

const listFiles = (dir: string): string[] =>
  (
    readdirSync(dir, { recursive: true, withFileTypes: true }) as {
      isFile(): boolean;
      name: string;
      parentPath: string;
    }[]
  )
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name));

/** Stage the sources (agent/ + shared/ + tsconfig.json) into `stage`. */
export const stageAgent = (stage: string, options: AgentBuildOptions): void => {
  const src = join(repo, "src", "agent");
  mkdirSync(join(stage, "agent", "pure"), { recursive: true });
  mkdirSync(join(stage, "shared"), { recursive: true });
  cpSync(join(repo, "src", "shared"), join(stage, "shared"), { recursive: true });
  if (options.mode === "repo")
    cpSync(src, join(stage, "agent"), { recursive: true, filter: (p) => !p.endsWith("tsconfig.json") });
  else {
    for (const f of ["index", ...CORE_FILES]) cpSync(join(src, `${f}.ts`), join(stage, "agent", `${f}.ts`));
    cpSync(join(src, "native"), join(stage, "agent", "native"), { recursive: true });
    for (const f of readdirSync(join(src, "pure")).filter((n) => /^core.*\.ts$/u.test(n)))
      cpSync(join(src, "pure", f), join(stage, "agent", "pure", f));
    for (const [file, methods] of Object.entries(FEATURE_STUBS))
      writeFileSync(join(stage, "agent", `${file}.ts`), stubSource(methods));
  }
  if (options.entry !== undefined)
    writeFileSync(join(stage, "agent", `${options.entry.name}.ts`), options.entry.source);
  const tsconfig = JSON.parse(readFileSync(join(src, "tsconfig.json"), "utf8")) as { include: string[] };
  tsconfig.include = ["agent/**/*.ts", "shared/**/*.ts"];
  writeFileSync(join(stage, "tsconfig.json"), JSON.stringify(tsconfig, null, 2));
};

const digestOf = (stage: string): string => {
  const h = createHash("sha256");
  for (const f of listFiles(stage).sort())
    h.update(relative(stage, f).replaceAll("\\", "/")).update("\0").update(readFileSync(f)).update("\0");
  return h.digest("hex");
};

interface FridaCompilerLike {
  readonly diagnostics: { connect(cb: (d: unknown) => void): void };
  build(entry: string, options: Record<string, unknown>): Promise<string>;
}

const formatDiagnostic = (d: Record<string, unknown>): string => {
  const file = d["file"] as { path?: string; line?: number } | undefined;
  return `${file?.path ?? "?"}:${(file?.line ?? 0) + 1} ${String(d["category"])} TS${String(d["code"])}: ${String(d["text"])}`;
};

/** Build (or reuse from the cache) a test agent bundle. Throws AgentBuildError on any diagnostic. */
export const buildTestAgent = async (options: AgentBuildOptions): Promise<AgentBuild> => {
  const stage = mkdtempSync(join(tmpdir(), "bea-wp3-stage-"));
  try {
    stageAgent(stage, options);
    const digest = digestOf(stage);
    const buildId = digest.slice(0, 16);
    writeFileSync(
      join(stage, "agent", "buildInfo.ts"),
      `export const AGENT_VERSION = "0.1.0-test";\nexport const AGENT_BUILD_ID = ${JSON.stringify(buildId)};\n`,
    );
    const cacheDir = join(tmpdir(), "bea-wp3-agent-cache");
    const cached = join(cacheDir, `${digest}.js`);
    if (existsSync(cached)) {
      const bundle = readFileSync(cached, "utf8");
      return { bundle, bytes: Buffer.byteLength(bundle), buildId, diagnostics: [] };
    }
    const fridaModule = (await import("frida")) as unknown as { default?: unknown };
    const frida = (fridaModule.default ?? fridaModule) as { Compiler: new () => FridaCompilerLike };
    const compiler = new frida.Compiler();
    const diagnostics: string[] = [];
    compiler.diagnostics.connect((batch) => {
      const list = JSON.parse(
        JSON.stringify(batch, (_k, v: unknown) => (typeof v === "bigint" ? Number(v) : v)),
      ) as Record<string, unknown>[];
      for (const d of list) diagnostics.push(formatDiagnostic(d));
    });
    const entryFile = join(stage, "agent", `${options.entry?.name ?? "index"}.ts`);
    let bundle: string;
    try {
      bundle = await compiler.build(entryFile, {
        projectRoot: stage,
        bundleFormat: "esm",
        typeCheck: "full",
        sourceMaps: "omitted",
        compression: "none",
      });
    } catch (cause) {
      throw new AgentBuildError(`frida.Compiler failed: ${String(cause)}`, diagnostics);
    }
    if (diagnostics.length > 0) throw new AgentBuildError("frida.Compiler reported diagnostics", diagnostics);
    mkdirSync(dirname(cached), { recursive: true });
    writeFileSync(cached, bundle);
    return { bundle, bytes: Buffer.byteLength(bundle), buildId, diagnostics };
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
};
