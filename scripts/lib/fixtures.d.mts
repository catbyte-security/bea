// Types for scripts/lib/fixtures.mjs (tests/globalSetup.ts and tests/support/acceptance/fixtures.ts import it).

export type FixtureId =
  | "game_sim"
  | "crashy"
  | "behavior"
  | "mathlib"
  | "pidcheck"
  | "vehcommit"
  | "waiters"
  | "mitigated"
  | "bea_emu_fixture"
  | "live_fixture"
  | "cxx_catch";

export interface ToolInfo {
  readonly command: string;
  readonly path: string;
  readonly version: string;
}

export interface FixtureArtifact {
  readonly id: FixtureId;
  readonly file: string;
  /** Absolute path of the built artifact. */
  readonly path: string;
  readonly source: string;
  readonly sourceSha256: string;
  readonly artifactSha256: string;
  readonly bytes: number;
  readonly compiler: ToolInfo & { readonly args: readonly string[] };
  readonly pe: {
    readonly machine: string;
    readonly imageBase: string;
    readonly dynamicBase: boolean;
    readonly highEntropyVa: boolean;
    readonly nxCompat: boolean;
    readonly sizeOfImage: number;
    readonly imports: readonly string[];
    /** export name -> RVA */
    readonly exportRvas: Readonly<Record<string, number>>;
    /** exported function -> .pdata extent */
    readonly pdata: Readonly<Record<string, { readonly rva: number; readonly size: number }>>;
    readonly sections: readonly {
      readonly name: string;
      readonly rva: number;
      readonly virtualSize: number;
      readonly characteristics: number;
    }[];
  };
  /** Per-fixture facts parsed from the disassembly (DESIGN §8.1, S6 §10.2); see scripts/lib/fixtures.mjs. */
  readonly expectations: Readonly<Record<string, unknown>>;
}

export interface FixtureManifest {
  readonly schema: "bea.fixtures/1";
  readonly builder: string;
  readonly key: string;
  /** Absolute directory holding every artifact (game_sim.exe and behavior.exe load mathlib.dll from it). */
  readonly dir: string;
  readonly toolchain: { readonly cc: ToolInfo; readonly cxx: ToolInfo; readonly objdump: ToolInfo };
  readonly artifacts: Readonly<Record<FixtureId, FixtureArtifact>>;
}

export interface FixturesUnavailable {
  readonly unavailable: string;
}

export declare class FixtureInvariantError extends Error {}

export declare const FIXTURE_SPECS: readonly {
  readonly id: FixtureId;
  readonly source: string;
  readonly file: string;
  readonly tool: "cc" | "cxx";
  readonly args: readonly string[];
  readonly libs?: readonly string[];
}[];

export declare function fixtureToolchain():
  | { readonly cc: ToolInfo; readonly cxx: ToolInfo; readonly objdump: ToolInfo }
  | FixturesUnavailable;

export declare function buildFixtures(options?: {
  readonly force?: boolean;
  readonly log?: (line: string) => void;
}): Promise<FixtureManifest | FixturesUnavailable>;
