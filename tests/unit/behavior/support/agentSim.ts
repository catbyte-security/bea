import type { SockName } from "../../../../src/agent/pure/profileDecode.js";
import { ProfileEngine, type CallState } from "../../../../src/agent/pure/profileEngine.js";
import { HandleCache } from "../../../../src/agent/pure/profileHandles.js";
import type { Cells, PayloadCaps } from "../../../../src/agent/pure/profileTypes.js";
import type { ApiRow } from "../../../../src/shared/agentProtocol.js";
import { API_CATALOG, type ApiSpec } from "../../../../src/shared/apiProfiles.js";
import type { Hex } from "../../../../src/shared/hex.js";
import { FakeMem } from "./fakeMem.js";

export interface SimOptions {
  readonly perApiMax?: number;
  readonly maxHits?: number;
  readonly threadIds?: readonly number[];
  readonly caps?: Partial<PayloadCaps>;
  readonly cacheEntries?: number;
}

export interface CallOptions {
  readonly tid?: number;
  readonly depth?: number;
  readonly lastError?: number;
  readonly caller?: Hex;
  /** the "kernel": runs between enter and leave (fills out-parameters) */
  readonly kernel?: () => void;
}

export const specOf = (exportName: string): ApiSpec => {
  const spec = API_CATALOG.find((s) => s.export === exportName);
  if (spec === undefined) throw new Error(`no catalog entry ${exportName}`);
  return spec;
};

/**
 * The pure profile engine driven by hand-made calls over FakeMem, as the GumJS glue drives it from Interceptor:
 * begin() = onEnter, end() = onLeave. Rows land in `rows`.
 */
export class AgentSim {
  readonly mem = new FakeMem();
  readonly cache: HandleCache;
  readonly rows: ApiRow[] = [];
  readonly keyRoots = new Map<bigint, string>();
  readonly endpoints = new Map<bigint, SockName>();
  readonly keyNameCalls: bigint[] = [];
  maxHitsCalls = 0;
  readonly engine: ProfileEngine<bigint>;
  private g = 0;
  private t = 1_000;

  constructor(options: SimOptions = {}) {
    this.cache = new HandleCache(options.cacheEntries ?? 65_536);
    this.engine = new ProfileEngine<bigint>(
      {
        mem: this.mem,
        cache: this.cache,
        caps: { fileBytes: 0, netBytes: 0, valueBytes: 0, ...options.caps },
        keyName: (h) => {
          this.keyNameCalls.push(h);
          return this.keyRoots.get(h) ?? null;
        },
      },
      {
        nextG: () => ++this.g,
        nowUs: () => (this.t += 10),
        emit: (row) => this.rows.push(row),
        onMaxHits: () => this.maxHitsCalls++,
        localEndpoint: (s) => this.endpoints.get(s) ?? null,
      },
      {
        perApiMax: options.perApiMax ?? 1_000_000,
        maxHits: options.maxHits ?? 1_000_000,
        threadIds: options.threadIds === undefined ? null : new Set(options.threadIds),
      },
    );
  }

  begin(exportName: string, args: readonly bigint[], o: CallOptions = {}): CallState<bigint> | null {
    return this.engine.enter(specOf(exportName), {
      tid: o.tid ?? 100,
      depth: o.depth ?? 0,
      args: (i) => args[i] ?? 0n,
      caller: () => o.caller ?? "0x401000",
    });
  }

  end(state: CallState<bigint> | null, ret: bigint, lastError = 0): void {
    if (state !== null) this.engine.leave(state, ret, lastError);
  }

  call(exportName: string, args: readonly bigint[], ret: bigint, o: CallOptions = {}): void {
    const state = this.begin(exportName, args, o);
    o.kernel?.();
    this.end(state, ret, o.lastError ?? 0);
  }

  pseudo(apiId: number, cells: Cells, tid = 100): void {
    this.engine.emitPseudo(apiId, tid, cells);
  }

  /** The last row's cells (for decoder assertions). */
  lastCells(): Cells {
    const row = this.rows[this.rows.length - 1];
    if (row === undefined) throw new Error("no rows");
    return row[6];
  }
}
