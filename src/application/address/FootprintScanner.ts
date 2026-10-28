import {
  compareWindow,
  diffRanges,
  overlayOriginals,
  type LoaderClass,
  type RvaRange,
} from "../../domain/address/verify.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { formatHex } from "../../domain/hex.js";
import type { PiId } from "../../domain/ids.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { EffectRegistry } from "../../ports/evidence.js";
import type { PeImage } from "../../ports/pe.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";

/**
 * FootprintScanner (S2 §18.4): the executable, non-writable sections of one loaded module compared with the
 * relocated on-disk image, loader-written classes and BEA's own effects excluded. The differing ranges are code
 * patched by the BEA agent itself (VERIFIED: ntdll!LdrLoadDll, one unexported ntdll function, kernel32!FatalExit)
 * or by another in-process component — a scan cannot tell them apart, so the class is `foreign-or-agent-patch`.
 * Runs lazily, once per (instance, module base), the first time a verification in that module finds a difference,
 * and only for the modules the agent patches (AddressService agentPatchesModule; review fix DATA-2: scanning any
 * module from the state being judged classed every pre-existing code change there as foreign).
 */
/** Agent read chunk: half the default agent read cap (limits.read_max_bytes = 1 MiB). */
const READ_CHUNK = 512 * 1024;

export interface LoaderSpan extends RvaRange {
  readonly class: LoaderClass;
}

/** Live bytes of [va, va+len): the readable prefix (an unreadable start is an empty read, not an error). */
export const readLive = async (
  session: LiveSession,
  va: bigint,
  len: number,
  op: OperationContext,
): Promise<Result<Uint8Array, BeaError>> => {
  const out = new Uint8Array(len);
  let done = 0;
  while (done < len) {
    const size = Math.min(READ_CHUNK, len - done);
    const reply = await session.agent.call("readMemory", { address: formatHex(va + BigInt(done)), size }, { op });
    if (!reply.ok) {
      if (reply.error._tag === "MemoryAccessFailed" || reply.error._tag === "AddressUnmapped") break;
      return err(reply.error);
    }
    const data = reply.value.data;
    out.set(data.subarray(0, Math.min(data.length, size)), done);
    done += Math.min(data.length, size);
    if (data.length < size || !reply.value.value.complete) break;
  }
  return ok(out.subarray(0, done));
};

export interface FootprintModule {
  readonly base: bigint;
  readonly size: number;
}

export class FootprintScanner {
  readonly #cache = new Map<string, Promise<readonly RvaRange[]>>();

  constructor(private readonly effects: Pick<EffectRegistry, "originalBytes">) {}

  /** Cached per (instance, module base); a failed scan is not cached (null = unknown → "unexplained"). */
  async scan(
    session: LiveSession,
    module: FootprintModule,
    image: PeImage,
    op: OperationContext,
  ): Promise<readonly RvaRange[] | null> {
    const key = `${session.instanceId}|${module.base.toString(16)}`;
    let pending = this.#cache.get(key);
    if (pending === undefined) {
      pending = this.#scan(session, session.instanceId, module, image, op);
      this.#cache.set(key, pending);
      pending.catch(() => this.#cache.delete(key));
    }
    try {
      return await pending;
    } catch {
      return null;
    }
  }

  async #scan(
    session: LiveSession,
    instance: PiId,
    module: FootprintModule,
    image: PeImage,
    op: OperationContext,
  ): Promise<readonly RvaRange[]> {
    const loader: LoaderSpan[] = [...(await image.loaderWritten())];
    const out: RvaRange[] = [];
    for (const section of image.sections) {
      if (!section.perms.includes("x") || section.perms.includes("w")) continue;
      const end = Math.min(section.rva + Math.max(section.virtual_size, section.raw_size), module.size);
      for (let rva = section.rva; rva < end; rva += READ_CHUNK) {
        const len = Math.min(READ_CHUNK, end - rva);
        const va = module.base + BigInt(rva);
        const live = await readLive(session, va, len, op);
        if (!live.ok) throw new Error(live.error._tag);
        const own = overlayOriginals(live.value, va, this.effects.originalBytes(instance, va, len).ranges);
        const { backed } = await image.readRva(rva, len);
        const expected = await image.imageBytes(rva, len, module.base);
        out.push(
          ...diffRanges(compareWindow({ rva, len, live: live.value, ownRestored: own, expected, backed, loader })),
        );
      }
    }
    return out;
  }
}
