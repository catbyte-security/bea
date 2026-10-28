import { beforeEach, describe, expect, it } from "vitest";

import type { BeaApplication } from "../../../src/application/BeaApplication.js";
import { createHandleRegistry } from "../../../src/application/handles/createHandleRegistry.js";
import {
  createWriteService,
  type WriteInput,
  type WriteService,
} from "../../../src/application/modify/writeService.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { err, ok } from "../../../src/domain/result.js";
import { bytesToHex } from "../../../src/shared/hex.js";
import {
  createFakeWorld,
  fakeOp,
  installWriteAgent,
  MODULE_BASE,
  SESSION_ID,
  type FakeWorld,
} from "./support/modifyFakes.js";

const op = fakeOp("write_memory");
const input = (over: Partial<WriteInput>): WriteInput => ({
  session_id: SESSION_ID,
  address: "game_sim.exe+0x3000",
  ...over,
});

let world: FakeWorld;
let service: WriteService;
beforeEach(() => {
  world = createFakeWorld();
  const app = { services: { ...world.services, handles: createHandleRegistry() } } as unknown as BeaApplication;
  service = createWriteService(app);
});

const methods = () => world.agentCalls.map((c) => c.method);

describe("write_memory service", () => {
  it("writes a typed value as exact bytes, records the effect and the evidence", async () => {
    installWriteAgent(world, { before: "00002041" });
    const result = await service.write(world.session, input({ type: "f32", value: 1 }), op);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(methods()).toEqual(["describeAddresses", "writeMemory"]);
    expect(world.agentCalls[1]?.params).toEqual({
      address: `0x${(MODULE_BASE + 0x3000n).toString(16)}`,
      mode: "data",
      bytes: "0000803f",
      allow_protect_change: true,
    });
    expect(result.value).toMatchObject({
      before_hex: "00002041",
      after_hex: "0000803f",
      verified: true,
      method: "direct",
      predicate_type: "bea.memory.write",
      address: { module: "game_sim.exe", rva: "0x3000" },
    });
    expect(world.effects).toHaveLength(1);
    const effect = world.effects[0];
    expect(effect?.draft.kind).toBe("memory-written");
    expect(effect?.draft.applied_by).toBe("write_memory");
    expect(bytesToHex(effect?.draft.before ?? new Uint8Array())).toBe("00002041");
    expect(result.value.effect_id).toBe(effect?.id);
    expect(result.value.effects_applied).toEqual([effect?.id]);
    expect(world.records[0]?.effects).toEqual([effect?.id]);
    expect(world.records[0]?.locations?.[0]).toMatchObject({ kind: "address", size: 4 });
    expect(result.value.limitations).toEqual([]);
    expect(service.entries(SESSION_ID).map((e) => e.state)).toEqual(["active"]);
  });

  it("patches executable pages with patchCode as a code-patched effect", async () => {
    installWriteAgent(world, { protection: "r-x" });
    const result = await service.write(world.session, input({ hex: "CC" }), op);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect((world.agentCalls[1]?.params as { mode: string } | undefined)?.mode).toBe("code");
    expect(result.value.method).toBe("patchCode");
    expect(world.effects[0]?.draft.kind).toBe("code-patched");
    expect(result.value.limitations).toEqual([LIMITATIONS.WRITE_CODE_PATCH]);
  });

  it("records a closed protection-changed effect for protect-and-restore", async () => {
    installWriteAgent(world, { protection: "r--" });
    const result = await service.write(world.session, input({ type: "u32", value: 7 }), op);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(world.effects.map((e) => e.draft.kind)).toEqual(["memory-written", "protection-changed"]);
    expect(world.transitions).toEqual([
      { id: world.effects[1]?.id, to: "reverted", ok: true, reason: "stop-requested" },
    ]);
    expect(result.value.effects_applied).toEqual(world.effects.map((e) => e.id));
    expect(result.value.limitations).toEqual([LIMITATIONS.WRITE_PROTECTION_RESTORED]);
  });

  it("reports an unverified read-back as a limitation, not as success text", async () => {
    installWriteAgent(world, { verified: false });
    const result = await service.write(world.session, input({ hex: "01" }), op);
    expect(result.ok && result.value.verified).toBe(false);
    expect(result.ok && result.value.limitations).toEqual([LIMITATIONS.WRITE_UNVERIFIED]);
  });

  it("resolves ptr values given as address expressions", async () => {
    installWriteAgent(world);
    const result = await service.write(world.session, input({ type: "ptr", value: "game_sim.exe!g_world" }), op);
    expect(result.ok).toBe(true);
    const va = MODULE_BASE + 0x5000n;
    const expected = bytesToHex(new Uint8Array(new BigUint64Array([va]).buffer));
    expect((world.agentCalls[1]?.params as { bytes: string } | undefined)?.bytes).toBe(expected);
  });

  it("refuses bad values and unmapped addresses before writing", async () => {
    installWriteAgent(world);
    const range = await service.write(world.session, input({ type: "u8", value: 256 }), op);
    expect(range.ok || range.error).toMatchObject({
      _tag: "InputError",
      issues: [{ path: "value", reason: "out_of_range" }],
    });
    world.handlers.describeAddresses = () => ok({ results: [] });
    const unmapped = await service.write(world.session, input({ hex: "00" }), op);
    expect(unmapped.ok || unmapped.error._tag).toBe("AddressUnmapped");
    expect(methods()).toEqual(["describeAddresses"]);
    const literals = await service.write(world.session, input({ hex: "00", sensitive_values: ["ab"] }), op);
    expect(literals.ok || literals.error._tag).toBe("InputError");
  });

  it("maps agent access violations to memory_access_failed with the instance id", async () => {
    installWriteAgent(world);
    world.handlers.writeMemory = () =>
      err({ _tag: "AccessViolation", message: "x", address: "0x10", operation: "write" });
    const result = await service.write(world.session, input({ hex: "00" }), op);
    expect(result.ok || result.error).toMatchObject({
      _tag: "MemoryAccessFailed",
      access: "write",
      instance_id: world.session.instanceId,
    });
  });

  it("undoes the write when its effect cannot be recorded", async () => {
    installWriteAgent(world);
    world.failEffects = true;
    world.handlers.revertWrite = (p) =>
      ok({ write_id: p.write_id, reverted: true, current_before_revert: "00", after: "00" });
    const result = await service.write(world.session, input({ hex: "00" }), op);
    expect(result.ok).toBe(false);
    expect(world.agentCalls.at(-1)).toEqual({ method: "revertWrite", params: { write_id: "wr1", force: true } });
    expect(service.entries(SESSION_ID)).toEqual([]);
  });
});

describe("write handle kind (CI-B6)", () => {
  const written = async () => {
    installWriteAgent(world, { before: "aa" });
    const result = await service.write(world.session, input({ hex: "bb" }), op);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    return result.value.effect_id;
  };

  it("owns, lists and reverts fx_ handles through revertWrite", async () => {
    const fx = await written();
    const kind = service.handleKind;
    expect(kind.owns(fx)).toBe(true);
    expect(kind.owns(`fx_${"f".repeat(64)}`)).toBe(false);
    expect(kind.owns("scan_00000001")).toBe(false);
    expect(kind.doneCondition(fx)).toBeNull();
    expect(kind.list(SESSION_ID)).toEqual([
      {
        id: fx,
        kind: "write",
        sessionId: SESSION_ID,
        state: "active",
        summary: {
          effect: "memory-written",
          address: `0x${(MODULE_BASE + 0x3000n).toString(16)}`,
          size: 1,
          method: "direct",
        },
      },
    ]);
    world.handlers.revertWrite = (p) =>
      ok({ write_id: p.write_id, reverted: true, current_before_revert: "bb", after: "aa" });
    const stopped = await kind.stop(world.session, fx, op);
    expect(stopped).toEqual(ok({ id: fx, kind: "write", status: "reverted" }));
    expect(world.agentCalls.at(-1)).toEqual({ method: "revertWrite", params: { write_id: "wr1", force: false } });
    expect(world.transitions.at(-1)).toEqual({ id: fx, to: "reverted", ok: true, reason: "stop-requested" });
    expect(kind.get(fx)?.state).toBe("reverted");
    expect(await kind.stop(world.session, fx, op)).toEqual(ok({ id: fx, kind: "write", status: "already_ended" }));
  });

  it("reports revert-failed when the memory changed since the write, and allows a retry", async () => {
    const fx = await written();
    world.handlers.revertWrite = (p) =>
      err({ _tag: "WriteConflict", message: "x", write_id: p.write_id, address: "0x1", expected: "bb", actual: "cc" });
    expect(await service.handleKind.stop(world.session, fx, op)).toEqual(
      ok({ id: fx, kind: "write", status: "revert-failed" }),
    );
    expect(world.transitions.at(-1)).toMatchObject({ to: "revert-failed", ok: false, reason: "revert-error" });
    expect(service.handleKind.get(fx)?.state).toBe("failed");
    world.handlers.revertWrite = (p) =>
      ok({ write_id: p.write_id, reverted: true, current_before_revert: "cc", after: "aa" });
    expect(await service.handleKind.stop(world.session, fx, op)).toEqual(
      ok({ id: fx, kind: "write", status: "reverted" }),
    );
  });

  it("treats a write the agent no longer holds as already ended", async () => {
    const fx = await written();
    world.handlers.revertWrite = (p) => err({ _tag: "NotFound", message: "x", what: "write", id: p.write_id });
    expect(await service.handleKind.stop(world.session, fx, op)).toEqual(
      ok({ id: fx, kind: "write", status: "already_ended" }),
    );
    expect(service.handleKind.owns(fx)).toBe(false);
  });

  it("refuses unknown ids and drops handles when the session ends", async () => {
    const fx = await written();
    const unknown = await service.handleKind.stop(world.session, `fx_${"e".repeat(64)}`, op);
    expect(unknown.ok || unknown.error).toMatchObject({ _tag: "ReferenceNotFound", reference: { kind: "effect" } });
    expect(world.endedListeners).toHaveLength(1);
    world.endedListeners[0]?.({ sessionId: SESSION_ID, kind: "live", reason: "closed" });
    expect(service.handleKind.owns(fx)).toBe(false);
    expect(service.handleKind.list(SESSION_ID)).toEqual([]);
  });
});
