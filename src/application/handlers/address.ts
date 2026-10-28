import type { ADDRESS_TOOLS } from "../../contracts/areas/address.js";
import { Deadline } from "../../domain/deadline.js";
import { canonicalHex } from "../../domain/hex.js";
import { err } from "../../domain/result.js";
import type { OperationContext } from "../../ports/sessions.js";
import { AddressServiceImpl } from "../address/AddressService.js";
import { runListModuleSymbols } from "../address/ListModuleSymbols.js";
import { runMapAddress } from "../address/MapAddress.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext, HandlersFor } from "../handlerContext.js";
import { notImplementedError } from "../notImplemented.js";
import { anySessionOp } from "../sessionAccess.js";
import { checkLocalInputPath } from "../localPaths.js";

/**
 * Handlers for area address (WP-ADDR): map_address and list_module_symbols run on a live or emulation session
 * through anySessionOp (exclusive: they may call the agent), or offline on `pe_path` without any session.
 */
let offlineOps = 0;

/** Offline calls are not admitted against a session; they get their own op context from the handler deadline. */
const offlineOp = (ctx: HandlerContext): OperationContext => ({
  opId: -++offlineOps,
  name: ctx.operation,
  signal: ctx.signal,
  deadline: Deadline.after(ctx.remainingMs()),
});

export const createAddressHandlers = (app: BeaApplication): HandlersFor<typeof ADDRESS_TOOLS> => {
  /** The real service (a test may install a fake AddressService port; these tools then report not-implemented). */
  const service = (): AddressServiceImpl | null =>
    app.services.address instanceof AddressServiceImpl ? app.services.address : null;
  const access = { mode: "exclusive", need: "agent" } as const;
  return {
    list_module_symbols: async (input, ctx) => {
      const svc = service();
      if (svc === null) return err(notImplementedError(ctx.operation));
      const evidence = app.services.evidence;
      if (input.pe_path !== undefined) {
        const local = await checkLocalInputPath(ctx.operation, "pe_path", input.pe_path, app.config.platform);
        if (!local.ok) return local;
        return runListModuleSymbols(
          svc,
          evidence,
          { kind: "file", imagePath: input.pe_path, runtimeBase: null },
          input,
          offlineOp(ctx),
        );
      }
      return anySessionOp(app, ctx, input.session_id ?? "", access, {
        live: (session, op) => runListModuleSymbols(svc, evidence, { kind: "live", session }, input, op),
        emulation: (handle, op) =>
          runListModuleSymbols(svc, evidence, { kind: "emulation", sessionId: handle.sessionId }, input, op),
      });
    },
    map_address: async (input, ctx) => {
      const svc = service();
      if (svc === null) return err(notImplementedError(ctx.operation));
      const evidence = app.services.evidence;
      if (input.pe_path !== undefined) {
        const local = await checkLocalInputPath(ctx.operation, "pe_path", input.pe_path, app.config.platform);
        if (!local.ok) return local;
        const runtimeBase = input.runtime_base === undefined ? null : BigInt(canonicalHex(input.runtime_base));
        return runMapAddress(
          svc,
          evidence,
          { kind: "file", imagePath: input.pe_path, runtimeBase },
          input,
          offlineOp(ctx),
        );
      }
      return anySessionOp(app, ctx, input.session_id ?? "", access, {
        live: (session, op) => runMapAddress(svc, evidence, { kind: "live", session }, input, op),
        emulation: (handle, op) =>
          runMapAddress(svc, evidence, { kind: "emulation", sessionId: handle.sessionId }, input, op),
      });
    },
  };
};
