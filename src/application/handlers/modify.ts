import type { MODIFY_TOOLS } from "../../contracts/areas/modify.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlersFor } from "../handlerContext.js";
import { createOverrideService, type OverrideService } from "../modify/overrideService.js";
import { createScriptService, type ScriptService } from "../modify/scriptService.js";
import { createWriteService, type WriteService } from "../modify/writeService.js";
import { liveOp } from "../sessionAccess.js";

interface ModifyServices {
  readonly writes: WriteService;
  readonly overrides: OverrideService;
  readonly scripts: ScriptService;
}

/**
 * One set of modify services per application: createToolHandlers may run more than once for an app (MCP server per
 * HTTP session), and the `write` handle kind must be registered exactly once (CI-B6).
 */
const SERVICES = new WeakMap<BeaApplication, ModifyServices>();
const servicesFor = (app: BeaApplication): ModifyServices => {
  const existing = SERVICES.get(app);
  if (existing !== undefined) return existing;
  const created: ModifyServices = {
    writes: createWriteService(app),
    overrides: createOverrideService(app),
    scripts: createScriptService(app),
  };
  app.services.handles.register(created.writes.handleKind);
  SERVICES.set(app, created);
  return created;
};

/**
 * Handlers for area modify (WP12). The gates (scope "always") are enforced by invokeTool before these run, so a
 * closed gate never admits a session or reaches the agent. All three need the agent and run in the session's
 * exclusive section (they change target state).
 */
export const createModifyHandlers = (app: BeaApplication): HandlersFor<typeof MODIFY_TOOLS> => {
  const { writes, overrides, scripts } = servicesFor(app);
  const exclusiveAgent = { mode: "exclusive", need: "agent" } as const;
  return {
    write_memory: (input, ctx) =>
      liveOp(app, ctx, input.session_id, exclusiveAgent, (session, op) => writes.write(session, input, op)),
    override_function: (input, ctx) =>
      liveOp(app, ctx, input.session_id, exclusiveAgent, (session, op) => overrides.install(session, input, op)),
    run_script: (input, ctx) =>
      liveOp(app, ctx, input.session_id, exclusiveAgent, (session, op) => scripts.run(session, input, op)),
  };
};
