import type { CALL_TOOLS } from "../../contracts/areas/call.js";
import type { BeaApplication } from "../BeaApplication.js";
import { runCallFunction } from "../call/callFunction.js";
import type { HandlersFor } from "../handlerContext.js";

/** Handlers for area call (WP11-CALL): call_function, the in-process oracle (DESIGN §6.2 #26). */
export const createCallHandlers = (app: BeaApplication): HandlersFor<typeof CALL_TOOLS> => ({
  call_function: (input, ctx) => runCallFunction(app, input, ctx),
});
