import type { HandleKindSpec, HandleRegistry, HandleView } from "../../ports/handles.js";
import type { SessionId } from "../../ports/sessions.js";

/**
 * CI-B6: WP0-owned and complete (not a stub). WP-SCAN and WP-MODIFY register their kinds from their
 * handler factories (createScanHandlers / createModifyHandlers run before any tool call), so no shared file changes.
 */
export const createHandleRegistry = (): HandleRegistry => {
  const specs = new Set<HandleKindSpec>();
  return {
    register: (spec) => {
      specs.add(spec);
      return () => {
        specs.delete(spec);
      };
    },
    find: (id) => [...specs].find((spec) => spec.owns(id)),
    list: (sessionId: SessionId): readonly HandleView[] => [...specs].flatMap((spec) => spec.list(sessionId)),
  };
};
