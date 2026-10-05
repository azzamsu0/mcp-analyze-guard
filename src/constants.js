export const MODES = Object.freeze({ ANALYZE: "ANALYZE", CONTROLLED_ACTION: "CONTROLLED_ACTION" });
export const EVENTS = Object.freeze(["previewed", "dry_run", "confirmed", "executed", "succeeded", "failed", "cancelled", "blocked"]);
export const FORBIDDEN_TOOL_NAMES = Object.freeze(["update_anything", "execute_request", "raw_api_call", "arbitrary_mutation", "generic_patch", "generic_post"]);
export const FORBIDDEN_METHODS = Object.freeze(["DELETE"]);
export const ACTION_TTL_MS = 5 * 60 * 1000;
