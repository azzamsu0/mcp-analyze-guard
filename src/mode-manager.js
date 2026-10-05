import { MODES } from "./constants.js";
import { SecurityError } from "./safe-error.js";

export function resolveMode(value = process.env.MCP_MODE) {
  const mode = String(value || MODES.ANALYZE).toUpperCase();
  if (!Object.values(MODES).includes(mode)) throw new SecurityError(`Invalid MCP mode: ${mode}`, "INVALID_MODE");
  return mode;
}

export function requireControlledMode(mode) {
  if (mode !== MODES.CONTROLLED_ACTION) throw new SecurityError("Write operation blocked: MCP is in ANALYZE mode.", "ANALYZE_MODE_WRITE_BLOCKED");
}
