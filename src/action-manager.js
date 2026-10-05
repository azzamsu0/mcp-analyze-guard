import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ACTION_TTL_MS } from "./constants.js";
import { SecurityError } from "./safe-error.js";

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  return value;
}
export const payloadFingerprint = value => crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");

export class ActionManager {
  constructor({ statePath, ttlMs = ACTION_TTL_MS, clock = () => Date.now(), logger }) { this.statePath = statePath; this.ttlMs = ttlMs; this.clock = clock; this.logger = logger; }
  read() { try { return JSON.parse(fs.readFileSync(this.statePath, "utf8")); } catch (e) { if (e.code === "ENOENT") return { actions: {} }; throw e; } }
  write(state) { fs.mkdirSync(path.dirname(this.statePath), { recursive: true }); const temp = `${this.statePath}.${process.pid}.tmp`; fs.writeFileSync(temp, JSON.stringify(state, null, 2), { mode: 0o600 }); fs.renameSync(temp, this.statePath); }
  create({ mcp, tool, resource, payload, before, after, fields, dryRun }) {
    const state = this.read(); const now = this.clock(); const action_id = crypto.randomBytes(24).toString("base64url");
    state.actions[action_id] = { mcp, tool, resource, payload, fingerprint: payloadFingerprint(payload), before, after, fields, dryRun, created_at: now, expires_at: now + this.ttlMs, status: "pending" };
    this.write(state); return { action_id, expires_at: new Date(now + this.ttlMs).toISOString(), fingerprint: state.actions[action_id].fingerprint };
  }
  consume({ action_id, expectedTool, userConfirmation }) {
    const state = this.read(); const action = state.actions[action_id];
    const reject = (code, message) => { this.logger?.log("blocked", { tool: expectedTool, resource: action?.resource, action_id, user_confirmation: Boolean(userConfirmation), error_code: code }); throw new SecurityError(message, code); };
    if (!action) reject("ACTION_NOT_FOUND", "Action ID not found.");
    if (action.status !== "pending") reject("ACTION_ALREADY_USED", "Action ID has already been used.");
    if (this.clock() > action.expires_at) { action.status = "expired"; this.write(state); reject("ACTION_EXPIRED", "Action ID has expired."); }
    if (action.tool !== expectedTool) reject("ACTION_TOOL_MISMATCH", "Action ID does not match this tool.");
    if (userConfirmation !== true) reject("CONFIRMATION_REQUIRED", "Fresh explicit user confirmation is required.");
    if (payloadFingerprint(action.payload) !== action.fingerprint) reject("PAYLOAD_CHANGED", "Stored action payload fingerprint does not match.");
    action.status = "consumed"; action.consumed_at = this.clock(); this.write(state); return action;
  }
  cancel(action_id, tool = null) { const state = this.read(); const action = state.actions[action_id]; if (!action || action.status !== "pending") throw new SecurityError("Pending Action ID not found.", "ACTION_NOT_PENDING"); action.status = "cancelled"; this.write(state); this.logger?.log("cancelled", { tool: tool || action.tool, resource: action.resource, action_id }); }
}
