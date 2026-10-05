import fs from "node:fs";
import path from "node:path";
import { EVENTS } from "./constants.js";
import { redact } from "./redactor.js";

export class SecurityLogger {
  /**
   * Each server passes a logPath inside its own folder, which is fine on a
   * workstation but not in a container, where the code sits on a read-only
   * layer. SECURITY_LOG_DIR redirects every server's audit trail to one
   * writable volume; the file is named after the mcp so they stay separate.
   * Resolved here rather than in each server: eight servers build this path in
   * five different shapes, and the audit trail should not depend on which.
   */
  constructor({ mcp, logPath, clock = () => new Date() }) {
    this.mcp = mcp;
    const centralDir = process.env.SECURITY_LOG_DIR;
    this.logPath = centralDir ? path.join(centralDir, `${mcp}.jsonl`) : logPath;
    this.clock = clock;
  }
  log(event, details = {}) {
    if (!EVENTS.includes(event)) throw new Error(`Unsupported security event: ${event}`);
    const record = redact({ timestamp: this.clock().toISOString(), mcp: this.mcp, tool: details.tool || null, resource: details.resource || null, action_id: details.action_id || null, status: event, duration: details.duration ?? null, user_confirmation: details.user_confirmation ?? false, error_code: details.error_code || null });
    fs.mkdirSync(path.dirname(this.logPath), { recursive: true });
    fs.appendFileSync(this.logPath, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
    return record;
  }
}
