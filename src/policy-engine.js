import { FORBIDDEN_METHODS, FORBIDDEN_TOOL_NAMES } from "./constants.js";
import { SecurityError } from "./safe-error.js";

const matches = (rule, value) => rule instanceof RegExp ? rule.test(value) : rule === value;

export class PolicyEngine {
  constructor({ mcp, rules = [], logger }) { this.mcp = mcp; this.rules = rules; this.logger = logger; }
  authorize({ tool, host, endpoint, method = "GET", fields = [], resourceCount = 1, bulk = false, scheduled = false, background = false, action_id = null }) {
    const normalizedMethod = String(method).toUpperCase();
    const block = (code, message) => { this.logger?.log("blocked", { tool, resource: endpoint, action_id, error_code: code }); throw new SecurityError(message, code); };
    if (FORBIDDEN_TOOL_NAMES.includes(tool)) block("FORBIDDEN_TOOL", `Forbidden tool: ${tool}`);
    if (FORBIDDEN_METHODS.includes(normalizedMethod)) block("DELETE_BLOCKED", "Delete operations are blocked.");
    if (bulk || resourceCount !== 1) block("MULTIPLE_RESOURCES_BLOCKED", "Bulk and multiple-resource operations are blocked.");
    if (scheduled || background) block("DEFERRED_EXECUTION_BLOCKED", "Scheduled and background execution are blocked.");
    const rule = this.rules.find(item => matches(item.host, host) && matches(item.endpoint, endpoint) && item.methods.map(v => v.toUpperCase()).includes(normalizedMethod));
    if (!rule) block("NOT_ALLOWLISTED", `Operation is not allowlisted: ${normalizedMethod} ${host}${endpoint}`);
    const allowed = new Set(rule.fields || []);
    const unexpected = fields.filter(field => !allowed.has(field));
    if (unexpected.length) block("FIELDS_NOT_ALLOWLISTED", `Fields are not allowlisted: ${unexpected.join(", ")}`);
    return rule;
  }
}
