import { requireControlledMode } from "./mode-manager.js";
import { redact } from "./redactor.js";

export class ControlledAction {
  constructor({ mcp, mode, policy, actions, logger }) { this.mcp = mcp; this.mode = mode; this.policy = policy; this.actions = actions; this.logger = logger; }
  preview({ tool, resource, request, before, after, fields, policyInput, dryRun }) {
    try { requireControlledMode(this.mode); } catch (error) { this.logger.log("blocked", { tool, resource, error_code: error.code }); throw error; }
    this.policy.authorize({ tool, resourceCount: 1, bulk: false, scheduled: false, background: false, ...policyInput });
    const dry = dryRun?.supported ? { supported: true, result: redact(dryRun.result) } : { supported: false, message: "Dry Run not supported by this API." };
    const created = this.actions.create({ mcp: this.mcp, tool, resource, payload: request, before, after, fields, dryRun: dry });
    this.logger.log("previewed", { tool, resource, action_id: created.action_id }); this.logger.log("dry_run", { tool, resource, action_id: created.action_id });
    return redact({ ...created, target_resource: resource, current_value: before, proposed_value: after, changed_fields: fields, dry_run: dry });
  }
  async execute({ tool, action_id, user_confirmation, operation }) {
    try { requireControlledMode(this.mode); } catch (error) { this.logger.log("blocked", { tool, action_id, user_confirmation: Boolean(user_confirmation), error_code: error.code }); throw error; }
    const action = this.actions.consume({ action_id, expectedTool: tool, userConfirmation: user_confirmation });
    this.logger.log("confirmed", { tool, resource: action.resource, action_id, user_confirmation: true }); const started = Date.now();
    this.logger.log("executed", { tool, resource: action.resource, action_id, user_confirmation: true });
    try { const apiResponse = await operation(action); const duration = Date.now() - started; this.logger.log("succeeded", { tool, resource: action.resource, action_id, user_confirmation: true, duration }); return redact({ action_id, target_resource: action.resource, before: action.before, after: apiResponse?.after ?? action.after, changed_fields: action.fields, undo: apiResponse?.undo || { supported: false, message: "Undo not supported by this API." }, api_response: apiResponse?.response ?? apiResponse }); }
    catch (error) { this.logger.log("failed", { tool, resource: action.resource, action_id, user_confirmation: true, duration: Date.now() - started, error_code: error?.code || "OPERATION_FAILED" }); throw error; }
  }
}
