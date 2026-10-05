import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { ActionManager, ControlledAction, MODES, PolicyEngine, SecurityLogger, payloadFingerprint, redact, redactError, resolveMode, validateScopes } from "../src/index.js";

const fixture = () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-security-")); let now = Date.now();
  const logger = new SecurityLogger({ mcp: "test", logPath: path.join(dir, "security.jsonl"), clock: () => new Date(now) });
  const actions = new ActionManager({ statePath: path.join(dir, "actions.json"), clock: () => now, logger });
  const policy = new PolicyEngine({ mcp: "test", logger, rules: [{ host: "api.test", endpoint: "/items/1", methods: ["PATCH"], fields: ["paused"], write: true }] });
  return { dir, logger, actions, policy, tick: ms => { now += ms; } };
};

test("ANALYZE is the default and controlled action is required", () => {
  assert.equal(resolveMode(undefined), MODES.ANALYZE);
  const f = fixture(); const controlled = new ControlledAction({ mcp: "test", mode: MODES.ANALYZE, policy: f.policy, actions: f.actions, logger: f.logger });
  assert.throws(() => controlled.preview({ tool: "pause", resource: "items/1", request: { paused: true }, before: { paused: false }, after: { paused: true }, fields: ["paused"], policyInput: { host: "api.test", endpoint: "/items/1", method: "PATCH", fields: ["paused"] } }), /ANALYZE mode/);
});

test("allowlist fails closed for fields, delete, bulk and forbidden generic tools", () => {
  const { policy } = fixture();
  assert.throws(() => policy.authorize({ tool: "pause", host: "api.test", endpoint: "/items/1", method: "PATCH", fields: ["name"] }), /not allowlisted/);
  assert.throws(() => policy.authorize({ tool: "pause", host: "api.test", endpoint: "/items/1", method: "DELETE" }), /Delete/);
  assert.throws(() => policy.authorize({ tool: "pause", host: "api.test", endpoint: "/items/1", method: "PATCH", resourceCount: 2 }), /multiple-resource/);
  assert.throws(() => policy.authorize({ tool: "raw_api_call", host: "api.test", endpoint: "/items/1", method: "PATCH" }), /Forbidden tool/);
});

test("action IDs are five-minute, payload-bound and single-use", async () => {
  const f = fixture(); const controlled = new ControlledAction({ mcp: "test", mode: MODES.CONTROLLED_ACTION, policy: f.policy, actions: f.actions, logger: f.logger });
  const preview = controlled.preview({ tool: "pause", resource: "items/1", request: { paused: true }, before: { paused: false }, after: { paused: true }, fields: ["paused"], policyInput: { host: "api.test", endpoint: "/items/1", method: "PATCH", fields: ["paused"] } });
  assert.equal(preview.dry_run.message, "Dry Run not supported by this API.");
  assert.throws(() => f.actions.consume({ action_id: preview.action_id, expectedTool: "pause", userConfirmation: false }), /confirmation/);
  const result = await controlled.execute({ tool: "pause", action_id: preview.action_id, user_confirmation: true, operation: async action => ({ response: { ok: true }, after: action.after }) });
  assert.equal(result.after.paused, true);
  assert.throws(() => f.actions.consume({ action_id: preview.action_id, expectedTool: "pause", userConfirmation: true }), /already been used/);
  const expiring = controlled.preview({ tool: "pause", resource: "items/1", request: { paused: false }, before: { paused: true }, after: { paused: false }, fields: ["paused"], policyInput: { host: "api.test", endpoint: "/items/1", method: "PATCH", fields: ["paused"] } });
  f.tick(300001);
  assert.throws(() => f.actions.consume({ action_id: expiring.action_id, expectedTool: "pause", userConfirmation: true }), /expired/);
  assert.equal(payloadFingerprint({ b: 2, a: 1 }), payloadFingerprint({ a: 1, b: 2 }));
});

test("logger records lifecycle and redacts secrets", () => {
  const f = fixture();
  f.logger.log("failed", { tool: "x", resource: "Bearer abc.def.ghi", error_code: "FAIL", access_token: "secret" });
  const text = fs.readFileSync(path.join(f.dir, "security.jsonl"), "utf8");
  assert.doesNotMatch(text, /abc\.def\.ghi|"secret"/);
  assert.match(text, /REDACTED/);
  assert.deepEqual(redact({ Authorization: "Bearer hidden", nested: { apiKey: "key" } }), { Authorization: "[REDACTED]", nested: { apiKey: "[REDACTED]" } });
  const unsafe = new Error("failed with Authorization: Bearer abc.def.ghi cookie=session-value session_id=abc123 AIza123456789012345678901234567890");
  unsafe.stack = `${unsafe.message}\nclient_secret=do-not-show`;
  const safe = JSON.stringify(redactError(unsafe));
  assert.doesNotMatch(safe, /abc\.def\.ghi|session-value|abc123|AIza|do-not-show|stack/i);
});

test("scope validation rejects missing and unexpected scopes", () => {
  assert.deepEqual(validateScopes("scope.a scope.b", ["scope.b", "scope.a"]), ["scope.a", "scope.b"]);
  assert.throws(() => validateScopes("scope.a scope.extra", ["scope.a"]), /unexpected/);
});
