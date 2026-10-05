import test from "node:test";
import assert from "node:assert/strict";
import { auditTools, authorize, mode } from "../src/policy.js";

test("agent is permanently analyze-only", () => {
  assert.equal(mode, "ANALYZE");
});

test("read tools are allowed", () => {
  assert.equal(authorize("ga4", "overview"), true);
  assert.equal(authorize("gtm", "list_tags"), true);
});

test("write, publish, and unknown tools fail closed", () => {
  assert.throws(() => authorize("gtm", "execute_set_tag_paused"));
  assert.throws(() => authorize("gtm", "publish"));
  assert.throws(() => authorize("ga4", "unknown_tool"));
});

test("tool audit blocks GTM controlled actions", () => {
  const result = auditTools("gtm", [
    "list_tags",
    "preview_set_tag_paused",
    "execute_set_tag_paused"
  ]);
  assert.deepEqual(result.allowed, ["list_tags"]);
  assert.deepEqual(result.blocked, [
    "preview_set_tag_paused",
    "execute_set_tag_paused"
  ]);
});

// Zid is the one server where the tool name does not decide what a call does:
// `Products` covers both `list` and `delete`, and the store credential in the
// MCP URL grants both. These lock the action-level gate that stands between
// a read-only dashboard and a tool that can empty the catalogue.
test("zid read actions are allowed", () => {
  assert.equal(authorize("zid", "Orders", { action: "list" }), true);
  assert.equal(authorize("zid", "Orders", { action: "get" }), true);
  assert.equal(authorize("zid", "Products", { action: "list" }), true);
  assert.equal(authorize("zid", "Customers", { action: "get" }), true);
});

test("zid write actions fail closed even on an allowed tool", () => {
  assert.throws(() => authorize("zid", "Products", { action: "delete" }));
  assert.throws(() => authorize("zid", "Products", { action: "create" }));
  assert.throws(() => authorize("zid", "Products", { action: "bulk_update" }));
  assert.throws(() => authorize("zid", "Orders", { action: "update_status" }));
  assert.throws(() => authorize("zid", "Orders", { action: "create_reverse" }));
});

test("zid calls without an explicit action are refused", () => {
  assert.throws(() => authorize("zid", "Products", {}));
  assert.throws(() => authorize("zid", "Products"));
});

test("zid tools outside the allowlist are refused whatever the action", () => {
  assert.throws(() => authorize("zid", "Coupons", { action: "list" }));
  assert.throws(() => authorize("zid", "Loyalty", { action: "list" }));
});
