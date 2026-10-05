# mcp-analyze-guard

A read-only policy engine for MCP servers.

When you connect an LLM agent to live marketing accounts — ad platforms with real budgets, a storefront with a real catalogue — the interesting question is not what the agent *should* do. It is what it *cannot* do, even when the model is wrong, the prompt is adversarial, or a tool is mislabelled.

This library answers that question with six independent gates. Every one of them fails closed.

## Background

This was extracted from a private marketing-intelligence platform I built for an e-commerce business. The platform connects an LLM agent to nine live sources — analytics, ad accounts with real budgets, a storefront — through MCP servers, and the agent is only ever allowed to read. The policy layer that enforces that is what you see here, published without the platform-specific code or any account data.

## The problem

An MCP server exposes tools to a model. The model picks which to call. Two assumptions quietly break:

**A tool's name tells you what it does.** Usually true. `top_pages` reads pages and cannot do anything else. But some APIs ship one tool per *resource*, not per *operation* — a single `Products` tool whose `action` argument accepts `list` and `get` alongside `create`, `update`, `bulk_update` and `delete`. The name reveals none of that, and one credential grants all of it.

**Read-only OAuth scopes exist.** Also usually true — `analytics.readonly`, `webmasters.readonly`. But Google Ads has no read-only scope at all: `adwords` is read *and* write. Merchant Center's `content` is the same. If your only defence is the scope, those two sources have no defence.

So the enforcement has to live in the application layer, and it has to assume both of the above are false.

## The six gates

| # | Gate | Where | Fails closed on |
|---|---|---|---|
| 1 | Mode is a constant, not configuration | `policy.js:1` | Any mode other than `ANALYZE` throws |
| 2 | Write-verb pattern | `policy.js:130` | 17 verbs, matched on tool **and** action |
| 3 | Name-level allowlist | `policy.js:3` | 89 tools, by exact name, across 9 sources |
| 4 | Action-level allowlist | `policy.js:122` | A listed tool with an unlisted or absent action |
| 5 | Request-shape engine | `policy-engine.js` | `DELETE`, bulk, multi-resource, scheduled, background, 6 generic tool names |
| 6 | OAuth scope validation | `scope-validator.js` | Missing *or* unexpected scopes, checked at runtime |

Gate 1 is deliberately not an environment variable. A mode you can flip from the outside is a mode an attacker can flip.

## Gate 4, the one worth reading

Most servers follow one tool, one capability, so gate 3 settles the question completely. The storefront integration does not:

```js
export const actionAllowlist = {
  zid: {
    Orders:    ["list", "get", "get_credit_notes", "list_reverse_reasons"],
    Products:  ["list", "get", "get_settings"],
    Customers: ["list", "get"]
  }
};
```

The default is refusal, in both directions:

- A tool in the name-allowlist with **no** entry here is refused, not waved past. Adding a tool without declaring its readable actions leaves it unusable rather than unrestricted.
- A call with **no** `action` argument is refused. Absence is not permission.

```js
authorize("zid", "Products", { action: "list"   });  // → true
authorize("zid", "Products", { action: "delete" });  // → throws
authorize("zid", "Products", {});                    // → throws
authorize("zid", "Coupons",  { action: "list"   });  // → throws
```

## Everything else is still hostile

Even a permitted read can leak. Two more pieces assume it will:

**Redaction before persistence.** `redactor.js` strips bearer tokens, JWTs, Google API keys, OAuth tokens and session cookies from strings, and nulls any object key matching a secret-shaped name — recursively, cycle-safe. Errors go through `redactError`, which drops the stack entirely rather than risk what is in it.

**An append-only audit trail.** `security-logger.js` writes one redacted JSONL record per event across a fixed vocabulary — `previewed`, `dry_run`, `confirmed`, `executed`, `succeeded`, `failed`, `cancelled`, `blocked` — at mode `0600`. Every refusal above is logged with its error code, so a blocked call leaves evidence rather than silence.

## Writes, if you ever enable them

`ANALYZE` is the only mode this repository ships in use. The `CONTROLLED_ACTION` path exists, is tested, and stays shut: a write requires a preview, a dry-run status, a fresh single-use confirmation, and an Action ID that is payload-bound (SHA-256 over a key-sorted serialisation) and expires in five minutes. Changing the payload after preview invalidates the ID. Reusing a consumed ID fails.

It is built so that turning writes on is a deliberate act with an audit trail, not a config toggle.

## Install

Not published to npm. Install straight from GitHub:

```bash
npm install github:azzamsu0/mcp-analyze-guard
```

Requires Node 20 or later.

## Usage

```js
import { authorize } from "mcp-analyze-guard/policy";

// Call this before dispatching any tool the model asked for.
authorize("ga4", "overview");                      // → true
authorize("gtm", "publish");                       // → throws
```

```js
import { redact, SecurityLogger, validateScopes } from "mcp-analyze-guard";

validateScopes(storedToken.scope, ["https://www.googleapis.com/auth/analytics.readonly"]);

const logger = new SecurityLogger({ mcp: "ga4", logPath: "./logs/ga4.jsonl" });
logger.log("blocked", { tool: "publish", error_code: "NOT_ALLOWLISTED" });
```

The allowlist in `src/policy.js` is a worked example covering GA4, Tag Manager, Google Ads, Search Console, Merchant Center, Clarity, Snapchat Ads, PageSpeed/CrUX and a storefront API. Replace it with your own surface — the gates do not care what the names are.

## Tests

```bash
npm test
```

13 tests. They assert the refusals, not the happy path: that `ANALYZE` cannot be left, that fields outside the allowlist are rejected, that an Action ID is single-use and payload-bound, that the logger does not write a secret it was handed, that scope validation rejects *unexpected* scopes and not only missing ones.

```bash
npm run audit:secrets
```

Scans the source for credential-shaped literals and for the return-shape patterns that leak a token into a tool response. Exits non-zero on any finding.

## No dependencies

Node's standard library only — `crypto`, `fs`, `path`. Nothing to audit transitively, nothing to pin.

## License

MIT
