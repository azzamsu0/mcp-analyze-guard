export const mode = "ANALYZE";

export const allowlist = {
  ga4: [
    "auth_status",
    "list_accounts_and_properties",
    "overview",
    "realtime",
    "traffic_sources",
    "top_pages",
    "events",
    "conversions"
  ],
  gtm: [
    "auth_status",
    "list_accounts",
    "list_containers",
    "list_workspaces",
    "list_tags",
    "list_triggers",
    "list_variables",
    "list_built_in_variables",
    "get_tag"
  ],
  google_ads: [
    "auth_status",
    "customers",
    "overview",
    "campaigns",
    "campaign",
    "ad_groups",
    "keywords",
    "search_terms",
    "ads",
    "devices",
    "locations",
    "hours",
    "performance_max",
    "conversions",
    "realtime_summary",
    "recommendations",
    "conversion_actions"
  ],
  search_console: [
    "status",
    "sites",
    "sitemaps",
    "performance",
    "search_analytics",
    "queries",
    "pages",
    "countries",
    "devices",
    "search_appearance",
    "index_coverage",
    "coverage",
    "url_inspection",
    "index_status",
    "core_web_vitals"
  ],
  merchant_center: [
    "status",
    "account_info",
    "products",
    "product",
    "product_status",
    "diagnostics",
    "issues",
    "feeds",
    "feed_status",
    "destinations",
    "programs",
    "shipping_services",
    "tax_settings",
    "business_info",
    "opportunities",
    "performance_summary"
  ],
  clarity: [
    "overview",
    "traffic",
    "engagement",
    "pages",
    "devices",
    "locations",
    "sources",
    "rage_clicks",
    "dead_clicks",
    "script_errors"
  ],
  snapchat_ads: ["status", "ad_accounts", "campaigns", "insights"],
  pagespeed_crux: [
    "status",
    "pagespeed",
    "crux",
    "core_web_vitals",
    "opportunities",
    "diagnostics",
    "recommendations"
  ],
  // Zid exposes far more than this; only the three tools the dashboard reads
  // are listed. See actionAllowlist below — for this server the tool name is
  // not enough to know what a call does.
  zid: ["Orders", "Products", "Customers"]
};

/**
 * Second gate, for servers where one tool name covers several capabilities.
 *
 * Every other server here follows one tool, one capability: `top_pages` reads
 * pages and cannot do anything else, so a name-level allowlist decides the
 * question completely. Zid does not work that way. A single `Products` tool
 * takes an `action` argument whose enum includes `list` and `get` alongside
 * `create`, `update`, `bulk_update` and `delete` — the name reveals none of
 * that, and the store credential in the MCP URL grants all of it.
 *
 * So for Zid the allowlist is on (tool, action) pairs, and the default is
 * refusal: a tool listed here with an action that is not, or with no action
 * at all, is blocked. Adding a Zid tool to `allowlist` above without adding
 * its readable actions here leaves it unusable rather than unrestricted.
 */
export const actionAllowlist = {
  zid: {
    Orders: ["list", "get", "get_credit_notes", "list_reverse_reasons"],
    Products: ["list", "get", "get_settings"],
    Customers: ["list", "get"]
  }
};

const forbiddenPattern =
  /(create|update|edit|delete|remove|publish|submit|execute|pause|enable|disable|mutate|upload|reply|claim|bulk|raw_api)/i;

/** Name-level check, shared by `authorize` and the tool audit. */
function authorizeTool(server, tool) {
  if (mode !== "ANALYZE") throw new Error("Only ANALYZE mode is supported.");
  if (forbiddenPattern.test(tool)) throw new Error("Write-capable tool is blocked.");
  if (!allowlist[server]?.includes(tool)) {
    throw new Error("Tool is not in the ANALYZE allowlist.");
  }
  return true;
}

export function authorize(server, tool, args) {
  authorizeTool(server, tool);

  const actions = actionAllowlist[server];
  if (!actions) return true;

  // Fail closed: a server that declares action-level rules must declare them
  // for every tool it allows, or the tool is refused rather than waved past.
  const permitted = actions[tool];
  if (!permitted) throw new Error("Tool has no action allowlist for this server.");

  const action = args?.action;
  if (typeof action !== "string") throw new Error("Tool requires an explicit action.");
  if (forbiddenPattern.test(action)) throw new Error("Write-capable action is blocked.");
  if (!permitted.includes(action)) throw new Error("Action is not in the ANALYZE allowlist.");
  return true;
}

export function auditTools(server, tools) {
  // Names only — an audit lists what a server offers, and for action-gated
  // servers the arguments that decide a call do not exist yet at this point.
  return {
    allowed: tools.filter((tool) => {
      try {
        return authorizeTool(server, tool);
      } catch {
        return false;
      }
    }),
    blocked: tools.filter((tool) => {
      try {
        authorizeTool(server, tool);
        return false;
      } catch {
        return true;
      }
    })
  };
}

