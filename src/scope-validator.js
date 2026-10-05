import { SecurityError } from "./safe-error.js";

const normalize = value => [...new Set((Array.isArray(value) ? value : String(value || "").split(/\s+/)).filter(Boolean))].sort();
export function validateScopes(actual, expected, { exact = true } = {}) {
  const have = normalize(actual); const want = normalize(expected);
  const missing = want.filter(scope => !have.includes(scope)); const unexpected = have.filter(scope => !want.includes(scope));
  if (missing.length || (exact && unexpected.length)) throw new SecurityError(`OAuth scope validation failed. Missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"}.`, "UNEXPECTED_OAUTH_SCOPES");
  return have;
}
