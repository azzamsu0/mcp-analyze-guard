const SECRET_KEY = /(authorization|cookie|token|secret|api[-_]?key|developer[-_]?token|client[-_]?secret|password|credential|refresh[-_]?token|access[-_]?token|session[-_]?id|sessionid|set[-_]?cookie)/i;
const BEARER = /Bearer\s+[A-Za-z0-9._~+\-/]+=*/gi;
const JWT = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const GOOGLE_KEY = /AIza[0-9A-Za-z_-]{20,}/g;
const GOOGLE_OAUTH = /(?:ya29\.|1\/\/)[A-Za-z0-9._~-]+/g;
const COOKIE_TEXT = /\b(?:cookie|set-cookie|session(?:_?id)?)\s*[:=]\s*[^\s,;]+/gi;

export function redactString(value) {
  return String(value).replace(BEARER, "Bearer [REDACTED]").replace(JWT, "[REDACTED_JWT]").replace(GOOGLE_KEY, "[REDACTED_API_KEY]").replace(GOOGLE_OAUTH, "[REDACTED_OAUTH_TOKEN]").replace(COOKIE_TEXT, "[REDACTED_SESSION]");
}

export function redact(value, seen = new WeakSet()) {
  if (typeof value === "string") return redactString(value);
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);
  if (Array.isArray(value)) return value.map(item => redact(item, seen));
  const output = {};
  for (const [key, item] of Object.entries(value)) output[key] = SECRET_KEY.test(key) ? "[REDACTED]" : redact(item, seen);
  return output;
}

export function redactError(error) {
  return { name: error?.name || "Error", code: error?.code || "OPERATION_FAILED", message: redactString(error?.message || "Operation failed.") };
}
