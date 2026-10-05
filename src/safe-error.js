export class SecurityError extends Error {
  constructor(message, code = "SECURITY_POLICY_VIOLATION") {
    super(message);
    this.name = "SecurityError";
    this.code = code;
  }
}

export function safeError(error, redact = value => value) {
  return {
    code: String(error?.code || "OPERATION_FAILED"),
    message: String(redact(error?.message || "Operation failed."))
  };
}
