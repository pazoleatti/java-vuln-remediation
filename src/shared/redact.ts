/**
 * Strip credential-like substrings from messages before they reach logs or
 * tool responses. Best-effort, header-shaped patterns only — the real
 * defence is never including the token in error paths in the first place.
 */
export function redactErrorMessage(input: string): string {
  return input
    .replace(/Authorization:\s*Bearer\s+\S+/gi, "Authorization: Bearer [REDACTED]")
    .replace(/"authorization"\s*:\s*"[^"]*"/gi, '"authorization":"[REDACTED]"')
    .replace(/Bearer\s+[A-Za-z0-9._\-+/=]{20,}/g, "Bearer [REDACTED]");
}
