export interface IngestedVuln {
  id: string;
  severity: string | null;
  cwe: string | null;
  title: string | null;
}

function stringOrNull(v: unknown): string | null {
  if (v == null) return null;
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return null;
}

/**
 * Schema-agnostic BFS over the SAST report tree. A node is treated as a vulnerability
 * iff it has an `id` (or `uuid`) AND at least one of severity/cwe/locations/description.
 * Mirrors the heuristic used by sast-mcp's findVulnerability so both servers see the
 * same set of findings without depending on a fixed corp schema.
 */
export function ingestVulnerabilities(report: unknown): IngestedVuln[] {
  const out: IngestedVuln[] = [];
  const seen = new Set<string>();
  const stack: unknown[] = [report];
  while (stack.length) {
    const node = stack.pop();
    if (Array.isArray(node)) {
      stack.push(...node);
      continue;
    }
    if (!node || typeof node !== "object") continue;
    const o = node as Record<string, unknown>;
    const id = stringOrNull(o.id) ?? stringOrNull(o.uuid);
    const isVulnLike =
      o.severity != null || o.cwe != null || o.locations != null || o.description != null;
    if (isVulnLike && id && !seen.has(id)) {
      seen.add(id);
      out.push({
        id,
        severity: stringOrNull(o.severity),
        cwe: stringOrNull(o.cwe),
        title: stringOrNull(o.title) ?? stringOrNull(o.name),
      });
    }
    stack.push(...Object.values(o));
  }
  return out;
}
