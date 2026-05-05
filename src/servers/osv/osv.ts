const OSV_BATCH = "https://api.osv.dev/v1/querybatch";

export type OsvVuln = {
  id: string;
  summary?: string;
  details?: string;
  modified?: string;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: string[];
  }>;
  references?: Array<{ type?: string; url?: string }>;
};

export type OsvBatchResult = { results: Array<{ vulns?: OsvVuln[] }> };

export async function osvQueryBatch(
  queries: Array<{ package: { name: string; ecosystem: string }; version: string }>
): Promise<OsvBatchResult> {
  const res = await fetch(OSV_BATCH, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ queries }),
  });
  if (!res.ok) {
    throw new Error(`OSV querybatch failed: ${res.status} ${await res.text()}`);
  }
  return (await res.json()) as OsvBatchResult;
}

export function vulnSummaries(vulns: OsvVuln[] | undefined): Map<string, string> {
  const m = new Map<string, string>();
  for (const v of vulns ?? []) {
    const text = (v.summary ?? v.details ?? "").trim().slice(0, 500);
    m.set(v.id, text || v.id);
  }
  return m;
}

export function extractFixedHints(vulns: OsvVuln[] | undefined): string[] {
  const hints: string[] = [];
  for (const v of vulns ?? []) {
    for (const aff of v.affected ?? []) {
      for (const r of aff.ranges ?? []) {
        for (const ev of r.events ?? []) {
          if (ev.fixed) hints.push(`${v.id}: fixed in ${ev.fixed}`);
        }
      }
    }
  }
  return [...new Set(hints)].slice(0, 20);
}
