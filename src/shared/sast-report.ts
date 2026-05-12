/**
 * Pure transformation: SAST report JSON → list of seeds ready for state-mcp's
 * init_run. Lives in shared/ so both report-state-mcp and (potentially)
 * sast-remediation-mcp can do the join the same way. The orchestrator never
 * builds this array itself — that proved too error-prone for an LLM.
 *
 * The SAST report shape is documented in jschema/sast-report-schema.json.
 * Schema is generated from a single example; in particular, `decision` is
 * legitimately absent / null / object in the wild — extraction normalises
 * the three cases to `decision: object | null`.
 */

export type SastDecision = {
  type: string;
  comment: string | null;
  author: string | null;
  createDate: string | null;
};

export type InitRunSeed = {
  vulnerabilityHash: string;
  severity: string | null;
  cwe: string | null;
  title: string | null;
  decision: SastDecision | null;
};

export type ExtractOk = {
  ok: true;
  sastUuid: string;
  seeds: InitRunSeed[];
  totalOccurrences: number;
  targetFound: boolean;
};

export type ExtractErr = {
  ok: false;
  error: string;
};

export type ExtractResult = ExtractOk | ExtractErr;

type CatalogEntry = {
  code: string;
  description?: string;
  severity?: string;
  cwe?: string | null;
};

function asObject(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function asString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function firstSentence(text: string | null): string | null {
  if (!text) return null;
  const trimmed = text.trim();
  if (trimmed.length === 0) return null;
  // First terminator (.!?) followed by whitespace or end-of-string.
  const m = trimmed.match(/^[\s\S]*?[.!?](?=\s|$)/);
  const head = m ? m[0] : trimmed;
  return head.length > 240 ? head.slice(0, 240).trimEnd() + "…" : head;
}

function normalizeDecision(raw: unknown): SastDecision | null {
  const o = asObject(raw);
  if (!o) return null;
  const type = asString(o.type);
  if (!type) return null;
  return {
    type,
    comment: asString(o.comment),
    author: asString(o.author),
    createDate: asString(o.createDate),
  };
}

function buildCatalogIndex(report: Record<string, unknown>): Map<string, CatalogEntry> {
  const out = new Map<string, CatalogEntry>();
  const list = Array.isArray(report.vulnerabilitiesInfo) ? report.vulnerabilitiesInfo : [];
  for (const raw of list) {
    const o = asObject(raw);
    if (!o) continue;
    const code = asString(o.code);
    if (!code) continue;
    out.set(code, {
      code,
      description: asString(o.description) ?? undefined,
      severity: asString(o.severity) ?? undefined,
      cwe: o.cwe === null ? null : asString(o.cwe) ?? undefined,
    });
  }
  return out;
}

/**
 * Extract a flat list of per-occurrence seeds from a parsed SAST report.
 * Joins `resultInfo[].vulnerabilities[]` (per-occurrence) with
 * `vulnerabilitiesInfo[]` (catalog) on `code`. When `targetVulnHash` is set,
 * keeps only the single occurrence with that `vulnerabilityHash` (targeted
 * mode); otherwise returns every occurrence in document order.
 *
 * Returns `targetFound: false` if `targetVulnHash` is set but no occurrence
 * matches — the caller (init_run) uses that to abort the run before any
 * branch/index is created.
 */
export function extractInitRunSeeds(
  rawReport: unknown,
  opts: { targetVulnHash?: string }
): ExtractResult {
  const report = asObject(rawReport);
  if (!report) {
    return { ok: false, error: "report is not an object" };
  }
  const sastUuid = asString(report.taskUuid);
  if (!sastUuid) {
    return { ok: false, error: "report.taskUuid is missing" };
  }
  const resultInfo = Array.isArray(report.resultInfo) ? report.resultInfo : null;
  if (!resultInfo) {
    return { ok: false, error: "report.resultInfo is not an array" };
  }

  const catalog = buildCatalogIndex(report);
  const target = opts.targetVulnHash;

  const seeds: InitRunSeed[] = [];
  let totalOccurrences = 0;
  let targetFound = target == null;

  for (const rawArtifact of resultInfo) {
    const artifact = asObject(rawArtifact);
    if (!artifact) continue;
    const vulns = Array.isArray(artifact.vulnerabilities) ? artifact.vulnerabilities : [];
    for (const rawVuln of vulns) {
      const v = asObject(rawVuln);
      if (!v) continue;
      const hash = asString(v.vulnerabilityHash);
      const code = asString(v.code);
      if (!hash || !code) continue;
      totalOccurrences += 1;
      if (target != null && hash !== target) continue;
      if (target != null) targetFound = true;

      const cat = catalog.get(code);
      seeds.push({
        vulnerabilityHash: hash,
        severity: cat?.severity ?? null,
        cwe: cat?.cwe === undefined ? null : cat.cwe,
        title: firstSentence(cat?.description ?? null),
        decision: normalizeDecision(v.decision),
      });
    }
  }

  return { ok: true, sastUuid, seeds, totalOccurrences, targetFound };
}
