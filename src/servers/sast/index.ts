#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";

import { makeTokenProvider } from "./auth.js";
import { SastClient } from "./client.js";
import {
  readCachedReportByCommit,
  writeCachedReportByCommit,
  findCachedReportByUuid,
  clearCache,
} from "./cache.js";
import { redactErrorMessage } from "../../shared/redact.js";

type CatalogEntry = {
  code: string;
  description?: string;
  fixGuide?: string;
  severity?: string;
  cwe?: string | null;
};

type Occurrence = {
  artifactName: string;
  code: string;
  vulnerabilityHash: string;
  location?: unknown;
  decision?: unknown;
  dates?: unknown;
};

type VulnerabilityView = {
  matchedBy: "code" | "vulnerabilityHash";
  catalog: CatalogEntry | null;
  occurrences: Occurrence[];
};

/**
 * Typed lookup against the SAST report shape (see jschema/sast-report-schema.json).
 * The identifier is either a vulnerability `code` (returns all occurrences of that
 * type across artifacts) or a `vulnerabilityHash` (returns the single instance).
 * Catalog metadata (description / fixGuide / severity / cwe) lives in
 * `vulnerabilitiesInfo[]`; per-artifact instances live in `resultInfo[].vulnerabilities[]`.
 */
function findVulnerability(report: unknown, identifier: string): VulnerabilityView | null {
  if (!report || typeof report !== "object") return null;
  const r = report as Record<string, unknown>;

  const catalogList = Array.isArray(r.vulnerabilitiesInfo) ? r.vulnerabilitiesInfo : [];
  const resultList = Array.isArray(r.resultInfo) ? r.resultInfo : [];

  const occurrences: Occurrence[] = [];
  let matchedBy: "code" | "vulnerabilityHash" | null = null;

  for (const artifact of resultList) {
    if (!artifact || typeof artifact !== "object") continue;
    const a = artifact as Record<string, unknown>;
    const artifactName = typeof a.artifactName === "string" ? a.artifactName : "";
    const vulns = Array.isArray(a.vulnerabilities) ? a.vulnerabilities : [];
    for (const v of vulns) {
      if (!v || typeof v !== "object") continue;
      const vo = v as Record<string, unknown>;
      const code = typeof vo.code === "string" ? vo.code : "";
      const hash = typeof vo.vulnerabilityHash === "string" ? vo.vulnerabilityHash : "";
      if (hash === identifier) {
        matchedBy = "vulnerabilityHash";
        occurrences.push({ artifactName, code, vulnerabilityHash: hash, location: vo.location, decision: vo.decision, dates: vo.dates });
      } else if (code === identifier) {
        if (matchedBy == null) matchedBy = "code";
        occurrences.push({ artifactName, code, vulnerabilityHash: hash, location: vo.location, decision: vo.decision, dates: vo.dates });
      }
    }
  }

  const catalogCode = matchedBy === "vulnerabilityHash" ? occurrences[0]?.code : identifier;
  let catalog: CatalogEntry | null = null;
  for (const c of catalogList) {
    if (!c || typeof c !== "object") continue;
    const co = c as Record<string, unknown>;
    if (typeof co.code === "string" && co.code === catalogCode) {
      catalog = {
        code: co.code,
        description: typeof co.description === "string" ? co.description : undefined,
        fixGuide: typeof co.fixGuide === "string" ? co.fixGuide : undefined,
        severity: typeof co.severity === "string" ? co.severity : undefined,
        cwe: co.cwe === null || typeof co.cwe === "string" ? (co.cwe as string | null) : undefined,
      };
      break;
    }
  }

  if (!catalog && occurrences.length === 0) return null;
  return { matchedBy: matchedBy ?? "code", catalog, occurrences };
}

type CompactVuln = {
  vulnerabilityHash: string;
  code: string;
  severity: string | null;
  artifactName: string;
  location: { line?: string; target?: string };
  decision: { type: string } | null;
};

/**
 * Compact per-occurrence projection for list_vulnerabilities. Joins
 * occurrences from `resultInfo[].vulnerabilities[]` with severity from the
 * `vulnerabilitiesInfo` catalog (matched on `code`). Skips the heavy fields
 * (description, fixGuide, full location text) so the response stays small
 * enough for an agent or operator to scan.
 */
function buildCompactList(report: unknown): CompactVuln[] {
  if (!report || typeof report !== "object") return [];
  const r = report as Record<string, unknown>;
  const catalog = Array.isArray(r.vulnerabilitiesInfo) ? r.vulnerabilitiesInfo : [];
  const result = Array.isArray(r.resultInfo) ? r.resultInfo : [];

  const severityByCode = new Map<string, string>();
  for (const c of catalog) {
    if (!c || typeof c !== "object") continue;
    const co = c as Record<string, unknown>;
    if (typeof co.code === "string" && typeof co.severity === "string") {
      severityByCode.set(co.code, co.severity);
    }
  }

  const out: CompactVuln[] = [];
  for (const a of result) {
    if (!a || typeof a !== "object") continue;
    const ao = a as Record<string, unknown>;
    const artifactName = typeof ao.artifactName === "string" ? ao.artifactName : "";
    const vulns = Array.isArray(ao.vulnerabilities) ? ao.vulnerabilities : [];
    for (const v of vulns) {
      if (!v || typeof v !== "object") continue;
      const vo = v as Record<string, unknown>;
      const code = typeof vo.code === "string" ? vo.code : "";
      const hash = typeof vo.vulnerabilityHash === "string" ? vo.vulnerabilityHash : "";
      const loc = vo.location && typeof vo.location === "object" ? (vo.location as Record<string, unknown>) : {};
      const dec = vo.decision && typeof vo.decision === "object" ? (vo.decision as Record<string, unknown>) : null;
      out.push({
        vulnerabilityHash: hash,
        code,
        severity: severityByCode.get(code) ?? null,
        artifactName,
        location: {
          line: typeof loc.line === "string" ? loc.line : undefined,
          target: typeof loc.target === "string" ? loc.target : undefined,
        },
        decision: dec && typeof dec.type === "string" ? { type: dec.type } : null,
      });
    }
  }
  return out;
}

function extractCommitHash(report: unknown): string | null {
  if (!report || typeof report !== "object") return null;
  const so = (report as Record<string, unknown>).scanObjectInfo;
  if (!so || typeof so !== "object") return null;
  const h = (so as Record<string, unknown>).hash;
  return typeof h === "string" && h.length > 0 ? h : null;
}

function extractTaskUuid(report: unknown): string | null {
  if (!report || typeof report !== "object") return null;
  const t = (report as Record<string, unknown>).taskUuid;
  return typeof t === "string" && t.length > 0 ? t : null;
}

const baseUrl = process.env.SAST_API_BASE_URL?.trim();
if (!baseUrl) {
  console.error(
    "[sast-mcp] SAST_API_BASE_URL is not set. Refusing to start — pointing at the wrong host could leak the JWT to a third party."
  );
  process.exit(1);
}

const tokenProvider = makeTokenProvider();
const client = new SastClient(baseUrl, tokenProvider);

const mcpServer = new McpServer({
  name: "sast-remediation-mcp",
  version: "0.1.0",
  description:
    "Corporate SAST report fetcher: request a report for a build, retrieve full JSON, look up a single vulnerability or a compact list, and manage the per-commit-hash report cache.",
});

mcpServer.registerTool(
  "request_report",
  {
    description:
      "POST commit hash + Nexus distribution URL to the SAST API and return the API response JSON. The report identifier comes back in the `uuid` field — pass that value as `reportUuid` to get_report. Reads from a per-commit-hash cache when available: if a previous run already fetched a report for this commit, returns a synthesized response `{ uuid: <cached.taskUuid>, status: \"READY\", cached: true }` without calling the API. Cache is cleared only manually via clear_cache.",
    inputSchema: {
      commitHash: z.string().min(1).describe("Git commit hash the SAST scan should be associated with."),
      distributionUrl: z
        .string()
        .min(1)
        .describe("URL of the built artifact in Nexus that should be scanned."),
    },
  },
  async ({ commitHash, distributionUrl }) => {
    try {
      const cached = await readCachedReportByCommit(commitHash);
      const cachedUuid = extractTaskUuid(cached);
      if (cached && cachedUuid) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { uuid: cachedUuid, status: "READY", cached: true },
                null,
                2
              ),
            },
          ],
        };
      }
      const result = await client.requestReport({ commitHash, distributionUrl });
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        isError: true,
        content: [{ type: "text" as const, text: redactErrorMessage(msg) }],
      };
    }
  }
);

mcpServer.registerTool(
  "get_report",
  {
    description:
      "GET full SAST report by reportUuid. Top-level fields: taskUuid, practice, ci, createdAt, finishedAt, scanObjectInfo, vulnerabilityCounts, vulnerabilitiesInfo (catalog of vulnerability types keyed by `code`), resultInfo (per-artifact findings keyed by `code` + `vulnerabilityHash`). First scans the commit-hash cache for a matching taskUuid; on miss, fetches from the API and stores the result keyed by `scanObjectInfo.hash` so subsequent calls hit the cache.",
    inputSchema: {
      reportUuid: z.string().min(1).describe("Report UUID returned by request_report."),
    },
  },
  async ({ reportUuid }) => {
    try {
      const hit = await findCachedReportByUuid(reportUuid);
      if (hit) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify(hit.report, null, 2) }],
        };
      }
      const report = await client.getReport(reportUuid);
      const hash = extractCommitHash(report);
      if (hash) {
        await writeCachedReportByCommit(hash, report);
      }
      return {
        content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }],
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        isError: true,
        content: [{ type: "text" as const, text: redactErrorMessage(msg) }],
      };
    }
  }
);

mcpServer.registerTool(
  "get_vulnerability",
  {
    description:
      "Return a single vulnerability from a previously fetched report. Joins the catalog entry from `vulnerabilitiesInfo` (description, fixGuide, severity, cwe) with all matching occurrences from `resultInfo[].vulnerabilities` (artifactName, location, decision, dates). The identifier may be either a vulnerability `code` (returns every occurrence of that type across artifacts) or a `vulnerabilityHash` (returns the single specific finding). Falls back to fetching the report if the cache is cold.",
    inputSchema: {
      reportUuid: z.string().min(1),
      vulnerabilityId: z
        .string()
        .min(1)
        .describe("Either a vulnerability `code` (catalog id from vulnerabilitiesInfo) or a `vulnerabilityHash` (per-finding id from resultInfo)."),
    },
  },
  async ({ reportUuid, vulnerabilityId }) => {
    try {
      let report: unknown;
      const hit = await findCachedReportByUuid(reportUuid);
      if (hit) {
        report = hit.report;
      } else {
        report = await client.getReport(reportUuid);
        const hash = extractCommitHash(report);
        if (hash) await writeCachedReportByCommit(hash, report);
      }
      const found = findVulnerability(report, vulnerabilityId);
      if (!found) {
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text: `Vulnerability \`${vulnerabilityId}\` not found in report \`${reportUuid}\` (searched by code and vulnerabilityHash). Use get_report to inspect available identifiers.`,
            },
          ],
        };
      }
      return {
        content: [{ type: "text" as const, text: JSON.stringify(found, null, 2) }],
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        isError: true,
        content: [{ type: "text" as const, text: redactErrorMessage(msg) }],
      };
    }
  }
);

mcpServer.registerTool(
  "list_vulnerabilities",
  {
    description:
      "Return a compact per-occurrence list of vulnerabilities from the cached SAST report for a given commit hash. Each entry has `vulnerabilityHash`, `code`, `severity`, `artifactName`, `location.{line,target}`, and `decision.type|null` — the heavy `description` / `fixGuide` / full `location.text` fields are stripped so the response stays small. Cache-only: returns an error if no report is cached for this commit (run /sast-run --commit=<hash> --nexus=<url> or call request_report+get_report first).",
    inputSchema: {
      commit: z.string().min(1).describe("Git commit hash whose cached report to list."),
    },
  },
  async ({ commit }) => {
    try {
      const cached = await readCachedReportByCommit(commit);
      if (!cached) {
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text: `No cached SAST report for commit \`${commit}\`. Run /sast-run --commit=${commit} --nexus=<url> to populate the cache, or call request_report + get_report directly.`,
            },
          ],
        };
      }
      const list = buildCompactList(cached);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              { commit, count: list.length, vulnerabilities: list },
              null,
              2
            ),
          },
        ],
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        isError: true,
        content: [{ type: "text" as const, text: redactErrorMessage(msg) }],
      };
    }
  }
);

mcpServer.registerTool(
  "clear_cache",
  {
    description:
      "Invalidate the per-commit SAST report cache. Without `commit`, removes every cached report. With `commit=<hash>`, removes only that commit's entry. Returns `{ scope: 'all'|'commit', removed: <count> }`. No-op (removed: 0) if there was nothing to clear; this is not an error. Use this when the SAST team re-ran a scan on the same commit and the cached report is stale.",
    inputSchema: {
      commit: z
        .string()
        .min(1)
        .optional()
        .describe("Optional. Git commit hash whose cache entry to clear. If omitted, clears the whole cache."),
    },
  },
  async ({ commit }) => {
    try {
      const result = await clearCache(commit);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        isError: true,
        content: [{ type: "text" as const, text: redactErrorMessage(msg) }],
      };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

main().catch((err) => {
  console.error(redactErrorMessage(err instanceof Error ? err.stack ?? err.message : String(err)));
  process.exit(1);
});
