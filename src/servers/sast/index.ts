#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";

import { makeTokenProvider } from "./auth.js";
import { SastClient } from "./client.js";
import { readCachedReport, writeCachedReport } from "./cache.js";
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
    "Corporate SAST report fetcher: request a report for a build, retrieve full JSON, or look up a single vulnerability by id without dumping the whole report into the agent context.",
});

mcpServer.registerTool(
  "request_report",
  {
    description:
      "POST commit hash + Nexus distribution URL to the SAST API. Returns the API response JSON; the report identifier comes back in the `uuid` field (alongside `type`, `status`, `format`) — pass that value as `reportUuid` to get_report.",
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
      "GET full SAST report by reportUuid. Top-level fields: taskUuid, practice, ci, createdAt, finishedAt, scanObjectInfo, vulnerabilityCounts, vulnerabilitiesInfo (catalog of vulnerability types keyed by `code`), resultInfo (per-artifact findings keyed by `code` + `vulnerabilityHash`). Caches the response on disk so subsequent get_vulnerability calls do not re-fetch.",
    inputSchema: {
      reportUuid: z.string().min(1).describe("Report UUID returned by request_report."),
    },
  },
  async ({ reportUuid }) => {
    try {
      const report = await client.getReport(reportUuid);
      await writeCachedReport(reportUuid, report);
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
      let report = await readCachedReport(reportUuid);
      if (report == null) {
        report = await client.getReport(reportUuid);
        await writeCachedReport(reportUuid, report);
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

async function main() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

main().catch((err) => {
  console.error(redactErrorMessage(err instanceof Error ? err.stack ?? err.message : String(err)));
  process.exit(1);
});
