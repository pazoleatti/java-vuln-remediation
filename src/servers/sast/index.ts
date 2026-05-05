#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";

import { makeTokenProvider } from "./auth.js";
import { SastClient } from "./client.js";
import { readCachedReport, writeCachedReport } from "./cache.js";
import { redactErrorMessage } from "../../shared/redact.js";

/**
 * BFS for an object with `id === vulnId` that looks like a vulnerability
 * (has at least one of: severity, cwe, locations, description). Schema-agnostic:
 * works regardless of how the corp report groups vulnerabilities by artifact.
 */
function findVulnerability(report: unknown, vulnId: string): unknown | null {
  const stack: unknown[] = [report];
  while (stack.length) {
    const node = stack.pop();
    if (Array.isArray(node)) {
      stack.push(...node);
    } else if (node && typeof node === "object") {
      const o = node as Record<string, unknown>;
      const isVulnLike =
        o.severity != null || o.cwe != null || o.locations != null || o.description != null;
      if (isVulnLike && (o.id === vulnId || o.uuid === vulnId)) return o;
      stack.push(...Object.values(o));
    }
  }
  return null;
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
      "POST commit hash + Nexus distribution URL to the SAST API. Returns whatever the API responds with (typically includes reportUuid).",
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
      "GET full SAST report by reportUuid. Caches the response on disk so subsequent get_vulnerability calls do not re-fetch.",
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
      "Return details of a single vulnerability (name, description, severity, CWE, guide, locations, resolution status) from a previously fetched report. Avoids loading the full report into agent context. Falls back to fetching the report if the cache is cold.",
    inputSchema: {
      reportUuid: z.string().min(1),
      vulnerabilityId: z
        .string()
        .min(1)
        .describe("Identifier of the vulnerability inside the report (matches `id` or `uuid` of the finding)."),
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
              text: `Vulnerability \`${vulnerabilityId}\` not found in report \`${reportUuid}\`. Use get_report to inspect available ids.`,
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
