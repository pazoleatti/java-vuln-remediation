#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";

import {
  findVulnState,
  readState,
  replaceVulnState,
  statePathForDisplay,
  writeState,
} from "./state.js";
import {
  vulnerabilityStatusSchema,
  type VulnerabilityState,
  type VulnerabilityStatus,
} from "./schema.js";

function nowIso(): string {
  return new Date().toISOString();
}

function textResult(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
}

function errorResult(message: string) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: message }],
  };
}

const mcpServer = new McpServer({
  name: "sast-report-state-mcp",
  version: "0.1.0",
  description:
    "Persistent per-vulnerability state across qwen-cli sessions. Ingests a SAST report into pending entries, then mediates strict phase transitions between Triage and Fix agents.",
});

// ────────────────────────────────────────────────────────────────────────────
// init_run
// ────────────────────────────────────────────────────────────────────────────
const initRunVulnSchema = z.object({
  vulnerabilityId: z.string().min(1).describe("Stable identifier of the finding from the SAST report."),
  severity: z.string().min(1).nullish(),
  cwe: z.string().min(1).nullish(),
  title: z.string().min(1).nullish(),
});

mcpServer.registerTool(
  "init_run",
  {
    description:
      "Seed pending entries in the state file from a pre-extracted vulnerability list. The orchestrator is responsible for fetching the SAST report (via sast-mcp) and extracting the array — this server is storage-only and does not parse the report. Idempotent per (sastUuid, vulnerabilityId): existing records are preserved, new findings are appended.",
    inputSchema: {
      sastUuid: z.string().min(1).describe("UUID of the SAST report this run corresponds to."),
      vulnerabilities: z
        .array(initRunVulnSchema)
        .min(1)
        .describe("Array of vulnerabilities to seed as pending in a single call."),
    },
  },
  async ({ sastUuid, vulnerabilities }) => {
    try {
      const state = await readState();
      const existingKeys = new Set(
        state.vulnerabilities
          .filter((v) => v.sastUuid === sastUuid)
          .map((v) => v.vulnerabilityId)
      );
      let added = 0;
      for (const v of vulnerabilities) {
        if (existingKeys.has(v.vulnerabilityId)) continue;
        existingKeys.add(v.vulnerabilityId);
        state.vulnerabilities.push({
          vulnerabilityId: v.vulnerabilityId,
          sastUuid,
          severity: v.severity ?? null,
          cwe: v.cwe ?? null,
          title: v.title ?? null,
          status: "pending",
          triageReasoning: null,
          fixCommitHash: null,
          fixSummary: null,
          regressionInstructions: null,
          failureReason: null,
          timestamps: { triagedAt: null, fixedAt: null },
        });
        added += 1;
      }
      await writeState(state);
      return textResult({
        sastUuid,
        statePath: statePathForDisplay(),
        received: vulnerabilities.length,
        added,
        alreadyPresent: vulnerabilities.length - added,
        totalForRun: state.vulnerabilities.filter((v) => v.sastUuid === sastUuid).length,
      });
    } catch (e) {
      return errorResult(e instanceof Error ? e.message : String(e));
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────
// get_vulnerability_state
// ────────────────────────────────────────────────────────────────────────────
mcpServer.registerTool(
  "get_vulnerability_state",
  {
    description: "Return the full state record for a single vulnerability.",
    inputSchema: {
      vulnerabilityId: z.string().min(1),
      sastUuid: z
        .string()
        .min(1)
        .optional()
        .describe("Required only if the same vulnerabilityId exists across multiple SAST runs."),
    },
  },
  async ({ vulnerabilityId, sastUuid }) => {
    try {
      const state = await readState();
      const result = findVulnState(state, vulnerabilityId, sastUuid);
      if (result.kind === "missing") {
        return errorResult(
          `No state record for vulnerabilityId=${vulnerabilityId}${sastUuid ? ` sastUuid=${sastUuid}` : ""}.`
        );
      }
      if (result.kind === "ambiguous") {
        return errorResult(
          `vulnerabilityId=${vulnerabilityId} exists in multiple runs (${result.uuids.join(", ")}). Pass sastUuid to disambiguate.`
        );
      }
      return textResult(result.record);
    } catch (e) {
      return errorResult(e instanceof Error ? e.message : String(e));
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────
// list_by_status
// ────────────────────────────────────────────────────────────────────────────
mcpServer.registerTool(
  "list_by_status",
  {
    description:
      "List vulnerability records filtered by status, optionally narrowed to a single SAST run. Returns light projections (id, sastUuid, severity, cwe, title, status) to keep agent context small.",
    inputSchema: {
      status: vulnerabilityStatusSchema,
      sastUuid: z.string().min(1).optional(),
    },
  },
  async ({ status, sastUuid }) => {
    try {
      const state = await readState();
      const items = state.vulnerabilities
        .filter((v) => v.status === status && (sastUuid == null || v.sastUuid === sastUuid))
        .map((v) => ({
          vulnerabilityId: v.vulnerabilityId,
          sastUuid: v.sastUuid,
          severity: v.severity,
          cwe: v.cwe,
          title: v.title,
          status: v.status,
        }));
      return textResult({ count: items.length, items });
    } catch (e) {
      return errorResult(e instanceof Error ? e.message : String(e));
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────
// update_triage_result — phase guard: pending → confirmed | rejected
// ────────────────────────────────────────────────────────────────────────────
mcpServer.registerTool(
  "update_triage_result",
  {
    description:
      "Triage Agent only. Records the triage verdict for a pending vulnerability. Allowed transitions: pending → confirmed | rejected. Refuses any other source status — Triage cannot overwrite a fix outcome.",
    inputSchema: {
      vulnerabilityId: z.string().min(1),
      sastUuid: z.string().min(1).optional(),
      decision: z.enum(["confirmed", "rejected"]),
      reasoning: z
        .string()
        .min(1)
        .describe("Motivated explanation for the verdict. For rejections this becomes the audit trail of why it was deemed a false positive."),
    },
  },
  async ({ vulnerabilityId, sastUuid, decision, reasoning }) => {
    try {
      const state = await readState();
      const result = findVulnState(state, vulnerabilityId, sastUuid);
      if (result.kind === "missing") {
        return errorResult(`No state record for vulnerabilityId=${vulnerabilityId}.`);
      }
      if (result.kind === "ambiguous") {
        return errorResult(
          `Ambiguous vulnerabilityId=${vulnerabilityId} (runs: ${result.uuids.join(", ")}). Pass sastUuid.`
        );
      }
      const current = result.record;
      if (current.status !== "pending") {
        return errorResult(
          `update_triage_result rejected: status is "${current.status}", expected "pending". Triage cannot modify post-triage state.`
        );
      }
      const updated: VulnerabilityState = {
        ...current,
        status: decision,
        triageReasoning: reasoning,
        timestamps: { ...current.timestamps, triagedAt: nowIso() },
      };
      const next = replaceVulnState(state, updated);
      await writeState(next);
      return textResult(updated);
    } catch (e) {
      return errorResult(e instanceof Error ? e.message : String(e));
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────
// update_fix_result — phase guard: confirmed | fix_failed → fixed | fix_failed
// ────────────────────────────────────────────────────────────────────────────
mcpServer.registerTool(
  "update_fix_result",
  {
    description:
      "Fix Agent only. Records the outcome of a fix attempt. Allowed source statuses: confirmed, fix_failed (retry). Refuses pending/rejected/fixed — Fix cannot triage and cannot overwrite a successful fix. For outcome=fixed, commitHash + fixSummary + regressionInstructions are required. For outcome=fix_failed, failureReason is required.",
    inputSchema: {
      vulnerabilityId: z.string().min(1),
      sastUuid: z.string().min(1).optional(),
      outcome: z.enum(["fixed", "fix_failed"]),
      commitHash: z.string().min(1).optional(),
      fixSummary: z.string().min(1).optional(),
      regressionInstructions: z.string().min(1).optional(),
      failureReason: z.string().min(1).optional(),
    },
  },
  async ({
    vulnerabilityId,
    sastUuid,
    outcome,
    commitHash,
    fixSummary,
    regressionInstructions,
    failureReason,
  }) => {
    try {
      const state = await readState();
      const result = findVulnState(state, vulnerabilityId, sastUuid);
      if (result.kind === "missing") {
        return errorResult(`No state record for vulnerabilityId=${vulnerabilityId}.`);
      }
      if (result.kind === "ambiguous") {
        return errorResult(
          `Ambiguous vulnerabilityId=${vulnerabilityId} (runs: ${result.uuids.join(", ")}). Pass sastUuid.`
        );
      }
      const current = result.record;
      if (current.status !== "confirmed" && current.status !== "fix_failed") {
        return errorResult(
          `update_fix_result rejected: status is "${current.status}", expected "confirmed" or "fix_failed". Fix Agent cannot operate on this record.`
        );
      }
      if (outcome === "fixed") {
        const missing: string[] = [];
        if (!commitHash) missing.push("commitHash");
        if (!fixSummary) missing.push("fixSummary");
        if (!regressionInstructions) missing.push("regressionInstructions");
        if (missing.length) {
          return errorResult(`outcome=fixed requires: ${missing.join(", ")}.`);
        }
      } else if (!failureReason) {
        return errorResult("outcome=fix_failed requires failureReason.");
      }
      const updated: VulnerabilityState =
        outcome === "fixed"
          ? {
              ...current,
              status: "fixed",
              fixCommitHash: commitHash ?? null,
              fixSummary: fixSummary ?? null,
              regressionInstructions: regressionInstructions ?? null,
              failureReason: null,
              timestamps: { ...current.timestamps, fixedAt: nowIso() },
            }
          : {
              ...current,
              status: "fix_failed",
              failureReason: failureReason ?? null,
              timestamps: { ...current.timestamps, fixedAt: nowIso() },
            };
      const next = replaceVulnState(state, updated);
      await writeState(next);
      return textResult(updated);
    } catch (e) {
      return errorResult(e instanceof Error ? e.message : String(e));
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────
// get_run_summary
// ────────────────────────────────────────────────────────────────────────────
mcpServer.registerTool(
  "get_run_summary",
  {
    description:
      "Aggregated read of a run for the final report: counts by status, list of fix commits with summaries + regression notes, list of rejections with reasoning, list of failed fixes with failure reasons.",
    inputSchema: {
      sastUuid: z.string().min(1).optional().describe("If omitted, summarises the entire state file."),
    },
  },
  async ({ sastUuid }) => {
    try {
      const state = await readState();
      const scope = sastUuid
        ? state.vulnerabilities.filter((v) => v.sastUuid === sastUuid)
        : state.vulnerabilities;

      const counts: Record<VulnerabilityStatus, number> = {
        pending: 0,
        rejected: 0,
        confirmed: 0,
        fixed: 0,
        fix_failed: 0,
      };
      for (const v of scope) counts[v.status] += 1;

      const fixed = scope
        .filter((v) => v.status === "fixed")
        .map((v) => ({
          vulnerabilityId: v.vulnerabilityId,
          sastUuid: v.sastUuid,
          severity: v.severity,
          cwe: v.cwe,
          title: v.title,
          fixCommitHash: v.fixCommitHash,
          fixSummary: v.fixSummary,
          regressionInstructions: v.regressionInstructions,
          fixedAt: v.timestamps.fixedAt,
        }));
      const rejected = scope
        .filter((v) => v.status === "rejected")
        .map((v) => ({
          vulnerabilityId: v.vulnerabilityId,
          sastUuid: v.sastUuid,
          severity: v.severity,
          cwe: v.cwe,
          title: v.title,
          triageReasoning: v.triageReasoning,
          triagedAt: v.timestamps.triagedAt,
        }));
      const failed = scope
        .filter((v) => v.status === "fix_failed")
        .map((v) => ({
          vulnerabilityId: v.vulnerabilityId,
          sastUuid: v.sastUuid,
          severity: v.severity,
          cwe: v.cwe,
          title: v.title,
          failureReason: v.failureReason,
        }));

      return textResult({
        sastUuid: sastUuid ?? null,
        total: scope.length,
        counts,
        fixed,
        rejected,
        failed,
      });
    } catch (e) {
      return errorResult(e instanceof Error ? e.message : String(e));
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack ?? err.message : String(err));
  process.exit(1);
});
