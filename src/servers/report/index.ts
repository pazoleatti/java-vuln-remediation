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
import { readCachedReportByCommit } from "../../shared/sast-cache.js";
import { extractInitRunSeeds } from "../../shared/sast-report.js";

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
  version: "0.2.0",
  description:
    "Persistent per-vulnerability state across qwen-cli sessions. Reads the cached SAST report directly to seed pending entries, then mediates strict phase transitions between Triage and Fix agents.",
});

// ────────────────────────────────────────────────────────────────────────────
// init_run — read cached SAST report, join catalog × occurrences, seed state.
// ────────────────────────────────────────────────────────────────────────────
mcpServer.registerTool(
  "init_run",
  {
    description:
      "Seed state-file entries for a SAST run by reading the cached corp SAST report for the given commit. The report must already be in the shared cache (request_report + get_report via sast-remediation-mcp). This server does the catalog × occurrences join and decision normalisation internally — the orchestrator does not build any array. Findings with decision.type === \"notexploit\" are seeded as \"skipped_notexploit\" (excluded from triage/fix) unless includeNotexploit=true; the original SAST decision is always persisted. When targetVulnHash is set, only the matching occurrence is seeded with includeNotexploit forced true (targeted mode); if the hash is not found the call returns targetFound:false and seeds nothing. Idempotent per (sastUuid, vulnerabilityHash).",
    inputSchema: {
      commit: z
        .string()
        .min(1)
        .describe("Git commit hash whose cached SAST report to read."),
      includeNotexploit: z
        .boolean()
        .optional()
        .default(false)
        .describe("When true, findings with decision.type === \"notexploit\" go through normal triage instead of being skipped. Default: false. Forced true when targetVulnHash is set."),
      targetVulnHash: z
        .string()
        .min(1)
        .optional()
        .describe("Targeted mode: seed only this one occurrence's vulnerabilityHash. All other findings of the report are skipped. includeNotexploit is forced true."),
    },
  },
  async ({ commit, includeNotexploit, targetVulnHash }) => {
    try {
      const cached = await readCachedReportByCommit(commit);
      if (cached == null) {
        return errorResult(
          `No cached SAST report for commit \`${commit}\`. Run sast-remediation-mcp.request_report + get_report first (or via /sast-run / /sast-list) to populate the cache.`
        );
      }

      const extracted = extractInitRunSeeds(cached, { targetVulnHash });
      if (!extracted.ok) {
        return errorResult(`malformed SAST report for commit \`${commit}\`: ${extracted.error}`);
      }

      const { sastUuid, seeds, totalOccurrences, targetFound } = extracted;

      if (targetVulnHash != null && !targetFound) {
        return textResult({
          sastUuid,
          commit,
          targetVulnHash,
          targetFound: false,
          totalOccurrences,
          added: 0,
          alreadyPresent: 0,
          skippedNotexploit: 0,
          totalForRun: 0,
        });
      }

      const effectiveIncludeNotexploit = targetVulnHash != null ? true : Boolean(includeNotexploit);

      const state = await readState();
      const existingKeys = new Set(
        state.vulnerabilities
          .filter((v) => v.sastUuid === sastUuid)
          .map((v) => v.vulnerabilityHash)
      );

      let added = 0;
      let alreadyPresent = 0;
      let skippedNotexploit = 0;

      for (const seed of seeds) {
        if (existingKeys.has(seed.vulnerabilityHash)) {
          alreadyPresent += 1;
          continue;
        }
        existingKeys.add(seed.vulnerabilityHash);
        const isNotexploit = seed.decision?.type === "notexploit";
        const status: VulnerabilityStatus =
          isNotexploit && !effectiveIncludeNotexploit ? "skipped_notexploit" : "pending";
        if (status === "skipped_notexploit") skippedNotexploit += 1;
        state.vulnerabilities.push({
          vulnerabilityHash: seed.vulnerabilityHash,
          sastUuid,
          severity: seed.severity,
          cwe: seed.cwe,
          title: seed.title,
          status,
          triageReasoning: null,
          fixCommitHash: null,
          fixSummary: null,
          regressionInstructions: null,
          failureReason: null,
          decision: seed.decision,
          timestamps: { triagedAt: null, fixedAt: null },
        });
        added += 1;
      }
      await writeState(state);

      return textResult({
        sastUuid,
        commit,
        statePath: statePathForDisplay(),
        targetVulnHash: targetVulnHash ?? null,
        targetFound: targetVulnHash != null ? true : null,
        includeNotexploit: effectiveIncludeNotexploit,
        totalOccurrences,
        considered: seeds.length,
        added,
        alreadyPresent,
        skippedNotexploit,
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
      vulnerabilityHash: z.string().min(1),
      sastUuid: z
        .string()
        .min(1)
        .optional()
        .describe("Required only if the same vulnerabilityHash exists across multiple SAST runs."),
    },
  },
  async ({ vulnerabilityHash, sastUuid }) => {
    try {
      const state = await readState();
      const result = findVulnState(state, vulnerabilityHash, sastUuid);
      if (result.kind === "missing") {
        return errorResult(
          `No state record for vulnerabilityHash=${vulnerabilityHash}${sastUuid ? ` sastUuid=${sastUuid}` : ""}.`
        );
      }
      if (result.kind === "ambiguous") {
        return errorResult(
          `vulnerabilityHash=${vulnerabilityHash} exists in multiple runs (${result.uuids.join(", ")}). Pass sastUuid to disambiguate.`
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
      "List vulnerability records filtered by status, optionally narrowed to a single SAST run. Returns light projections (vulnerabilityHash, sastUuid, severity, cwe, title, status) to keep agent context small.",
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
          vulnerabilityHash: v.vulnerabilityHash,
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
      vulnerabilityHash: z.string().min(1),
      sastUuid: z.string().min(1).optional(),
      decision: z.enum(["confirmed", "rejected"]),
      reasoning: z
        .string()
        .min(1)
        .describe("Motivated explanation for the verdict. For rejections this becomes the audit trail of why it was deemed a false positive."),
    },
  },
  async ({ vulnerabilityHash, sastUuid, decision, reasoning }) => {
    try {
      const state = await readState();
      const result = findVulnState(state, vulnerabilityHash, sastUuid);
      if (result.kind === "missing") {
        return errorResult(`No state record for vulnerabilityHash=${vulnerabilityHash}.`);
      }
      if (result.kind === "ambiguous") {
        return errorResult(
          `Ambiguous vulnerabilityHash=${vulnerabilityHash} (runs: ${result.uuids.join(", ")}). Pass sastUuid.`
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
      vulnerabilityHash: z.string().min(1),
      sastUuid: z.string().min(1).optional(),
      outcome: z.enum(["fixed", "fix_failed"]),
      commitHash: z.string().min(1).optional(),
      fixSummary: z.string().min(1).optional(),
      regressionInstructions: z.string().min(1).optional(),
      failureReason: z.string().min(1).optional(),
    },
  },
  async ({
    vulnerabilityHash,
    sastUuid,
    outcome,
    commitHash,
    fixSummary,
    regressionInstructions,
    failureReason,
  }) => {
    try {
      const state = await readState();
      const result = findVulnState(state, vulnerabilityHash, sastUuid);
      if (result.kind === "missing") {
        return errorResult(`No state record for vulnerabilityHash=${vulnerabilityHash}.`);
      }
      if (result.kind === "ambiguous") {
        return errorResult(
          `Ambiguous vulnerabilityHash=${vulnerabilityHash} (runs: ${result.uuids.join(", ")}). Pass sastUuid.`
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
      "Aggregated read of a run for the final report: counts by status, list of pending findings (those not picked up for triage — e.g. due to --limit), list of fix commits with summaries + regression notes, list of rejections with reasoning, list of failed fixes with failure reasons, list of findings skipped because the SAST report already marked them notexploit.",
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
        skipped_notexploit: 0,
      };
      for (const v of scope) counts[v.status] += 1;

      const pending = scope
        .filter((v) => v.status === "pending")
        .map((v) => ({
          vulnerabilityHash: v.vulnerabilityHash,
          sastUuid: v.sastUuid,
          severity: v.severity,
          cwe: v.cwe,
          title: v.title,
        }));
      const fixed = scope
        .filter((v) => v.status === "fixed")
        .map((v) => ({
          vulnerabilityHash: v.vulnerabilityHash,
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
          vulnerabilityHash: v.vulnerabilityHash,
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
          vulnerabilityHash: v.vulnerabilityHash,
          sastUuid: v.sastUuid,
          severity: v.severity,
          cwe: v.cwe,
          title: v.title,
          failureReason: v.failureReason,
        }));
      const skippedNotexploit = scope
        .filter((v) => v.status === "skipped_notexploit")
        .map((v) => ({
          vulnerabilityHash: v.vulnerabilityHash,
          sastUuid: v.sastUuid,
          severity: v.severity,
          cwe: v.cwe,
          title: v.title,
          decision: v.decision,
        }));

      return textResult({
        sastUuid: sastUuid ?? null,
        total: scope.length,
        counts,
        pending,
        fixed,
        rejected,
        failed,
        skippedNotexploit,
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
