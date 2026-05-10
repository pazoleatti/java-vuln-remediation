---
name: sast-fetch-report
description: Methodology for the SAST Orchestrator on how to fetch a corporate SAST report at the start of a run — call `sast-remediation-mcp.request_report` with the commit hash + Nexus URL, wait for the report to become ready by polling `get_report`, and return the parsed JSON. Covers the request/response envelope shape, the readiness state machine, retry/back-off policy, and which errors abort the run vs. which are transient. Loaded only by `sast-orchestrator`; the Triage and Fix agents never fetch reports themselves.
---

# Fetch SAST report — orchestrator procedure

Use this skill at the very beginning of `/sast-run`, before any state is initialised. The output of this skill is **the full SAST report JSON** in memory, which the orchestrator then feeds into `report-state-mcp.init_run`. Nothing else in the run can proceed without it.

## Inputs

The slash-command supplies two parameters:

- `--commit=<hash>` — git commit the SAST scan should be associated with. Forwarded as `commitHash`.
- `--nexus=<url>` — URL of the built artifact in the corp Nexus. Forwarded as `distributionUrl`.

Both are required. If either is missing, abort the run with a clear message — do **not** invent defaults, do **not** read them from the environment.

## Tool surface

You use exactly two tools from `sast-remediation-mcp`:

- `request_report({ commitHash, distributionUrl })` — kicks off a scan, returns the report envelope.
- `get_report({ reportUuid })` — fetches the full report JSON; also serves as the readiness probe.

You do **not** call `get_vulnerability` here — that is for the Triage Agent, after `init_run` has populated state.

## Step 1 — request the report

Call `request_report({ commitHash, distributionUrl })`. The response is an envelope, not the report itself:

```jsonc
{
  "uuid":   "string",  // <— this is the reportUuid you pass to get_report
  "type":   "EXTENDED",
  "status": "PENDING|IN_PROGRESS|READY|FAILED",
  "format": "JSON"
}
```

**Capture `uuid` immediately** and record it in the run log (you will print it in the final report header). The other envelope fields are status metadata, not report content.

If `status == "FAILED"` already on the first response, **abort the run**. The corp pipeline rejected the request — usually a bad commit hash, a Nexus URL the SAST host cannot reach, or an expired JWT. Do not retry; surface the error string verbatim (it has already been redacted by the MCP).

If `status == "READY"` on the first response (cached prior scan), skip step 2 and go straight to step 3.

Otherwise (`PENDING` / `IN_PROGRESS`), proceed to step 2.

## Step 2 — wait for readiness

The corp SAST scan is asynchronous; readiness is signalled by `get_report` switching from "envelope-shaped" to "report-shaped". Poll:

```
loop:
  res = get_report({ reportUuid: uuid })
  if res looks like a report (has `vulnerabilitiesInfo` and `resultInfo` arrays): break
  if res.status == "FAILED": abort run
  if res.status in ("PENDING", "IN_PROGRESS"): wait, then retry
```

**Polling policy:**

- Initial wait: **30 seconds**.
- Back-off: linear, `30s → 45s → 60s → 60s → ...` capped at 60 s.
- Hard timeout: **20 minutes** total wall-clock from the first `request_report`. If still not ready, abort with `SAST scan did not become ready within 20 min for commit <hash>` and tell the operator to re-run later.
- Maximum **40 poll attempts** as a secondary safety cap.

Do not poll faster than 30 s — the corp SAST host rate-limits aggressively, and a 429 from `get_report` will surface as an opaque error here.

## Step 3 — validate the report shape

Once `get_report` returns a report-shaped object, before handing it to `init_run`, sanity-check:

1. `vulnerabilitiesInfo` is an array (may be empty).
2. `resultInfo` is an array (may be empty).
3. `scanObjectInfo.hash` exists and **equals the `--commit` arg**. If they differ, abort — the corp system associated the scan with a different commit, which would mean Triage/Fix agents reason against the wrong tree. Do not silently proceed.
4. `taskUuid` is present (used in the run header).

A report with **zero findings** (`vulnerabilitiesInfo.length === 0` AND every `resultInfo[].vulnerabilities` empty) is a valid outcome — finish the run early with a short "no findings" report; do **not** create a fix branch, do **not** call `code-index.build_deep_index`, do **not** call `init_run` with an empty array.

For full field semantics see the **`sast-report-format`** skill — it is the single source of truth on report shape. This skill only describes the fetch lifecycle.

## Error classification

| Error class | Examples | Action |
|---|---|---|
| **Configuration** | `SAST_API_BASE_URL is not set`, missing JWT file | Abort. The MCP server itself will not start; surface the exact message to the operator. |
| **Auth** | HTTP 401 / 403 from `request_report` or `get_report` | Abort. Token is invalid or expired. Do not retry; the operator must rotate the JWT. |
| **Bad input** | HTTP 400 / 404, "unknown commit", "distribution not found in Nexus" | Abort with the corp error message. Re-running with the same args will not help. |
| **Transient** | network timeout, HTTP 502 / 503 / 504 | Retry up to 3 times with the same back-off as the readiness poll, then abort. |
| **Scan failed** | envelope `status == "FAILED"` at any point | Abort. Surface the corp `errorMessage`/`comment` field if present. |

All error strings already pass through `redactErrorMessage` inside the MCP, so it is safe to include them verbatim in the final operator-facing report.

## Output contract — what this skill hands off

After this skill completes successfully, the orchestrator has, in scratchpad memory:

- `reportUuid` (string) — for later `get_vulnerability` calls by the Triage Agent.
- `report` (object) — the full report JSON.
- `report.scanObjectInfo.hash` — pinned commit; used to verify the working tree before fixes.
- `report.taskUuid` — for the run header.

Pass the **list of vulnerabilities** to `report-state-mcp.init_run` in **one call**, plus the `includeNotexploit` boolean from the orchestrator's `--include-notexploit` flag (default `false`). Build the list by joining each `resultInfo[].vulnerabilities[]` occurrence with its catalog entry from `vulnerabilitiesInfo[]` (key: `code`), and **forward the occurrence's `decision` field verbatim** so the MCP can apply the notexploit policy:

```jsonc
{
  sastUuid:           <reportUuid>,
  includeNotexploit:  <booleanFromOrchestratorFlag>,
  vulnerabilities: [
    {
      vulnerabilityId: <vulnerabilityHash>,   // primary key — see sast-report-format
      severity:        <catalog.severity>,
      cwe:             <catalog.cwe>,         // may be null
      title:           <catalog.description first sentence>,
      decision:        <occurrence.decision>  // pass through; null when absent
    }
  ]
}
```

`vulnerabilityHash` (not `code`) is the per-occurrence id — use it as the state-mcp primary key. `code` is many-to-one and is only useful when reasoning about a class.

**Do not pre-filter the array client-side.** Always send every occurrence; the MCP seeds findings with `decision.type == "notexploit"` as `skipped_notexploit` (when `includeNotexploit` is false) and the rest as `pending`. The response includes a `skippedNotexploit` count — record it for the final report header.

## Hard rules

1. **Never log the JWT or full Authorization header.** All error strings from the MCP are already redacted; do not re-format them in a way that could un-redact (e.g. don't `JSON.parse` an error string and re-`JSON.stringify` parts of it).
2. **Never call `get_report` before `request_report` has returned a `uuid`.** There is no list-reports endpoint; you only ever look up reports the current run created.
3. **Never proceed to `init_run` with a malformed report.** If shape validation (step 3) fails, abort. The cost of a corrupted run far exceeds the cost of the operator re-issuing the slash-command.
4. **Never retry on auth errors.** A 401/403 means the JWT is bad; retrying will at best waste time and at worst lock the account.
5. **Do not call this skill twice in the same run.** The fetched report is pinned for the whole run; if a later phase needs the report again, read it from the orchestrator's scratchpad or have the appropriate sub-agent call `get_vulnerability` (which reads from the on-disk cache).
