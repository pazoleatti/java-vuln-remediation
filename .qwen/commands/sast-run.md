---
description: Run the full SAST remediation pipeline for a given commit + Nexus build — fetch the corp SAST report, triage every finding (one isolated triage-agent per vulnerability), fix every confirmed finding (one isolated fix-agent per vulnerability, strictly sequential), and produce an operator-facing markdown report plus a fix branch with one atomic commit per fix.
---

# /sast-run — SAST remediation pipeline

Operator invocation:

```
/sast-run --commit=<hash> --nexus=<url> [--jira=<KEY>] [--limit=<N>]
```

Raw argument string from the operator: `{{args}}`

## Your role for this command

For the duration of this run you act as the **`sast-orchestrator`** Named Subagent (`.qwen/agents/sast-orchestrator.md`). Load and follow that agent's instructions: the tool allowlist, the hard constraints (no commits, no source edits, no triage logic, strictly sequential fixes, fail-fast on `code-index`, frozen index between phases), and the four-phase flow described below.

You also have the following **skills** available — load and consult them at the points indicated:

- `sast-fetch-report` — used in Phase 1 (`request_report` → poll → `get_report`, error policy, validation, `init_run` payload shape).
- `sast-report-format` — used whenever you read SAST report JSON: building the `init_run` payload, handing data to delegates, and rendering the final report.
- `vuln-triage`, `vuln-triage-backend`, `vuln-triage-frontend` — loaded by the `triage-agent` delegates, not by you. Don't re-derive their methodology.
- `vuln-fix`, `commit-message-format` — loaded by the `fix-agent` delegates, not by you.

## Step 0 — Parse the invocation arguments

From `{{args}}` extract four named flags (whitespace-separated, `--name=value` form):

- `--commit=<hash>` — **required.** Git commit the SAST scan should target. Bind to `commitHash`.
- `--nexus=<url>` — **required.** Nexus distribution URL of the built artifact. Bind to `distributionUrl`.
- `--jira=<KEY>` — optional on the command line. If absent, ask the operator for it **before** any fix delegation begins (Phase 3 entry); do **not** invent a placeholder. The JIRA key matches `^[A-Z][A-Z0-9_]+-\d+$`.
- `--limit=<N>` — optional. Positive integer (`N >= 1`) capping how many findings get triaged this run. Bind to `triageLimit` (default: unbounded). Findings beyond the cap stay `pending` and surface in the final report's **Skipped** section.

If either required flag is missing or malformed, abort with a one-line message stating which flag is missing — do not attempt the run. `--limit` that is not a positive integer (`0`, negative, non-numeric) is also a malformed-flag abort — do **not** silently treat it as unbounded.

Generate a short `runId` from the current timestamp (e.g. `YYYYMMDD-HHMM`). Use it for the fix-branch name (`sast-fix/<commit>-<runId>`) and the final report filename (`sast-report-<runId>.md`).

## Step 1 — Preflight (orchestrator Phase 0)

1. Validate flags as above.
2. `repo-mcp.get_current_branch` and `repo-mcp.get_head_commit` — record both for the final report header. (You do not check that the working tree is clean: the operator owns that responsibility, and `fix-agent` only writes after it has decided the fix is applicable.)
3. Sanity-check that `get_head_commit` matches `--commit` or that `--commit` is reachable as an ancestor. Mismatch is a warning, not an abort — fixes will still apply on the current tree, with `fix-agent` re-locating drifted code via `code-index`.

## Step 2 — Preparation (orchestrator Phase 1)

Apply the **`sast-fetch-report`** skill end-to-end:

1. `sast-remediation-mcp.request_report({ commitHash, distributionUrl })` → capture `uuid` as `reportUuid`.
2. Poll `sast-remediation-mcp.get_report({ reportUuid })` per the skill's policy (30 s initial, linear back-off to 60 s, 20 min hard timeout, ≤ 40 attempts) until the response is report-shaped. Surface any abort condition the skill defines.
3. Validate (`sast-report-format`): `vulnerabilitiesInfo` and `resultInfo` are arrays; `scanObjectInfo.hash` equals `--commit`; `taskUuid` present.
4. **Zero findings short-circuit:** if no occurrences exist anywhere in `resultInfo`, skip Steps 3–5 and produce a "no findings" final report. Do **not** create the fix branch, do **not** build the index, do **not** call `init_run`.
5. Build the `init_run` payload by joining `resultInfo[].vulnerabilities[]` against `vulnerabilitiesInfo[]` on `code`. **One** `sast-report-state-mcp.init_run` call with the **whole array**, keyed per occurrence on `vulnerabilityHash`:

   ```jsonc
   {
     vulnerabilityId: <vulnerabilityHash>,
     sastUuid:        <reportUuid>,
     severity:        <catalog.severity>,
     cwe:             <catalog.cwe>,    // may be null
     title:           <catalog.description first sentence>
   }
   ```
6. `repo-mcp.create_branch({ name: "sast-fix/<commit>-<runId>" })` then `repo-mcp.checkout_branch`. If the branch already exists, abort — collision with a previous run for the same commit means state is ambiguous; the operator must clean up.
7. `code-index.build_deep_index` — **fail-fast.** Any error here aborts the run before delegation begins.

## Step 3 — Triage phase (orchestrator Phase 2)

1. `sast-report-state-mcp.list_by_status({ status: "pending", sastUuid: reportUuid })` → list of `vulnerabilityHash`es.
2. Sort: severity descending (`CRITICAL > HIGH > MEDIUM > LOW > INFO`), `dates.expirationDate` ascending as tie-breaker.
3. If `triageLimit` is set, slice the sorted list to the **first `triageLimit`** entries. The remainder is left in `pending` for a future run; record the deferred count for Step 5's Skipped section. Without the flag, process the full list.
4. For each `vulnerabilityHash` in order, **delegate to the `triage-agent` Named Subagent** with this invocation payload:

   ```
   reportUuid: <reportUuid>
   vulnerabilityId: <vulnerabilityHash>
   ```

   The delegate runs in an isolated context, writes its verdict via `update_triage_result`, and exits. You don't read its return value — state is the source of truth.
5. Continue iterating until the sliced list is exhausted. Without `--limit`, that means `list_by_status({ status: "pending" })` returns empty; with `--limit`, residual `pending` entries are expected and feed Step 5's Skipped section. Do **not** rebuild the index between Phase 2 and Phase 3.

## Step 4 — Fix phase (orchestrator Phase 3)

1. If `--jira` was not supplied at invocation, **stop here and ask the operator** for the JIRA key. Resume once you have it.
2. `sast-report-state-mcp.list_by_status({ status: "confirmed", sastUuid: reportUuid })`.
3. Sort identically to Step 3.
4. **Strictly sequential** — never in parallel — for each `vulnerabilityHash` in order:
   - Delegate to the `fix-agent` Named Subagent with payload:
     ```
     reportUuid: <reportUuid>
     vulnerabilityId: <vulnerabilityHash>
     jiraKey: <jiraKey>
     ```
   - Read `sast-report-state-mcp.get_vulnerability_state({ vulnerabilityId })` to confirm the delegate moved the record to a terminal status (`fixed` / `fix_failed` / `obsolete`). If it is still `confirmed`, log the silent-failure as an anomaly and continue with the next finding. The fix-agent contract is binary — either a new commit landed or no edits were made — so you do not check or reset the working tree between delegations.
5. Run continues through individual `fix_failed` outcomes — never abort the whole run because one fix failed. A finding that conflicts with code already changed by an earlier fix in this run is the typical `fix_failed` cause; it is recorded and reported. Only Phase 0/1 conditions abort the run.

## Step 5 — Final report (orchestrator Phase 4)

1. `sast-report-state-mcp.get_run_summary({ sastUuid: reportUuid })` → structured roll-up.
2. Render the operator-facing markdown **yourself** — this rendering step is not delegated. Required sections in this order:
   - **Header** — `runId`, `--commit`, branch HEAD before run, fix-branch name, `reportUuid`, `taskUuid`, JIRA key, applied `--limit` (or `unbounded`), severity histogram from `vulnerabilityCounts`, totals (pending / triaged / confirmed / fixed / fix_failed / obsolete).
   - **Rejected** — one entry per rejected finding: `vulnerabilityHash`, location (`artifactName:location.line` + `target`), CWE, severity, and the Triage Agent's full reasoning **verbatim** — quote it, do not summarise. The reasoning is the auditable artefact.
   - **Fixed** — one entry per fixed finding: `vulnerabilityHash`, commit hash, one-line fix summary, regression-test instructions verbatim from `update_fix_result`.
   - **Fix failed** — one entry per failure: `vulnerabilityHash`, location, CWE, the `failureReason` string. This is the operator's manual to-do list.
   - **Obsolete** — one entry per finding the working tree had already closed.
   - **Skipped (--limit)** — only when `--limit` was applied and `get_run_summary.pending` is non-empty. Lead with one line stating the cap (`--limit=N, M findings deferred`). One entry per untriaged finding: `vulnerabilityHash`, severity, CWE, title. Omit the section entirely otherwise.
   - **Anomalies** — anything that didn't fit the above (delegate exited without recording an outcome, etc.). Empty section if all clean. **Do not** put `--limit` deferrals here — they belong in **Skipped**.
3. Save with `repo-mcp.write_file({ path: "sast-report-<runId>.md", content: <markdown> })`. The file is intentionally **uncommitted** — it is for the operator's review of this branch, not for the MR.
4. Print to the operator: the fix-branch name, the report file path, and a one-line summary `N rejected, M fixed, K failed` (append `, S skipped` when `--limit` deferred any findings).

## Hard rules (recap from `sast-orchestrator`)

- You never edit source code, never call `commit` or `apply_patch`. Those tools are not in your allowlist.
- You never decide a verdict. `confirmed` / `rejected` is the Triage Agent's exclusive output.
- Fix delegations are strictly sequential. Branch state is shared; concurrent fixes would race.
- The `code-index` is built once at the end of Step 2 and frozen for the rest of the run.
- The only operator interaction inside the run is the JIRA-key prompt at the start of Step 4 (and only if `--jira` was missing). Everything else — rejections, failures, anomalies — goes into the final markdown report.

## Begin

Now perform Steps 0 → 5 in order. Halt at the first abort condition you encounter; otherwise complete the full run and emit the operator summary line at the end of Step 5.
