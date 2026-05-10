---
description: Print a compact table of vulnerabilities in the SAST report for a given commit, without running triage / fix. Used to discover the `vulnerabilityHash` of a specific finding before launching a targeted `/sast-run --vuln=<hash>`. Hits the per-commit cache in `sast-remediation-mcp` when available; otherwise fetches the report and caches it for subsequent calls.
---

# /sast-list — list vulnerabilities for a commit

Operator invocation:

```
/sast-list --commit=<hash>
```

Raw argument string from the operator: `{{args}}`

## What this command does

Calls `sast-remediation-mcp.list_vulnerabilities({ commit: <hash> })` and prints the response as a markdown table. No branch is created, no state file is written, no agents are delegated. This is a read-only inspection helper.

The MCP serves the response from its commit-hash cache when present; otherwise it performs the same `request_report → poll get_report` lifecycle as a real run and stores the result in the cache. The next `/sast-run` for the same commit will then reuse this cached report.

## Step 0 — Parse the invocation arguments

From `{{args}}` extract one required flag:

- `--commit=<hash>` — **required.** Git commit hash whose SAST report to list.

If the flag is missing or has an empty value, abort with a one-line message naming the missing flag. Any other flag in `{{args}}` is a malformed-flag abort.

## Step 1 — Fetch the compact list

Call `sast-remediation-mcp.list_vulnerabilities({ commit: "<hash>" })`. Each response item carries:

- `vulnerabilityHash`
- `code`
- `severity` (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`)
- `artifactName`
- `location.target`
- `location.line`
- `decision.type` (`notexploit` or absent)

If the report is not yet cached, the MCP will fetch it. Surface any abort condition the MCP reports (network error, timeout, validation failure) verbatim.

## Step 2 — Print the table

Render to the operator a markdown table sorted by severity descending (`CRITICAL > HIGH > MEDIUM > LOW > INFO`) with these columns, in this order:

| `vulnerabilityHash` | severity | code | location | decision |

Where:

- **vulnerabilityHash** — full hash, monospace.
- **severity** — uppercase.
- **code** — uppercase code from the report.
- **location** — `<artifactName>:<location.line>` followed by `(<target>)` on the same line. If `target` is empty, omit the parenthesised part.
- **decision** — `notexploit` if the finding has `decision.type == "notexploit"`, otherwise an empty cell.

Above the table, print a one-line summary: `<commit>: N findings (cached: yes|no)` — `cached` indicates whether the response came from cache. If the report has zero findings, print only the summary line and skip the table.

## Hard rules

- Do **not** invoke the `sast-orchestrator` agent.
- Do **not** call `init_run`, `create_branch`, `build_deep_index`, or any write tool.
- Do **not** delegate to `triage-agent` or `fix-agent`.
- The output is informational. Do **not** persist anything to disk.

## Begin

Now perform Steps 0 → 2 in order.
