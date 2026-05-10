---
description: Manually invalidate the corp SAST report cache held by `sast-remediation-mcp`. Without arguments — clear the whole cache; with `--commit=<hash>` — clear only that commit's cached report. Use when the SAST team re-ran a scan on the same commit (rules / engine version changed) and you need the orchestrator to re-fetch on the next `/sast-run` instead of replaying the stale cached report.
---

# /sast-cache-clear — invalidate the SAST report cache

Operator invocation:

```
/sast-cache-clear [--commit=<hash>]
```

Raw argument string from the operator: `{{args}}`

## What this command does

`sast-remediation-mcp` keeps fetched SAST reports in a per-commit-hash cache (`<cache-dir>/by-commit/<hash>.json`). The cache has **no TTL** — once a report is fetched for commit `X`, every subsequent `/sast-run --commit=X` returns the same cached report until it is cleared. This command is the **only** sanctioned way to invalidate the cache.

The orchestrator does not run, no branch is created, no agents are delegated. This is a single tool call wrapped in a slash command for ergonomics.

## Step 0 — Parse the invocation arguments

From `{{args}}` extract one optional flag:

- `--commit=<hash>` — optional. If present, clear only the cached report for this commit hash. If absent, clear the entire cache.

`--commit=` with empty value is a malformed-flag abort. Any other flag in `{{args}}` is a malformed-flag abort.

## Step 1 — Invoke the tool

Call `sast-remediation-mcp.clear_cache`:

- Without `--commit` — `clear_cache({})`. Clears the whole cache.
- With `--commit=<hash>` — `clear_cache({ commit: "<hash>" })`. Clears only the entry for that commit, no-op if no such entry exists.

## Step 2 — Report the outcome

Print one line to the operator:

- `cache cleared (N entries removed)` for a full clear,
- `cache cleared for commit <hash>` for a targeted clear (or `no cache entry for commit <hash>` if the entry didn't exist — this is not an error).

## Hard rules

- Do **not** invoke the `sast-orchestrator` agent. This is a flat one-tool command.
- Do **not** call `request_report`, `get_report`, `init_run`, or any branch / commit operation.
- Do **not** delegate to `triage-agent` or `fix-agent`.

## Begin

Now perform Steps 0 → 2 in order.
