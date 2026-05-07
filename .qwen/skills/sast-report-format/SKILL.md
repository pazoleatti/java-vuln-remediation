---
name: sast-report-format
description: Reference for the corporate SAST report JSON shape returned by sast-remediation-mcp (`get_report`, `get_vulnerability`). Describes the two-table model (vulnerabilitiesInfo catalog + resultInfo per-artifact occurrences), every field's meaning, the `code` vs `vulnerabilityHash` identifier semantics, the `decision` field lifecycle, and severity/CWE conventions. Loaded by both the Triage Agent and the Fix Agent — they read the same report shape, so this skill is the single source of truth for field names. Authoritative schema lives at `jschema/sast-report-schema.json`; this skill is the prose companion.
---

# SAST report JSON — field reference

Read this before parsing any output of `sast-remediation-mcp`. Both the Triage Agent and the Fix Agent rely on the field names and semantics described here. If a field is not listed below, treat it as informational only — do not branch logic on it.

## Where the report comes from

1. **`request_report({ commitHash, distributionUrl })`** → returns an envelope with a `uuid` field. That `uuid` is the `reportUuid` used by the next two tools. Other envelope fields (`type`, `status`, `format`) are status metadata, not the report itself.
2. **`get_report({ reportUuid })`** → full report JSON (the shape documented here). Cached to disk after the first call.
3. **`get_vulnerability({ reportUuid, vulnerabilityId })`** → joined view (see "Joined view" section). Reads from cache; falls back to fetching if cold.

The authoritative JSON Schema is `jschema/sast-report-schema.json`. If you find a discrepancy between this skill and that file, the schema wins — update this skill.

## Top-level shape

```jsonc
{
  "taskUuid":            "string",            // UUID of the scan task (NOT the report uuid you pass in)
  "practice":            "SAST",              // always literal "SAST"
  "ci":                  "string",            // CI patch number (corp-internal build id)
  "createdAt":           "ISO-8601 datetime", // when the scan task was created
  "finishedAt":          "ISO-8601 datetime", // when the scan finished
  "scanObjectInfo":      { ... },             // what was scanned (commit + repo)
  "vulnerabilityCounts": { ... },             // severity histogram for the whole report
  "vulnerabilitiesInfo": [ ... ],             // CATALOG of vulnerability types (one entry per `code`)
  "resultInfo":          [ ... ]              // PER-ARTIFACT findings (occurrences grouped by file)
}
```

The two arrays — `vulnerabilitiesInfo` and `resultInfo` — form a normalised relation. **Join key is `code`.** Catalog metadata (description, fix guide, severity, CWE) is stored once in the catalog; each occurrence in `resultInfo` only carries the `code` plus location-specific fields. Always join when presenting a finding to the user; never report a `code` without its catalog entry.

## `scanObjectInfo`

```jsonc
{
  "type":    "COMMIT",      // currently the only documented value
  "hash":    "git sha",     // commit that was scanned — use this when creating fix commits
  "repoUrl": "https://..."  // optional; URL of the source repo
}
```

`hash` is the commit the SAST scan ran against. The Fix Agent should base remediation commits on (or at least sanity-check parentage against) this hash so that locations cited by the report still match the working tree.

## `vulnerabilityCounts`

Severity histogram for the whole report. All keys are integers ≥ 0; any of them may be absent.

```jsonc
{ "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 }
```

Use only as a sanity check (does the per-status total in `report-state` match this?). Do not drive triage prioritisation off these counts directly — iterate `resultInfo` instead.

## `vulnerabilitiesInfo[]` — vulnerability **catalog**

One entry per **type** of vulnerability detected anywhere in the project. Keyed by `code`.

```jsonc
{
  "code":        "string",                       // catalog id, e.g. "SQLI-001" — joins to resultInfo[].vulnerabilities[].code
  "description": "string",                       // human description of the bug class as the SAST tool sees it
  "fixGuide":    "string",                       // generic remediation guide — NOT a code patch, treat as a hint only
  "severity":    "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "cwe":         "string|null"                   // e.g. "CWE-79"; may be null when the SAST tool did not classify
}
```

**Required fields:** `code`, `description`, `fixGuide`, `severity`. **`cwe` may be null** — handle it. Severity is a fixed enum (uppercase). If you ever see a different value, fail loudly rather than coercing.

`description` and `fixGuide` are the SAST tool's hypothesis — the Triage Agent must form an independent verdict and not paraphrase them. The Fix Agent may use `fixGuide` as a starting point but must verify the actual code shape before applying any change.

## `resultInfo[]` — findings grouped by artifact

One entry per artifact (file/class) that has at least one finding.

```jsonc
{
  "artifactName": "string",   // path to the artifact (file path relative to repo root, or a class FQCN)
  "vulnerabilities": [        // every individual occurrence in this artifact
    {
      "code":              "string",   // FK into vulnerabilitiesInfo
      "vulnerabilityHash": "string",   // unique id of THIS specific occurrence — stable across reports for the same finding
      "location":          { ... },    // where in the file
      "decision":          { ... }|null, // prior triage outcome from the corp system, may be null
      "dates":             { ... }     // lifecycle timestamps
    }
  ]
}
```

### `location` (required on every occurrence)

```jsonc
{
  "line":   "string",  // line number — note this is a STRING, not an integer; coerce if you do arithmetic
  "text":   "string",  // the exact source line at that position (verbatim, including indentation)
  "target": "string"   // the symbol/method/function the finding sits inside (e.g. "UserController.login")
}
```

`text` is the offending line as the SAST tool saw it at scan time. If the working tree no longer matches `text`, the file has drifted since the scan — **do not** trust the line number; the Fix Agent must re-locate the symbol via `code-index` using `target`.

### `decision` (nullable — prior triage from the corp system, NOT this agent's verdict)

```jsonc
{
  "type":       "notexploit",      // currently the only documented value
  "comment":    "string",          // human reasoning recorded with the decision
  "author":     "string",          // who recorded it
  "createDate": "ISO-8601 datetime"
}
```

Semantics:
- **`decision == null`** → the corp system has no prior outcome; this is a fresh finding. Triage normally.
- **`decision.type == "notexploit"`** → the corp system has previously marked this **rejected** (false positive). Treat as historical context only; the Triage Agent must still form its own verdict. If the new verdict disagrees with `notexploit`, **flag the disagreement explicitly** in the reasoning (the corp record may be stale or wrong, but the disagreement matters).
- This field is **not** where this agent stores its own verdict. Agent verdicts go to `sast-report-state-mcp` via `update_triage_result`; never write back into the SAST report.

### `dates` (lifecycle timestamps)

```jsonc
{
  "createDate":     "ISO-8601 datetime",  // when the finding was first opened
  "confirmDate":    "ISO-8601 datetime",  // when it was confirmed reproducible by the SAST pipeline
  "expirationDate": "ISO-8601 datetime"   // when the corp policy says it must be resolved by
}
```

`expirationDate` matters for prioritisation — a finding past its expiration is policy-blocking and outranks freshly-found findings of the same severity, all else equal. The Triage Agent's normal ordering (severity-first) still wins; expiration is only a tie-breaker.

## Identifier semantics — `code` vs `vulnerabilityHash`

`get_vulnerability` accepts either as `vulnerabilityId`. They mean different things:

| Identifier            | Scope                                    | Returns                                                      |
|-----------------------|------------------------------------------|--------------------------------------------------------------|
| `code`                | Catalog id — the bug **type**            | Catalog entry **plus every occurrence** of that type, across all artifacts |
| `vulnerabilityHash`   | Per-occurrence id — one specific finding | Catalog entry plus the **single** matching occurrence        |

**Rule of thumb:** triage and fix operate per-occurrence (one verdict, one commit), so prefer `vulnerabilityHash` end-to-end. Use `code` only when you deliberately want to reason about a class of findings together (e.g. "all SQLI-001 in this repo").

`vulnerabilityHash` is stable across re-scans for "the same" finding (same code at the same location). Use it as the primary key when persisting state to `sast-report-state-mcp`.

## Joined view returned by `get_vulnerability`

`get_vulnerability` does **not** return the raw report slice — it returns a joined projection:

```jsonc
{
  "matchedBy":   "code"|"vulnerabilityHash",       // tells you which path matched
  "catalog":     { code, description, fixGuide, severity, cwe } | null,
  "occurrences": [
    { artifactName, code, vulnerabilityHash, location, decision, dates }
  ]
}
```

Notes:
- `catalog` may be `null` if the report has occurrences whose `code` is missing from `vulnerabilitiesInfo`. That is a corrupt report — surface it; do not silently fall back.
- When `matchedBy == "vulnerabilityHash"` the array has length 1.
- When `matchedBy == "code"` the array may have any length, including 0 (catalog hit, no per-artifact occurrences — happens when SAST tracks a type but found nothing this run).

## Severity ordering & CWE handling

Strict order, highest first: `CRITICAL > HIGH > MEDIUM > LOW > INFO`. Both agents use this for prioritisation. There is no other ordering signal in the report.

`cwe` is `"CWE-NNN"` or `null`. Do not assume a CWE class; if `null`, fall back to reasoning from `description` + `fixGuide` + the offending `text`. The backend/frontend triage skills key their checklists off the CWE — when it is missing, pick the closest CWE based on the description and call that out in the reasoning.

## What is **not** in the report

The report does **not** carry:
- A patch / diff suggestion. `fixGuide` is prose, not code.
- Symbol references / call graph. Use `code-index` for that.
- Test coverage or regression hints. The Fix Agent must derive regression test guidance itself.
- A canonical "status" per finding. Status (pending / triaged / fixed) lives in `sast-report-state-mcp`, not here.

If you find yourself wanting one of these from the SAST report, you are looking in the wrong place.

## Hard rules for both agents

1. **Never write back to the SAST report.** It is read-only from this codebase's perspective. Verdicts go to `sast-report-state-mcp`; fixes go to git.
2. **Always join `resultInfo` to `vulnerabilitiesInfo` before presenting a finding.** A `code` with no catalog entry is unusable — surface it as a report-integrity error.
3. **Trust `vulnerabilityHash` as the per-finding identity.** It is the only field guaranteed unique per occurrence. `code` is many-to-one.
4. **Treat `location.text` as a scan-time snapshot, not ground truth.** Re-locate via `code-index` when the working tree may have moved.
5. **`decision != null` is corp-system history, not this agent's output.** Read it; do not overwrite it; do flag disagreement.
