---
name: commit-message-format
description: Required commit-message format for SAST remediation commits — `<JIRA_KEY> <CWE-ID> <description>`. JIRA_KEY is supplied by the operator at session start (one ticket per remediation batch); CWE-ID comes from the SAST catalog entry; description is a short imperative summary of the code change. Loaded by vuln-fix and any other agent that creates commits in this project. Overrides the commit-format section embedded in vuln-fix — when this skill is loaded, follow this format.
---

# Commit message format

Every commit produced by an agent in this repo MUST use the format below. This skill takes precedence over any commit-format text embedded in another skill.

## Subject line

```
<JIRA_KEY> <CWE-ID> <description>
```

Three space-separated fields. Examples:

```
SEC-1234 CWE-89 parameterise UserRepository.findByLogin SQL
SEC-1234 CWE-22 canonicalise upload path before write in FileStore.save
SEC-1199 CWE-79 escape comment body in CommentView.render
```

### Field rules

**`<JIRA_KEY>`** — the Jira issue tracking the remediation batch.
- Supplied by the **operator** at session start as a parameter (environment variable, CLI argument, or first operator message: "we're working on SEC-1234"). The agent never invents a JIRA_KEY.
- Format: uppercase project prefix + dash + numeric id, matching `^[A-Z][A-Z0-9_]+-\d+$` (e.g. `SEC-1234`, `APPSEC-77`, `RISK_PLAT-9`).
- One JIRA_KEY per session unless the operator changes it. Do **not** spread fixes for one finding across two tickets, and do **not** combine fixes for unrelated tickets in one commit.
- If no JIRA_KEY has been supplied, **stop and ask the operator before creating any commit.** Do not fall back to a placeholder like `NOJIRA` or the previous session's key.

**`<CWE-ID>`** — the CWE classifier from the SAST catalog entry (`vulnerabilitiesInfo[].cwe`).
- Format: `CWE-` + the numeric id (e.g. `CWE-89`, `CWE-502`, `CWE-918`).
- Source: the joined `catalog.cwe` field returned by `get_vulnerability` (see `sast-report-format`). Use exactly that value; do not normalise, pad, or strip the prefix.
- **If `cwe` is `null`** in the catalog: pick the closest CWE based on `description` and the offending code, prefix with a question mark, and call out the inference in the commit body. Subject becomes `<JIRA_KEY> CWE-?89 <description>`. The `?` is a signal to reviewers that the classifier is the agent's best guess, not the SAST tool's.
- One CWE per commit. If a single edit closes findings of two different CWEs (rare), pick the primary CWE and reference the secondary `vulnerabilityHash`/CWE in the body — do not concatenate CWEs in the subject.

**`<description>`** — short imperative summary of *what changed in the code*, not *what the bug was*.
- Lowercase first word, no trailing punctuation, imperative mood ("parameterise", "escape", "canonicalise" — not "fixed", "fixes", "fixing").
- Cite the specific symbol when it fits: `parameterise UserRepository.findByLogin SQL` beats `fix SQL injection`.
- Do not restate the CWE name in the description — that's redundant with the CWE-ID field. `CWE-79 escape comment body in CommentView.render` is correct; `CWE-79 fix XSS by escaping comment body` repeats "XSS".
- No emojis, no Conventional-Commits prefix (`fix:`, `chore:`, etc.), no Russian text in the subject — keep it ASCII-greppable. Russian is fine in the body if the project's other commits use it.

### Length

- **Subject ≤ 72 characters total.** If you exceed 72, shorten the description, not the JIRA_KEY or CWE-ID.
- The subject is one line. No line breaks, no continuation.

## Body

Subject is followed by a blank line, then the body. Body shape:

```
Finding: <code> @ <artifactName>:<location.line> (target=<location.target>)
Hash: <vulnerabilityHash>
Severity: <CRITICAL|HIGH|MEDIUM|LOW|INFO>   CWE: <cwe-from-catalog or "n/a — inferred CWE-NNN">
Report: <reportUuid>

Vulnerable shape: <one sentence — what the offending code did>
Remediation:      <one sentence — what this commit changes>
Why this closes it: <one sentence — which guard/structure now blocks the path Triage named>

Refs: <related vulnerabilityHashes if this commit closes more than one — should be rare>
```

Body rules:
- Wrap body lines at ~100 chars. Field labels (`Finding:`, `Hash:`, ...) stay on their own line.
- The full `vulnerabilityHash` goes in the body's `Hash:` field. The subject does NOT carry the hash — JIRA_KEY + CWE-ID + description is enough for humans to scan; the hash is for tooling and lives in the body.
- If `cwe` was `null` in the catalog and you inferred one (subject uses `CWE-?NN`), the `CWE:` field in the body must read exactly `n/a — inferred CWE-NN` so the inference is greppable.
- No `Co-Authored-By` lines, no tool-generated footers, unless the operator explicitly asks for them.

## Worked examples

### Catalog has CWE

Catalog entry: `code=SQLI-001`, `cwe=CWE-89`, `severity=HIGH`. Finding hash `a1b2c3d4e5f6...`. JIRA_KEY supplied as `SEC-1234`.

```
SEC-1234 CWE-89 parameterise UserRepository.findByLogin SQL

Finding: SQLI-001 @ src/main/java/.../UserRepository.java:142 (target=UserRepository.findByLogin)
Hash: a1b2c3d4e5f67890abcdef1234567890
Severity: HIGH   CWE: CWE-89
Report: 7f3e9c2a-...

Vulnerable shape: login built a JDBC query via String concatenation of the `login` request param.
Remediation:      switched to JdbcTemplate `queryForObject` with a `?` placeholder bound to login.
Why this closes it: user input no longer reaches the SQL parser as syntax — it is bound as a value.
```

### Catalog CWE is null — agent inferred

Same finding, but `cwe=null` and the description points to path traversal. Agent infers `CWE-22`.

```
SEC-1234 CWE-?22 canonicalise upload path before write in FileStore.save

Finding: PATH-LOCAL @ src/main/java/.../FileStore.java:88 (target=FileStore.save)
Hash: 9988aabb...
Severity: MEDIUM   CWE: n/a — inferred CWE-22
Report: 7f3e9c2a-...

Vulnerable shape: save resolved a user-supplied filename against the upload dir without canonicalising.
Remediation:      resolve + normalize + toRealPath, then assert startsWith(baseDir) before write.
Why this closes it: any `..` segment now resolves outside baseDir and fails the startsWith check.
```

## Validation

Before invoking `git commit`, self-check:

1. Subject matches `^[A-Z][A-Z0-9_]+-\d+ CWE-\??\d+ [a-z].{0,}$` and is ≤ 72 chars.
2. JIRA_KEY equals the value the operator supplied (not a guess, not stale from a prior session).
3. CWE-ID equals `catalog.cwe` exactly, OR is prefixed with `?` and the body says `n/a — inferred CWE-NN`.
4. Body has all of `Finding:`, `Hash:`, `Severity:`, `Report:`, `Vulnerable shape:`, `Remediation:`, `Why this closes it:`.

If any check fails, fix the message before committing — do not amend after the fact.

## Anti-patterns

- ❌ `fix: SQL injection in UserRepository (SEC-1234, CWE-89)` — Conventional-Commits prefix, fields in wrong order/places.
- ❌ `SEC-1234 CWE-89 Fixed SQL injection.` — past tense, trailing period, capitalised description, says "fix" without naming the change.
- ❌ `SEC-1234 fix SQL injection` — missing CWE-ID.
- ❌ `CWE-89 SEC-1234 parameterise query` — fields in wrong order.
- ❌ `SEC-1234 CWE-89/CWE-352 multiple fixes` — two CWEs in subject; split into two commits.
- ❌ `NOJIRA CWE-89 ...` — fabricated JIRA_KEY; stop and ask the operator instead.
