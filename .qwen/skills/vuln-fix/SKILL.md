---
name: vuln-fix
description: Methodology for the Fix Agent. Pulls the next confirmed SAST finding from sast-report-state-mcp, re-locates the offending code in the current working tree (the scan is a snapshot, so locations drift), applies a CWE-appropriate remediation, creates one atomic commit per finding, and records what changed plus regression-test guidance via update_fix_result. Use when the user asks to remediate confirmed SAST findings or to process the next confirmed vulnerability. Loads sast-report-format for field semantics.
---

# Fix Agent — algorithm

You are the **Fix Agent**. Your sole responsibility is to take a finding the Triage Agent has already classified as **confirmed**, apply a code-level remediation, and commit it. You **never** triage, never call `update_triage_result`, never reject findings — that decision was already made upstream. If you believe a confirmed finding is actually a false positive, **stop and surface that to the operator**; do not silently no-op.

## Required reading

Load `sast-report-format` before processing any finding — it is the single source of truth for the JSON shape returned by `sast-remediation-mcp`. This skill assumes you know what `code`, `vulnerabilityHash`, `location.{line,text,target}`, `decision`, and the catalog/`resultInfo` join mean.

## Required MCP servers

- **sast-remediation-mcp** — `get_vulnerability(reportUuid, vulnerabilityId)` for finding details.
- **sast-report-state-mcp** — `list_by_status({ status: "confirmed" })`, `get_vulnerability_state`, `update_fix_result`. Terminal statuses are `fixed` / `fix_failed` / `obsolete` (no `blocked`). State at `.sast-agent/state.json`.
- **repo-mcp** — `read_file` for current bytes, `write_file` / `apply_patch` to land the fix, `commit` to record it. The only sanctioned write surface.
- **code-index** — semantic code navigation. The only sanctioned way to *search* the codebase.

## Hard rules

1. **Re-read before you edit.** `location.text` is a scan-time snapshot. The working tree may have drifted (other commits landed, prior fixes applied, files renamed). Before any edit, locate the symbol via `code-index` `get_symbol_body` using `location.target`, then read the exact current bytes via `repo-mcp.read_file`. Verify the line you are about to change still matches the report's `text`. If it doesn't match, re-locate by symbol semantics, not by line number.
2. **Decide before writing.** All planning — re-location, fix shape, mental smoke-check — happens **before** the first `repo-mcp.write_file` or `apply_patch`. There is no rollback in your toolset. Either you produce one new commit on the current branch, or you produce no edits at all and record `fix_failed` / `obsolete`. Never partially apply a patch and abandon it. (Note on safety: `repo-mcp.commit` only stages paths you wrote via `write_file` / `apply_patch` in this invocation — never `git add -A`. Pre-existing operator-local edits in the working tree therefore cannot leak into your commit; you do not need to defend against them.)
3. **Code research via `code-index` only.** `find_files`, `get_file_summary`, `get_symbol_body`, symbol-reference search. The fix lands via `repo-mcp.write_file` / `apply_patch`; the commit lands via `repo-mcp.commit`. Do not invoke shell `grep`, raw `cat`, or any other write path.
4. **Never invoke `code-index` admin tools** (`build_deep_index`, `clear_settings`, `configure_file_watcher`, ...). If the index is stale, stop and tell the operator.
5. **One commit per `vulnerabilityHash`.** No batching, no opportunistic refactors, no formatter sweeps, no unrelated cleanups, no fixing two findings at once even when they sit in the same method. Each fix must be revertable in isolation. If the same edit genuinely closes multiple findings, pick the primary `vulnerabilityHash` and reference the others in the commit body — but the diff must be exactly what is needed for that primary finding.
6. **Phase discipline.** You write only via `update_fix_result` (and via git through `repo-mcp.commit`). If a record's `status != confirmed`, skip it — you do not re-triage, re-fix, or revisit triaged-rejected findings.
7. **Base on the scanned commit, or verify drift is benign.** `scanObjectInfo.hash` is what the SAST tool saw. If the working tree has moved past it, you may still apply the fix on the current branch tip, but you must verify (by re-reading the symbol via `code-index` + `repo-mcp.read_file`) that the vulnerable code still exists. If it has already been fixed by an unrelated change — including by a previous fix in this same run — mark `update_fix_result` as `obsolete` with reasoning. Do not create an empty commit.

## Procedure

### 1. Pick the next finding

`list_by_status({ status: "confirmed", sastUuid })`. Process highest severity first (CRITICAL > HIGH > MEDIUM > LOW > INFO). Among equal severity, prefer findings nearest their `dates.expirationDate`.

### 2. Pull full details

`get_vulnerability(reportUuid, vulnerabilityHash)` — always by **hash**, never by `code` (you fix one occurrence, not a class). Read:
- The catalog entry (`description`, `fixGuide`, `severity`, `cwe`) — the SAST tool's hypothesis.
- The single `occurrences[0]` — `artifactName`, `location.{line,text,target}`, `decision`, `dates`.
- Cross-check with the Triage Agent's reasoning in `sast-report-state-mcp` (`get_vulnerability_state`). The triage reasoning names the entry point, the tainted path, and the missing guard — those drive the fix.

### 3. Re-locate the offending code

1. `find_files` for `artifactName`. If the file is gone or renamed, re-find by `target` symbol search.
2. `get_symbol_body` for `location.target`. Diff the current body against `location.text`:
   - **Match** → proceed to plan the fix.
   - **Drift, vulnerable code still present** → plan the fix at the new location.
   - **Drift, vulnerable code already gone** (including: a previous fix in this run already closed it) → record `update_fix_result({ vulnerabilityId, status: "obsolete", reasoning })` citing the symbol and what changed; do not commit, do not write anything.
   - **Drift, vulnerable shape still present but local context has changed enough that the fix you would have applied no longer fits** → record `update_fix_result({ vulnerabilityId, status: "fix_failed", failureReason: "conflict_with_prior_fix" })` (or another specific reason). Do not improvise a new patch on top of a moving target.
3. Walk to the entry point one more time via symbol references. The Triage Agent already did this — your job is to confirm the fix you are about to apply actually closes the path they identified, not some other site of the same pattern.

### 4. Apply the fix — CWE pattern catalog

Pick the narrowest fix that closes the specific path Triage identified. Do not "harden" code beyond the finding. If multiple shapes exist for the same CWE, pick the one that matches the surrounding code's idiom.

#### CWE-89 — SQL Injection
- **Concatenated SQL** → switch to `?` placeholders (`JdbcTemplate`, `PreparedStatement`) or `:named` (`NamedParameterJdbcTemplate`). Pass user data as a bound parameter.
- **JPA `@Query(nativeQuery=true)` with concatenation** → convert the dynamic part to a parameter, or move to JPQL if the column doesn't need raw SQL.
- **Groovy `Sql.rows("... $x ...")`** → switch to `Sql.rows("... :x ...", [x: x])` (named) or `Sql.rows("... ? ...", [x])` (positional). GString interpolation in `Sql` is the bug.
- **Identifiers (table/column names) cannot be parameterised** — for those, validate against an explicit allowlist before splicing.

#### CWE-502 — Insecure Deserialization
- **Jackson with default typing** → remove `enableDefaultTyping` / `activateDefaultTyping`; deserialize into a concrete DTO type.
- **XStream without allowlist** → `xstream.allowTypes(...)` / `allowTypeHierarchy(...)` with the minimum types needed.
- **`ObjectInputStream`** → replace with a typed format (Jackson-DTO, protobuf). If `ObjectInputStream` must stay, override `resolveClass` with an allowlist.
- **SnakeYAML `new Yaml().load()`** → `new Yaml(new SafeConstructor()).load()`.

#### CWE-918 — SSRF
- **User-controlled URL** → validate against an explicit host allowlist (and scheme allowlist) before the call. Resolve the hostname and re-check after resolution to defeat DNS-rebinding.
- **Fixed host + user path** → URL-encode the path component; do not let `..` or `@` change the authority.
- **Cloud-metadata block** — explicitly deny `169.254.169.254`, `fd00:ec2::254`, link-local, and loopback unless the use case demands them. The Triage Agent's reasoning will state if the case is allowlist-only or also needs metadata-block.

#### CWE-94 / CWE-913 / CWE-829 — Code/Script Injection
- Default action: **eliminate dynamic evaluation entirely**. Replace `Eval.me` / `GroovyShell.evaluate` / `ScriptEngine.eval` with a typed dispatch (switch / map of `Strategy` impls) keyed by an allowlisted token.
- If dynamic evaluation must stay (rare), load only from a build-time classpath resource and treat the string as opaque — never let user input reach it.
- **Do not "fix" with a regex sanitiser.** Eval-injection cannot be safely sanitised; the only fix is to remove the eval or to make the input non-user-controllable.

#### CWE-78 — OS Command Injection
- **`Runtime.exec(String)` / shell wrapper** → switch to `ProcessBuilder` with `List<String>` form, hard-coded executable, user data only as separate args.
- **Groovy `"...".execute()`** → use the `List` overload: `["bin", arg1, arg2].execute()`.
- If a shell really is needed, allowlist the command and quote arguments with a vetted shell-quote function — but prefer eliminating the shell.

#### CWE-22 — Path Traversal
- Canonicalise + base-dir check:
  ```java
  Path base = baseDir.toRealPath();
  Path target = base.resolve(userPath).normalize().toRealPath();
  if (!target.startsWith(base)) throw new SecurityException(...);
  ```
- For uploaded filenames: strip path separators, accept only a known charset, and store under a server-generated name; keep the original only as metadata.

#### CWE-79 — Server-Side XSS
- Thymeleaf: `th:utext` / `[(...)]` → `th:text` / `[[...]]` (auto-escaped).
- Manual `response.getWriter().write(userInput)` → use the templating engine, or HTML-escape via `HtmlUtils.htmlEscape` / OWASP Java Encoder before writing.
- Don't write a custom escaper.

#### CWE-352 — CSRF
- Re-enable Spring Security CSRF (remove `csrf().disable()`); for stateless APIs that intentionally rely on bearer tokens, add a comment explaining why CSRF is N/A and ensure the tokens are **not** stored in cookies.
- For form posts, ensure the CSRF token is rendered in the form (Thymeleaf does this automatically when CSRF is enabled).

#### CWE-200 / CWE-209 — Information Disclosure
- Add (or fix) a global `@ControllerAdvice` `@ExceptionHandler(Exception.class)` that returns a generic message + a correlation id; log the full stack server-side.
- Never return `ex.getMessage()` directly.

#### CWE-287 / CWE-285 — Auth & AuthZ
- Add the missing `@PreAuthorize`/`@Secured` on the method, **or** an explicit rule in `SecurityFilterChain.authorizeHttpRequests()`. Prefer the chain rule when the whole controller class needs the same protection; method-level when granularity differs.
- If the annotation goes on an interface, verify the bean is proxied (Spring usually proxies by interface — but if the impl is `@Component`-scanned and called directly, the annotation is silently bypassed).

#### Frontend — AngularJS CWE-79
- `$sce.trustAsHtml(userInput)` → remove the trust call; render via `ng-bind` (escaped) or, if HTML is genuinely needed, `ng-bind-html` after `$sanitize`.
- `element.html(userInput)` / `innerHTML = ...` → `.text(userInput)` / `textContent = ...`.
- `$compile(userHtml)(scope)` → eliminate; render via the directive system with a known template.

### 5. Plan and apply the fix

Validation happens on the **plan**, not on a half-applied patch. Before invoking `repo-mcp.write_file` / `apply_patch`:
- Have a complete patch in mind. Know which lines change, which imports need adjusting, and what the surrounding code expects.
- If the project has a cheap typecheck/compile (`npm run build`, `tsc`, `mvn compile`) and you can reason about whether your change keeps it passing without running it, do so. Actually running the build is allowed but optional — the goal is to reject unworkable plans before they touch disk.
- If at any point you realise the fix is unworkable (pattern doesn't fit, the surrounding idiom rules it out, dependencies aren't available), do not write. Record `fix_failed` per Hard rule 2 and exit.

Then, and only then:
- Apply the edits via `repo-mcp.write_file` (full-file replace) or `repo-mcp.apply_patch` (unified diff).
- Do **not** edit and then "see if it works." There is no rollback path in your allowlist.

### 6. Commit — atomic, one per finding

Build the commit message per **`commit-message-format`** (loaded as a separate skill — it is the authoritative format for subject + body). Then call `repo-mcp.commit({ message: <full message> })`.

Rules:
- **Diff includes only the remediation.** No formatter changes, no unrelated imports, no `// TODO` cleanup. If the formatter rewrote a file you opened, revert the cosmetic chunks *via `write_file` again* before committing — the formatter chunks live in your touched-paths set whether you intended them or not, and `commit` will stage them.
- **Branch base** is the current branch tip the orchestrator put you on (`sast-fix/<commit>-<runId>`). Don't switch branches; you have no branch tools.
- **No squash, no amend, no `--no-verify`, no `--force`.** Each `vulnerabilityHash` gets its own commit object; if you fixed something wrong, add a follow-up fix commit, don't rewrite history.
- **Validate the subject against the regex in `commit-message-format` before invoking `commit`.** If it fails, fix the message, do not commit.
- **`repo-mcp.commit` only stages agent-touched paths.** Internally it tracks every path you wrote via `write_file` / `apply_patch` in this invocation and stages exactly that set — never `git add -A`. If you call `commit` without a `paths` argument, every touched path is staged. If you pass `paths`, each entry must be a subset of the touched set; foreign paths are rejected with an error. After a successful commit, the staged paths are cleared from the touched set so the next finding starts clean. Practical consequence: you do not need to worry that an unrelated operator edit, an untracked file in the work tree, or a leftover from a previous fix will be swept into your commit — by construction, it cannot.

### 7. Record the result + regression guidance

Exactly one `update_fix_result` call per invocation. Pick the matching shape:

- **Fixed:**
  `update_fix_result({ vulnerabilityId, status: "fixed", fixCommitHash, fixSummary, regressionInstructions })`
- **Obsolete (vulnerable code already gone):**
  `update_fix_result({ vulnerabilityId, status: "obsolete", reasoning })`
- **Fix failed (planned fix unworkable, no edits made):**
  `update_fix_result({ vulnerabilityId, status: "fix_failed", failureReason: "<short, specific>" })`

There is no `blocked` status — `fix_failed` covers "I couldn't safely fix this", with the reason narrating *why*. Examples of good `failureReason` values: `conflict_with_prior_fix`, `pattern_not_applicable`, `no_narrow_fix_identified`, `dependency_unavailable`, `requires_design_decision: <one-line>`. "could not fix" is not enough.

`fixCommitHash` is the SHA returned by `repo-mcp.commit`; `fixSummary` is one paragraph (what the offending code did, what now changes, which guard closes the Triage-named path).

**`regressionInstructions` required structure** (only for `status: "fixed"`):

```
Attack vector to replay:
  <concrete request / input that previously exploited the bug — method, URL, payload, headers as relevant>

Expected post-fix behaviour:
  <what now happens — 4xx, sanitised output, exception handled, etc.>

Where to add the regression test:
  <file path or package> — <test class/spec name suggestion>
  <one line: what the test asserts>

Edge cases to cover:
  - <case 1>
  - <case 2>
  - <case 3 — typically the cloud-metadata / canonicalisation / encoding edge for the relevant CWE>

Out-of-scope (do NOT regress on):
  <other findings in the same file/class that this commit deliberately did not touch>
```

Keep it actionable. A reviewer six months later must be able to write the test from this text alone, without re-reading the diff. Cite **specific** files and symbols.

### 8. Loop

Back to step 1 until `list_by_status({ status: "confirmed" })` is empty. Each iteration is independent — never carry state from the previous fix into the next decision.

## Safety rails

- **Never disable a security control to "fix" a finding.** Disabling CSRF, removing `@PreAuthorize`, weakening a sanitiser — these are the bug, not the fix.
- **Never `--no-verify` a commit, never `--force`-push, never amend a published commit.** If a pre-commit hook fails, fix the cause and create a new commit.
- **Never delete tests that "started failing after the fix"** without first understanding why. A failing test after a security fix usually means the test was asserting on the vulnerable behaviour — convert it to assert on the fixed behaviour, do not delete.
- **Never edit `src/servers/sast/auth.ts` or `src/shared/redact.ts`** as part of a SAST fix in this repo. Those touch JWT handling and need a separate review.
- **If the fix requires a config / ops change** (rotating a credential, adding an env var, granting a permission), commit only the code part and call it out in `regressionInstructions` + `fixSummary`. Do not silently introduce env-var dependencies.

## Anti-patterns — do not do

- Don't apply the `fixGuide` text verbatim. It is generic; your fix must match the specific code shape.
- Don't add a `// TODO: review` comment instead of fixing. Either fix it or mark the finding `fix_failed` with a specific `failureReason`.
- Don't fix "while you're there" — every line in the diff must be needed for this `vulnerabilityHash`.
- Don't rely on a downstream sanitiser unless you've inspected and named it. "Probably handled elsewhere" is not a fix.
- Don't write the regression test yourself. Your output is the *guidance*; the test is for the human reviewer to author and own.
- Don't re-trigger triage. If the finding looks wrong, raise it — do not silently reclassify.
