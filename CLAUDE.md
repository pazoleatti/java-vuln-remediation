dct# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install          # install deps
npm run build        # tsc → dist/ (only build step; no lint or test scripts configured)
npm run start:osv    # OSV/Maven server over stdio (dist/servers/osv/index.js)
npm run start:sast   # corp-SAST server over stdio (dist/servers/sast/index.js)
npm start            # alias for start:osv (kept for backward compat with old MCP configs)
```

There is **no test runner, no linter, and no watch script** wired up. Type-checking happens only via `tsc` during `npm run build`. To smoke-test a tool end-to-end, build first, then invoke the relevant `dist/servers/<name>/index.js` from an MCP client — there is no CLI harness for tools beyond stdio.

## Module system gotcha

`package.json` sets `"type": "module"` and `tsconfig.json` uses `module: "NodeNext"`. **Local imports must include the `.js` extension even though source files are `.ts`** (e.g. `import { scanJavaProject } from "./scan.js"`). Dropping the suffix breaks the build. Zod is imported from `"zod/v4"`, not `"zod"` — keep that subpath when adding schemas.

## Repo layout — multiple MCP servers, one codebase

This is a **monorepo of MCP servers**, not a single server. Each server lives under `src/servers/<name>/` with its own `index.ts` entry point and its own `bin` entry in `package.json`. Cross-server code goes in `src/shared/`. Adding a third server means: new dir under `src/servers/`, new `bin`, new `start:*` script — nothing else.

```
src/
  servers/
    osv/   — public OSV + Maven Central scanner (no secrets)
    sast/  — corporate SAST API client (holds JWT, must NOT be configured as a public MCP)
  shared/
    redact.ts — strips Authorization headers / Bearer tokens from any string
```

**Security-domain separation is the reason for splitting.** OSV server only talks to public endpoints. SAST server holds a corporate JWT and only talks to one configured corp host. They run as separate processes so a misconfigured client cannot cross-talk: e.g. a tool from the OSV server cannot accidentally see the JWT, and the SAST server cannot be invoked without the auth env vars set.

## OSV server (`src/servers/osv/`)

Entry point `src/servers/osv/index.ts` registers two tools (`scan_java_project`, `check_maven_dependency`) on an `McpServer` and connects a `StdioServerTransport`. There is no router, no DI, no persistence — every tool call is a fresh async function that walks the filesystem and hits the network.

The interesting logic is the **scan-and-remediate pipeline**, distributed across `scan.ts`, `pom.ts`, `gradle.ts`, `osv.ts`, `mavenMeta.ts`, `remediate.ts`. Reading any one file in isolation does not show the flow — read them as a chain:

1. **Coordinate collection** (`pom.ts` + `gradle.ts`). `collectMavenDependencies` recursively walks for `pom.xml`, parses with `fast-xml-parser`, expands `${prop}` placeholders against `<properties>` (up to 12 levels deep — see `expandProps`), drops entries where the version still contains `${` after expansion, and skips `<type>pom</type>`. `collectGradleDependencies` is **regex-based heuristics**, not a Gradle parser — it only catches simple string literals like `implementation 'g:a:v'`. Version catalogs, Kotlin DSL with variables, convention plugins are silently missed. Both walkers skip `target/`, `build/`, `node_modules/`, and dotted directories.

2. **Initial OSV batch** (`scan.ts:batchInitialVulns`). Coordinates are deduped by `groupId:artifactId:version`, optionally filtered by `scope=test` / `optional=true`, then queried against `https://api.osv.dev/v1/querybatch` in slices of 80. Only coordinates that come back with vulns proceed to remediation.

3. **Remediation** (`remediate.ts:suggestRemediation`). For each vulnerable coordinate:
   - Fetch `maven-metadata.xml` from Maven Central (`mavenMeta.ts:fetchMavenMetadataVersions`); if Central does not have it (private repo), the report bails out with a manual-review note rather than failing.
   - Compute "newer than current" via `versionsNewerThan` — uses metadata index order if the exact current version string is in the list; otherwise falls back to `semver.coerce` comparison. This matters because Maven versions are not always semver-compatible strings.
   - **Stable-first ordering** (`preferStableFirst`): `semver.parse` flags prereleases, plus regex catches `-SNAPSHOT` and `-M\d+` suffixes that `semver.coerce` would strip. The intent is to avoid suggesting `3.0.0-beta3` when `2.25.x` is fixed and stable.
   - Probe up to 40 candidates from newest backward (`candidateUpgradeOrder`), querying OSV for each one sequentially. The first version with **zero** OSV records wins. Note this is N additional OSV round-trips per vulnerable artifact — slow on a large vuln set but bounded.
   - Build `changeComment` from the **delta of OSV IDs** between current and chosen version, plus short summaries (capped at 8). The OSV-delta is the only "what changed" signal — there is no real changelog parsing.

4. **Markdown rendering** (`index.ts:formatReportMarkdown`). Output is Russian-language Markdown intended to be returned verbatim to the calling assistant; do not strip the Russian strings unless localizing the whole report.

## SAST server (`src/servers/sast/`)

Stdio MCP server that wraps a corporate SAST API. Three tools: `request_report` (POST commit hash + Nexus URL → reportUuid), `get_report` (GET full report by uuid + cache to disk), `get_vulnerability` (slice one finding out of the cached report so agents do not load a huge JSON into context).

**Token handling — read this before touching `auth.ts` or `client.ts`:**

- JWT is read from `SAST_JWT_FILE` (path, preferred — re-read on every call so rotation works without restart) or `SAST_JWT` (inline). `SAST_API_BASE_URL` is required; the server refuses to start without it because pointing the client at the wrong host would leak the JWT to a third party.
- The token lives **only** inside the closure returned by `makeTokenProvider()`. `SastClient` does not store it as a field. `JSON.stringify(client)` cannot leak it.
- Every error path passes through `redactErrorMessage` from `src/shared/redact.ts` before the string reaches `console.error` or an MCP `content` field. When you add a new code path that handles errors, route it through `redactErrorMessage` — do not log or return raw exception messages.
- **Endpoint paths in `client.ts` are placeholders** (`POST /reports`, `GET /reports/{uuid}`). When the real corp contract is known, adjust them in one place — `SastClient.fetchJson` is the only network surface.

**Report cache** (`cache.ts`): `get_report` writes the response JSON to `${SAST_CACHE_DIR ?? os.tmpdir()/sast-mcp-cache}/<uuid>.json`. `get_vulnerability` reads from this cache to avoid re-fetching multi-MB reports. Cache is plain JSON with no TTL — stale entries persist until manually deleted or the OS cleans tmpdir.

**`get_vulnerability` is schema-agnostic** (`findVulnerability` in `index.ts`): it does a BFS over the report and matches any object whose `id` (or `uuid`) equals the requested id and which "looks like" a vulnerability (has at least one of `severity`, `cwe`, `locations`, `description`). This is deliberate — the exact corp report shape is not yet pinned down. When the schema is finalized, replace the BFS with a typed lookup.

## Conventions worth knowing

- **Errors are swallowed for unparseable inputs.** Broken `pom.xml` files and unreadable Gradle files are skipped silently in `collectMavenDependencies` / `collectGradleDependencies`. This is intentional — one malformed module should not abort the scan.
- **Dedup happens at every layer.** Coordinates are deduped inside `parsePomFile`, again across pom + gradle in `scanJavaProject`, and in `dedupe()` in `gradle.ts`. Don't remove these; multi-module projects produce massive overlap.
- **OSV completeness is explicitly disclaimed.** The README and `changeComment` template both note OSV is not authoritative vs. enterprise SCA. Keep that caveat in any new user-facing output.
- **No private Maven mirrors.** `mavenMeta.ts` hardcodes `https://repo1.maven.org/maven2`. If you add support for internal Nexus/Artifactory, that constant becomes a config surface — currently nothing reads env vars or config files.
- **Never put the JWT in OSV-server code paths.** The OSV server is intended to be configured as a public/shared MCP and may run in environments where a corp token has no business existing. If you find yourself importing from `src/servers/sast/auth.ts` inside `src/servers/osv/`, stop — that is the security-domain boundary the split exists to enforce.
