# java-vuln-remediation

An [MCP](https://modelcontextprotocol.io/) server for working with **Java dependencies**: find versions with known vulnerabilities (via [OSV](https://osv.dev/)), suggest **newer versions** with no OSV records for coordinates from [Maven Central](https://repo1.maven.org/maven2/), and short **notes** on which advisories no longer apply after an upgrade.

Repository: [https://github.com/Neovaryag/java-vuln-remediation](https://github.com/Neovaryag/java-vuln-remediation)

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install and build](#install-and-build)
- [Connecting to Cursor / VS Code](#connecting-to-cursor--vs-code)
- [MCP tools](#mcp-tools)
- [Limitations and disclaimer](#limitations-and-disclaimer)
- [Development](#development)
- [License](#license)

---

## Features

| Feature | Description |
|--------|-------------|
| **Maven** | Recursively walks all `pom.xml` files (excluding `target/`, `node_modules/`), reads `<dependencies>`, resolves `${properties}` in `groupId` / `artifactId` / `version`, skips `type=pom`. |
| **Gradle** | Heuristics for `build.gradle` / `build.gradle.kts`: lines like `implementation 'g:a:v'`, `api("g:a:v")`, and similar for `compileOnly`, `runtimeOnly`, `annotationProcessor`, etc. |
| **Vulnerability checks** | Batch requests to the OSV API (`POST https://api.osv.dev/v1/querybatch`), ecosystem `Maven`, package name `groupId:artifactId`. |
| **Remediation** | Version list from `maven-metadata.xml` on Maven Central; tries candidates from **newer stable** releases (prereleases deferred); the first version with no OSV records is suggested as the replacement. |
| **Upgrade notes** | Lists OSV IDs (e.g. `GHSA-…`, `CVE-…`) that applied to the old version and are **not** returned for the suggested version, plus short `summary` strings from the OSV response when available. |

This is **not** a full substitute for SCA in CI (Snyk, OWASP Dependency-Check, GitHub Dependabot, etc.); it is a convenient layer for the IDE and assistants.

---

## How it works

1. **Collect coordinates** — Build a list of `groupId:artifactId:version` from dependencies declared in the project.
2. **OSV** — For each coordinate, check whether known vulnerabilities exist for that version.
3. **Upgrade candidates** — Take the ordered version list from `maven-metadata.xml`; keep versions **newer** than the current one (via index in metadata or `semver.coerce` if the exact string is missing from the list).
4. **Traversal order** — **Stable** releases first (prerelease detection via `semver.parse`, plus `-SNAPSHOT`, `-M…`), then alpha/beta/rc, so `3.0.0-beta3` is not suggested when stable `2.25.x` works.
5. **Validate candidate** — For each chosen version, query OSV again; the first version with an **empty** vulnerability list becomes the recommendation.

External services: **OSV** and **Maven Central** (HTTP); no API keys required.

---

## Requirements

- **Node.js 18+** (uses built-in `fetch`).
- Network access to `api.osv.dev` and `repo1.maven.org`.

---

## Install and build

```bash
git clone https://github.com/Neovaryag/java-vuln-remediation.git
cd java-vuln-remediation
npm install
npm run build
```

Run the server manually (stdio, as MCP clients expect):

```bash
npm start
# or
node dist/index.js
```

Globally (after `npm link` in the project directory or `npm install -g .`):

```bash
java-vuln-remediation
```

---

## Connecting to Cursor / VS Code

In your MCP configuration, set the command and path to the built `dist/index.js`.

**Example (Windows, path with spaces):**

```json
{
  "mcpServers": {
    "java-vuln-remediation": {
      "command": "node",
      "args": [
        "C:\\path\\to\\java-vuln-remediation\\dist\\index.js"
      ]
    }
  }
}
```

**Example (macOS / Linux):**

```json
{
  "mcpServers": {
    "java-vuln-remediation": {
      "command": "node",
      "args": ["/absolute/path/to/java-vuln-remediation/dist/index.js"]
    }
  }
}
```

After saving settings, restart MCP or the editor window. Ensure `npm run build` has been run and `dist/index.js` exists.

---

## MCP tools

### `scan_java_project`

Scans the project tree from the given root.

| Parameter | Type | Description |
|-----------|------|-------------|
| `projectPath` | `string` | Root of the Java project (prefer an **absolute** path). |
| `includeTestScope` | `boolean`, optional | Include dependencies with `scope=test` (default `false`). |
| `includeOptional` | `boolean`, optional | Include `optional=true` (default `false`). |

**Response:** short summary and a **Markdown** table: dependency, current version, suggested version, source file; sections listing OSV IDs and text on what is cleared by the upgrade.

### `check_maven_dependency`

Point check for a single Maven coordinate.

| Parameter | Type | Description |
|-----------|------|-------------|
| `groupId` | `string` | Maven `groupId`. |
| `artifactId` | `string` | Maven `artifactId`. |
| `version` | `string` | Current version. |

**Response:** either a message that OSV has no records, or a vulnerability list, suggested version (if found), and notes on the OSV delta.

---

## Limitations and disclaimer

1. **Transitive dependencies** are not fully resolved: `mvn dependency:list` is not invoked and Gradle is not run for the full graph. The report mainly covers **explicitly** declared artifacts in `pom.xml` / Gradle files.
2. **Gradle** — common string declarations only; complex Kotlin DSL, version catalogs, convention plugins, etc. may not be detected.
3. **OSV** does not guarantee completeness versus enterprise databases or the NVD; false negatives and lag versus other sources are possible.
4. “What changed” reflects the **OSV delta / OSV summaries**, not the library’s full changelog; for major upgrades, review release notes and API compatibility manually.
5. Private Maven repositories (not Central) are **not** used for version lists — if `maven-metadata.xml` on Central is unavailable, version selection may fail.

---

## Development

```bash
npm install
npm run build
```

Sources in `src/`:

| File | Role |
|------|------|
| `index.ts` | MCP tool registration, stdio transport. |
| `scan.ts` | Maven/Gradle coordinate collection and scan orchestration. |
| `pom.ts` | `pom.xml` parsing. |
| `gradle.ts` | Gradle heuristics. |
| `osv.ts` | OSV `querybatch` client. |
| `mavenMeta.ts` | Load `maven-metadata.xml`, compare versions. |
| `remediate.ts` | Pick a version with no OSV records, comments. |

---

## License

MIT — see [LICENSE](LICENSE).
