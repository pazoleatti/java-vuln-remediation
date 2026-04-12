import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

import type { MavenCoord } from "./pom.js";

/** Heuristic extraction of Maven coordinates from Gradle files (not a full Gradle parser). */
function extractFromGradleText(text: string, source: string): MavenCoord[] {
  const found: MavenCoord[] = [];
  const patterns: RegExp[] = [
    /(?:implementation|api|compileOnly|runtimeOnly|compileClasspath|testImplementation|annotationProcessor)\s*\(?\s*['"]([^'":\s]+):([^'":\s]+):([^'":\s]+)['"]\s*\)?/g,
    /(?:implementation|api|compileOnly|runtimeOnly|compileClasspath|testImplementation|annotationProcessor)\s*\(\s*["']([^"']+)["']\s*\)/g,
  ];

  const parseGav = (gav: string): MavenCoord | null => {
    const parts = gav.split(":");
    if (parts.length < 3) return null;
    const [groupId, artifactId, version] = parts;
    if (!groupId || !artifactId || !version || version.includes("$")) return null;
    return { groupId, artifactId, version, source };
  };

  for (const re of patterns) {
    let m: RegExpExecArray | null;
    const r = new RegExp(re.source, re.flags);
    while ((m = r.exec(text)) !== null) {
      if (m.length >= 4 && m[1] && m[2] && m[3]) {
        const c = parseGav(`${m[1]}:${m[2]}:${m[3]}`);
        if (c) found.push(c);
      } else if (m[1]) {
        const c = parseGav(m[1]);
        if (c) found.push(c);
      }
    }
  }
  return dedupe(found);
}

function dedupe(coords: MavenCoord[]): MavenCoord[] {
  const seen = new Set<string>();
  const out: MavenCoord[] = [];
  for (const c of coords) {
    const k = `${c.groupId}:${c.artifactId}:${c.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(c);
  }
  return out;
}

async function walkGradle(dir: string, out: string[]) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name === "build" || e.name === "node_modules" || e.name.startsWith(".")) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await walkGradle(p, out);
    else if (e.name === "build.gradle" || e.name === "build.gradle.kts") out.push(p);
  }
}

export async function collectGradleDependencies(projectPath: string): Promise<MavenCoord[]> {
  const files: string[] = [];
  await walkGradle(projectPath, files);
  const all: MavenCoord[] = [];
  for (const f of files) {
    try {
      const text = await readFile(f, "utf8");
      all.push(...extractFromGradleText(text, f));
    } catch {
      /* skip */
    }
  }
  return dedupe(all);
}
