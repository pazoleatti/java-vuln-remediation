import { collectMavenDependencies, type MavenCoord } from "./pom.js";
import { collectGradleDependencies } from "./gradle.js";
import { osvQueryBatch, type OsvVuln } from "./osv.js";
import { suggestRemediation } from "./remediate.js";

export type ScanOptions = {
  includeTestScope?: boolean;
  includeOptional?: boolean;
};

export type VulnerableDepReport = {
  coordinate: string;
  groupId: string;
  artifactId: string;
  version: string;
  source: string;
  vulnerabilities: OsvVuln[];
  suggestedVersion: string | null;
  changeComment: string;
};

function filterCoords(coords: MavenCoord[], opts: ScanOptions): MavenCoord[] {
  return coords.filter((c) => {
    if (!opts.includeOptional && c.optional) return false;
    if (!opts.includeTestScope && c.scope === "test") return false;
    return true;
  });
}

const BATCH = 80;

async function batchInitialVulns(
  coords: MavenCoord[]
): Promise<Map<string, OsvVuln[]>> {
  const map = new Map<string, OsvVuln[]>();
  for (let i = 0; i < coords.length; i += BATCH) {
    const slice = coords.slice(i, i + BATCH);
    const queries = slice.map((c) => ({
      package: { name: `${c.groupId}:${c.artifactId}`, ecosystem: "Maven" as const },
      version: c.version,
    }));
    const res = await osvQueryBatch(queries);
    slice.forEach((c, j) => {
      const key = `${c.groupId}:${c.artifactId}:${c.version}`;
      map.set(key, res.results[j]?.vulns ?? []);
    });
  }
  return map;
}

export async function scanJavaProject(
  projectPath: string,
  opts: ScanOptions = {}
): Promise<{ coords: MavenCoord[]; reports: VulnerableDepReport[] }> {
  const maven = await collectMavenDependencies(projectPath);
  const gradle = await collectGradleDependencies(projectPath);
  const merged: MavenCoord[] = [];
  const seen = new Set<string>();
  for (const c of [...maven, ...gradle]) {
    const k = `${c.groupId}:${c.artifactId}:${c.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    merged.push(c);
  }

  const coords = filterCoords(merged, opts);
  const vulnMap = await batchInitialVulns(coords);
  const reports: VulnerableDepReport[] = [];

  for (const c of coords) {
    const key = `${c.groupId}:${c.artifactId}:${c.version}`;
    const vulns = vulnMap.get(key) ?? [];
    if (!vulns.length) continue;

    const rem = await suggestRemediation(c.groupId, c.artifactId, c.version, vulns);
    reports.push({
      coordinate: `${c.groupId}:${c.artifactId}:${c.version}`,
      groupId: c.groupId,
      artifactId: c.artifactId,
      version: c.version,
      source: c.source,
      vulnerabilities: vulns,
      suggestedVersion: rem.suggestedVersion,
      changeComment: rem.changeComment,
    });
  }

  return { coords, reports };
}
