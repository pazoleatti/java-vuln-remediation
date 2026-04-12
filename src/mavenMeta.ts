import { XMLParser } from "fast-xml-parser";
import semver from "semver";

const CENTRAL = "https://repo1.maven.org/maven2";

export function groupPath(groupId: string): string {
  return groupId.replace(/\./g, "/");
}

export async function fetchMavenMetadataVersions(
  groupId: string,
  artifactId: string
): Promise<{ versions: string[]; release?: string } | null> {
  const url = `${CENTRAL}/${groupPath(groupId)}/${artifactId}/maven-metadata.xml`;
  const res = await fetch(url);
  if (!res.ok) return null;
  const text = await res.text();
  const parser = new XMLParser({ ignoreAttributes: false, trimValues: true });
  const doc = parser.parse(text) as Record<string, unknown>;
  const meta = (doc.metadata ?? doc) as Record<string, unknown>;
  const ver = meta.versioning as Record<string, unknown> | undefined;
  if (!ver) return null;
  const versionsBlock = ver.versions as Record<string, unknown> | undefined;
  const raw = versionsBlock?.version;
  let versions: string[] = [];
  if (Array.isArray(raw)) versions = raw.map(String);
  else if (raw != null) versions = [String(raw)];
  const release = ver.release != null ? String(ver.release) : undefined;
  return { versions, release };
}

/**
 * Versions strictly newer than `current`.
 * Uses metadata order when the exact string exists; otherwise semver.coerce when possible.
 */
export function versionsNewerThan(
  ordered: string[],
  current: string
): string[] {
  const idx = ordered.lastIndexOf(current);
  if (idx >= 0) return ordered.slice(idx + 1);
  const cur = semver.coerce(current);
  if (cur) {
    return ordered.filter((v) => {
      const c = semver.coerce(v);
      return c ? semver.gt(c, cur) : false;
    });
  }
  return ordered.filter((v) => v > current);
}

/** Prefer trying from newest (end of ordered list) toward older. */
export function candidateUpgradeOrder(newerSlice: string[], orderedFull: string[]): string[] {
  const set = new Set(newerSlice);
  const fromEnd = [...orderedFull].reverse().filter((v) => set.has(v));
  if (fromEnd.length) return fromEnd;
  return [...newerSlice].reverse();
}
