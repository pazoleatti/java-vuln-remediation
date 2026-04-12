import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

export type MavenCoord = {
  groupId: string;
  artifactId: string;
  version: string;
  scope?: string;
  optional?: boolean;
  source: string;
};

function asArray<T>(x: T | T[] | undefined): T[] {
  if (x == null) return [];
  return Array.isArray(x) ? x : [x];
}

function expandProps(value: string, props: Record<string, string>, depth = 0): string {
  if (depth > 12) return value;
  return value.replace(/\$\{([^}]+)\}/g, (_, key: string) => {
    const v = props[key];
    if (v == null) return _;
    return expandProps(v, props, depth + 1);
  });
}

function collectProperties(obj: unknown, into: Record<string, string>) {
  if (!obj || typeof obj !== "object") return;
  const p = (obj as Record<string, unknown>).properties;
  if (!p || typeof p !== "object") return;
  for (const [k, v] of Object.entries(p as Record<string, unknown>)) {
    if (typeof v === "string" && k && !k.startsWith("@_")) into[k] = v;
  }
}

async function parsePomFile(path: string): Promise<MavenCoord[]> {
  const { XMLParser } = await import("fast-xml-parser");
  const xml = await readFile(path, "utf8");
  const parser = new XMLParser({ ignoreAttributes: false, trimValues: true });
  const doc = parser.parse(xml) as Record<string, unknown>;
  const project = (doc.project ?? doc) as Record<string, unknown>;
  const props: Record<string, string> = {};
  collectProperties(project, props);

  const deps: MavenCoord[] = [];
  const depRoot = project.dependencies as Record<string, unknown> | undefined;

  const pushDeps = (block: Record<string, unknown> | undefined) => {
    if (!block) return;
    const list = asArray<Record<string, unknown>>(block.dependency as Record<string, unknown> | undefined);
    for (const d of list) {
      const groupId = expandProps(String(d.groupId ?? ""), props).trim();
      const artifactId = expandProps(String(d.artifactId ?? ""), props).trim();
      const version = expandProps(String(d.version ?? ""), props).trim();
      const scope = d.scope != null ? String(d.scope) : undefined;
      const optional = d.optional === true || d.optional === "true";
      const typ = d.type != null ? String(d.type) : "jar";
      if (!groupId || !artifactId) continue;
      if (!version || version.includes("${")) continue;
      if (typ === "pom") continue;
      deps.push({
        groupId,
        artifactId,
        version,
        scope,
        optional,
        source: path,
      });
    }
  };

  pushDeps(depRoot);

  const seen = new Set<string>();
  const uniq: MavenCoord[] = [];
  for (const c of deps) {
    const k = `${c.groupId}:${c.artifactId}:${c.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    uniq.push(c);
  }
  return uniq;
}

async function walkForPom(dir: string, out: string[]) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name === "target" || e.name === "node_modules" || e.name.startsWith(".")) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await walkForPom(p, out);
    else if (e.name === "pom.xml") out.push(p);
  }
}

export async function collectMavenDependencies(projectPath: string): Promise<MavenCoord[]> {
  const poms: string[] = [];
  await walkForPom(projectPath, poms);
  const all: MavenCoord[] = [];
  for (const f of poms) {
    try {
      all.push(...(await parsePomFile(f)));
    } catch {
      /* skip broken pom */
    }
  }
  return all;
}
