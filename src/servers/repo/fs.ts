import { mkdir, readFile, writeFile, stat } from "node:fs/promises";
import { dirname, isAbsolute, normalize, resolve, sep } from "node:path";

/**
 * Resolve a user-supplied path against the repo root and refuse anything that
 * escapes via "..", absolute paths pointing elsewhere, or symlink-like trickery
 * at the string level. Symlinks themselves are not resolved here — the agent
 * is responsible for not pointing at them; this guards the common path-traversal
 * vector, not a hostile filesystem.
 */
export function safeJoin(root: string, p: string): string {
  if (typeof p !== "string" || p.length === 0) {
    throw new Error("path must be a non-empty string");
  }
  if (p.includes("\0")) {
    throw new Error("path contains NUL byte");
  }
  const rootAbs = resolve(root);
  const abs = isAbsolute(p) ? normalize(p) : resolve(rootAbs, p);
  if (abs !== rootAbs && !abs.startsWith(rootAbs + sep)) {
    throw new Error(`path escapes repo root: ${p}`);
  }
  return abs;
}

export async function readFileText(root: string, relPath: string): Promise<string> {
  const abs = safeJoin(root, relPath);
  return await readFile(abs, "utf8");
}

export async function writeFileText(
  root: string,
  relPath: string,
  content: string
): Promise<void> {
  const abs = safeJoin(root, relPath);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, content, "utf8");
}

export async function pathExists(root: string, relPath: string): Promise<boolean> {
  try {
    const abs = safeJoin(root, relPath);
    await stat(abs);
    return true;
  } catch {
    return false;
  }
}
