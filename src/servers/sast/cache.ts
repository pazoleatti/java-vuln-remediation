import { mkdir, readFile, writeFile, rm, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

function cacheRoot(): string {
  return process.env.SAST_CACHE_DIR?.trim() || join(tmpdir(), "sast-mcp-cache");
}

function byCommitDir(): string {
  return join(cacheRoot(), "by-commit");
}

function reportPath(commitHash: string): string {
  return join(byCommitDir(), `${commitHash}.json`);
}

export async function readCachedReportByCommit(commitHash: string): Promise<unknown | null> {
  try {
    const text = await readFile(reportPath(commitHash), "utf8");
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

export async function writeCachedReportByCommit(
  commitHash: string,
  report: unknown
): Promise<void> {
  const dir = byCommitDir();
  await mkdir(dir, { recursive: true });
  await writeFile(reportPath(commitHash), JSON.stringify(report), "utf8");
}

/**
 * Locate a cached report by its `taskUuid`. Used by get_report when the caller
 * has a uuid (e.g. previously returned by request_report) but the cache is
 * keyed by commit hash. Performs a directory scan; cardinality of cached
 * entries is small (one per commit ever fetched) so this stays O(N) without
 * a separate index file.
 */
export async function findCachedReportByUuid(
  uuid: string
): Promise<{ commitHash: string; report: unknown } | null> {
  let entries: string[];
  try {
    entries = await readdir(byCommitDir());
  } catch {
    return null;
  }
  for (const file of entries) {
    if (!file.endsWith(".json")) continue;
    try {
      const text = await readFile(join(byCommitDir(), file), "utf8");
      const report = JSON.parse(text) as Record<string, unknown>;
      if (typeof report.taskUuid === "string" && report.taskUuid === uuid) {
        return { commitHash: file.replace(/\.json$/, ""), report };
      }
    } catch {
      // skip malformed entry; treat as cache miss for this iteration
    }
  }
  return null;
}

export type ClearCacheResult = {
  scope: "all" | "commit";
  removed: number;
};

export async function clearCache(commitHash?: string): Promise<ClearCacheResult> {
  if (commitHash) {
    try {
      await rm(reportPath(commitHash), { force: true });
      return { scope: "commit", removed: 1 };
    } catch {
      return { scope: "commit", removed: 0 };
    }
  }
  let entries: string[];
  try {
    entries = await readdir(byCommitDir());
  } catch {
    return { scope: "all", removed: 0 };
  }
  let removed = 0;
  for (const file of entries) {
    if (!file.endsWith(".json")) continue;
    try {
      await rm(join(byCommitDir(), file), { force: true });
      removed++;
    } catch {
      // skip; partial clear is still progress
    }
  }
  return { scope: "all", removed };
}
