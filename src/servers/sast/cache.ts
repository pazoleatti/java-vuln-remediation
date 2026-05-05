import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

function cacheDir(): string {
  return process.env.SAST_CACHE_DIR?.trim() || join(tmpdir(), "sast-mcp-cache");
}

export async function readCachedReport(uuid: string): Promise<unknown | null> {
  try {
    const text = await readFile(join(cacheDir(), `${uuid}.json`), "utf8");
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

export async function writeCachedReport(uuid: string, report: unknown): Promise<void> {
  const dir = cacheDir();
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, `${uuid}.json`), JSON.stringify(report), "utf8");
}
