import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { EMPTY_STATE, stateFileSchema, type StateFile, type VulnerabilityState } from "./schema.js";

function stateDir(): string {
  return process.env.SAST_AGENT_STATE_DIR?.trim() || join(process.cwd(), ".sast-agent");
}

function statePath(): string {
  return join(stateDir(), "state.json");
}

export async function readState(): Promise<StateFile> {
  try {
    const text = await readFile(statePath(), "utf8");
    const parsed = JSON.parse(text) as unknown;
    return stateFileSchema.parse(parsed);
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException)?.code === "ENOENT") {
      return { ...EMPTY_STATE, vulnerabilities: [] };
    }
    throw e;
  }
}

export async function writeState(state: StateFile): Promise<void> {
  const dir = stateDir();
  await mkdir(dir, { recursive: true });
  const target = statePath();
  const tmp = `${target}.tmp.${process.pid}.${Date.now()}`;
  await writeFile(tmp, JSON.stringify(state, null, 2), "utf8");
  await rename(tmp, target);
}

/**
 * Look up by composite key. If sastUuid is omitted and >1 record matches,
 * returns "ambiguous" so the caller can ask the agent to disambiguate.
 */
export function findVulnState(
  state: StateFile,
  vulnerabilityId: string,
  sastUuid: string | undefined
): { kind: "found"; record: VulnerabilityState } | { kind: "missing" } | { kind: "ambiguous"; uuids: string[] } {
  const matches = state.vulnerabilities.filter(
    (v) => v.vulnerabilityId === vulnerabilityId && (sastUuid == null || v.sastUuid === sastUuid)
  );
  if (matches.length === 0) return { kind: "missing" };
  if (matches.length > 1) return { kind: "ambiguous", uuids: matches.map((m) => m.sastUuid) };
  return { kind: "found", record: matches[0] };
}

export function replaceVulnState(state: StateFile, updated: VulnerabilityState): StateFile {
  return {
    ...state,
    vulnerabilities: state.vulnerabilities.map((v) =>
      v.vulnerabilityId === updated.vulnerabilityId && v.sastUuid === updated.sastUuid ? updated : v
    ),
  };
}

export function statePathForDisplay(): string {
  return statePath();
}
