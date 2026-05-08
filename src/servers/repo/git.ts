import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const MAX_BUFFER = 16 * 1024 * 1024; // 16MB — large enough for big git grep / log outputs.

export class GitError extends Error {
  constructor(
    message: string,
    public readonly code: number | null,
    public readonly stderr: string
  ) {
    super(message);
    this.name = "GitError";
  }
}

/**
 * Run `git <args>` in the given cwd. Always passed as an argv array — the
 * shell is never invoked, so values from the agent (paths, branch names,
 * commit messages) cannot be interpreted as flags or shell metacharacters.
 * The only remaining risk is git itself treating leading "-" as a flag, so
 * callers that take such values from input must validate them or use "--"
 * separators.
 */
export async function runGit(
  args: string[],
  cwd: string
): Promise<{ stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync("git", args, {
      cwd,
      maxBuffer: MAX_BUFFER,
      windowsHide: true,
    });
    return { stdout, stderr };
  } catch (e) {
    const err = e as NodeJS.ErrnoException & { stdout?: string; stderr?: string; code?: number };
    const stderr = err.stderr ?? "";
    throw new GitError(
      `git ${args[0] ?? ""} failed: ${stderr.trim() || err.message}`,
      typeof err.code === "number" ? err.code : null,
      stderr
    );
  }
}

/**
 * Same as runGit but pipes `stdin` into git. Used for `git apply` so we can
 * accept a unified diff blob from the agent without ever writing it to a
 * tempfile under the repo.
 */
export function runGitWithStdin(
  args: string[],
  cwd: string,
  stdin: string
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const proc = spawn("git", args, { cwd, windowsHide: true });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (b: Buffer) => (stdout += b.toString("utf8")));
    proc.stderr.on("data", (b: Buffer) => (stderr += b.toString("utf8")));
    proc.on("error", (e) =>
      rejectPromise(new GitError(`git ${args[0] ?? ""} spawn failed: ${e.message}`, null, ""))
    );
    proc.on("close", (code) => {
      if (code === 0) {
        resolvePromise({ stdout, stderr });
      } else {
        rejectPromise(
          new GitError(
            `git ${args[0] ?? ""} failed: ${stderr.trim() || `exit code ${code}`}`,
            code,
            stderr
          )
        );
      }
    });
    proc.stdin.end(stdin);
  });
}

/**
 * Reject branch/ref names that would either confuse git (leading "-" looks
 * like a flag) or that git itself rejects. We delegate the deeper rules to
 * `git check-ref-format`; the leading-dash guard runs first because we don't
 * want to pass attacker-controlled flag-shaped input to any git command.
 */
export async function assertValidBranchName(name: string, cwd: string): Promise<void> {
  if (!name || name.startsWith("-") || /\s/.test(name) || name.includes("\0")) {
    throw new Error(`invalid branch name: ${JSON.stringify(name)}`);
  }
  await runGit(["check-ref-format", "--branch", name], cwd);
}

export async function isGitRepo(cwd: string): Promise<boolean> {
  try {
    const { stdout } = await runGit(["rev-parse", "--is-inside-work-tree"], cwd);
    return stdout.trim() === "true";
  } catch {
    return false;
  }
}
