#!/usr/bin/env node
import { relative, resolve } from "node:path";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";

import { pathExists, readFileText, safeJoin, writeFileText } from "./fs.js";
import {
  GitError,
  assertValidBranchName,
  isGitRepo,
  runGit,
  runGitWithStdin,
} from "./git.js";

// ────────────────────────────────────────────────────────────────────────────
// Repo root: env override, fall back to cwd. Must contain a git work tree —
// the server refuses to start otherwise so the orchestrator gets a clear
// error before it tries to delegate fixes into nowhere.
// ────────────────────────────────────────────────────────────────────────────
const repoRoot = resolve(process.env.REPO_MCP_ROOT?.trim() || process.cwd());

if (!(await isGitRepo(repoRoot))) {
  console.error(
    `[repo-mcp] ${repoRoot} is not inside a git work tree. Set REPO_MCP_ROOT to the repo root.`
  );
  process.exit(1);
}

function textResult(payload: unknown) {
  const text =
    typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  return { content: [{ type: "text" as const, text }] };
}

function errorResult(message: string) {
  return { isError: true, content: [{ type: "text" as const, text: message }] };
}

function toMessage(e: unknown): string {
  if (e instanceof GitError) return e.message;
  return e instanceof Error ? e.message : String(e);
}

// ────────────────────────────────────────────────────────────────────────────
// Touched-paths tracking. The fix-agent commits only files it actually
// modified via write_file / apply_patch — never `git add -A`, which would
// otherwise sweep up unrelated manual edits or untracked files in the work
// tree. Entries are repo-relative POSIX paths. Cleared per path on commit.
// ────────────────────────────────────────────────────────────────────────────
const touchedPaths = new Set<string>();

function toRepoRelPosix(root: string, p: string): string {
  const abs = safeJoin(root, p);
  const rel = relative(root, abs);
  return rel.split(/[\\/]/).filter((seg) => seg.length > 0).join("/");
}

function extractPathsFromDiff(diff: string): string[] {
  const out = new Set<string>();
  for (const rawLine of diff.split(/\r?\n/)) {
    // "diff --git a/<old> b/<new>" — unambiguous; covers renames (both sides).
    const dg = rawLine.match(/^diff --git a\/(.+?) b\/(.+)$/);
    if (dg) {
      out.add(dg[1]);
      out.add(dg[2]);
      continue;
    }
    // Fallback for non-git diffs: --- a/<path> / +++ b/<path>. Skip /dev/null
    // (new-file or deleted-file marker on the opposite side).
    const m = rawLine.match(/^(?:---|\+\+\+) (?:a|b)\/(.+)$/);
    if (m) {
      const p = m[1].replace(/\t.*$/, "");
      if (p !== "/dev/null") out.add(p);
    }
  }
  return Array.from(out);
}

const mcpServer = new McpServer({
  name: "repo-mcp",
  version: "0.1.0",
  description:
    "Controlled access to the local git work tree: read, search, list, write, patch, commit, and branch. The fix-agent uses the write subset; the triage-agent only the read subset.",
});

// ════════════════════════════════════════════════════════════════════════════
// READ TOOLS
// ════════════════════════════════════════════════════════════════════════════

mcpServer.registerTool(
  "read_file",
  {
    description:
      "Read a UTF-8 text file from the repo work tree. Optional 1-based line range to slice large files. The path is resolved against the repo root and rejected if it escapes.",
    inputSchema: {
      path: z.string().min(1).describe("Path relative to the repo root."),
      startLine: z.number().int().min(1).optional(),
      endLine: z.number().int().min(1).optional(),
    },
  },
  async ({ path, startLine, endLine }) => {
    try {
      const content = await readFileText(repoRoot, path);
      if (startLine == null && endLine == null) {
        return textResult(content);
      }
      const lines = content.split(/\r?\n/);
      const from = (startLine ?? 1) - 1;
      const to = endLine ?? lines.length;
      if (from < 0 || to < from) {
        return errorResult(`invalid line range ${startLine}..${endLine}`);
      }
      return textResult(lines.slice(from, to).join("\n"));
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

mcpServer.registerTool(
  "search_code",
  {
    description:
      "git grep over tracked files. Returns lines as `path:lineNo:content`. Default mode is regex (POSIX extended); set fixedString=true for literal search. Optional pathScope narrows to a directory or file.",
    inputSchema: {
      pattern: z.string().min(1),
      ignoreCase: z.boolean().optional(),
      fixedString: z.boolean().optional(),
      pathScope: z.string().optional(),
      maxResults: z.number().int().min(1).max(2000).optional(),
    },
  },
  async ({ pattern, ignoreCase, fixedString, pathScope, maxResults }) => {
    try {
      const args = ["grep", "-n", "-I", "--no-color"];
      if (ignoreCase) args.push("-i");
      args.push(fixedString ? "-F" : "-E");
      args.push("-e", pattern);
      if (pathScope) {
        safeJoin(repoRoot, pathScope); // validate
        args.push("--", pathScope);
      }
      let stdout: string;
      try {
        ({ stdout } = await runGit(args, repoRoot));
      } catch (e) {
        // git grep exits 1 when there are no matches — that's not an error here.
        if (e instanceof GitError && e.code === 1 && !e.stderr.trim()) {
          return textResult({ matches: [], truncated: false });
        }
        throw e;
      }
      const all = stdout.split(/\r?\n/).filter((l) => l.length > 0);
      const cap = maxResults ?? 500;
      const matches = all.slice(0, cap);
      return textResult({ matches, truncated: all.length > matches.length, total: all.length });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

mcpServer.registerTool(
  "list_files",
  {
    description:
      "List tracked files (git ls-files), optionally narrowed to a path scope. Pathspec globs supported by git are passed through verbatim after `--`.",
    inputSchema: {
      pathScope: z.string().optional(),
    },
  },
  async ({ pathScope }) => {
    try {
      const args = ["ls-files"];
      if (pathScope) {
        // Validate the scope only if it's a real path; pathspec wildcards won't
        // resolve cleanly through safeJoin, so accept patterns containing "*"
        // without filesystem validation but still reject NUL / leading dashes.
        if (pathScope.includes("\0") || pathScope.startsWith("-")) {
          return errorResult(`invalid pathScope: ${JSON.stringify(pathScope)}`);
        }
        if (!pathScope.includes("*") && !pathScope.includes("?")) {
          safeJoin(repoRoot, pathScope);
        }
        args.push("--", pathScope);
      }
      const { stdout } = await runGit(args, repoRoot);
      const files = stdout.split(/\r?\n/).filter((l) => l.length > 0);
      return textResult({ count: files.length, files });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

mcpServer.registerTool(
  "get_file_history",
  {
    description:
      "Recent commit history for a file: list of {hash, authorDate, author, subject}, newest first. Limit defaults to 20.",
    inputSchema: {
      path: z.string().min(1),
      limit: z.number().int().min(1).max(200).optional(),
    },
  },
  async ({ path, limit }) => {
    try {
      safeJoin(repoRoot, path);
      const sep = "\u001f";
      const { stdout } = await runGit(
        [
          "log",
          `--pretty=format:%H${sep}%aI${sep}%an${sep}%s`,
          `-n`,
          String(limit ?? 20),
          "--",
          path,
        ],
        repoRoot
      );
      const commits = stdout
        .split(/\r?\n/)
        .filter((l) => l.length > 0)
        .map((line) => {
          const [hash, authorDate, author, subject] = line.split(sep);
          return { hash, authorDate, author, subject };
        });
      return textResult({ count: commits.length, commits });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

// ════════════════════════════════════════════════════════════════════════════
// WRITE TOOLS — fix-agent only.
// ════════════════════════════════════════════════════════════════════════════

mcpServer.registerTool(
  "write_file",
  {
    description:
      "Overwrite a UTF-8 text file in the repo work tree. Creates parent directories as needed. Path must resolve inside the repo root.",
    inputSchema: {
      path: z.string().min(1),
      content: z.string(),
    },
  },
  async ({ path, content }) => {
    try {
      const existedBefore = await pathExists(repoRoot, path);
      await writeFileText(repoRoot, path, content);
      touchedPaths.add(toRepoRelPosix(repoRoot, path));
      return textResult({ path, bytes: Buffer.byteLength(content, "utf8"), created: !existedBefore });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

mcpServer.registerTool(
  "apply_patch",
  {
    description:
      "Apply a unified diff to the work tree via `git apply`. The diff is piped on stdin — never written to disk inside the repo. Fails atomically: nothing is changed if any hunk does not apply.",
    inputSchema: {
      diff: z.string().min(1).describe("Unified diff (one or more files)."),
    },
  },
  async ({ diff }) => {
    try {
      const diffPaths = extractPathsFromDiff(diff);
      await runGitWithStdin(["apply", "--whitespace=nowarn", "-"], repoRoot, diff);
      const tracked: string[] = [];
      for (const p of diffPaths) {
        try {
          const norm = toRepoRelPosix(repoRoot, p);
          touchedPaths.add(norm);
          tracked.push(norm);
        } catch {
          // Path failed safeJoin (escapes repo root) — git apply would have
          // refused it too, but be defensive: ignore for tracking purposes.
        }
      }
      return textResult({ applied: true, paths: tracked });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

mcpServer.registerTool(
  "commit",
  {
    description:
      "Stage and commit ONLY paths the agent modified through write_file / apply_patch in this run (tracked internally). `git add -A` is never used, so unrelated manual edits and untracked files in the work tree never end up in the commit. If `paths` is provided, it must be a subset of the agent-touched set — foreign paths are rejected. If omitted, all currently-touched paths are staged. Returns the new commit hash, subject, and the list of committed paths. Successfully-committed paths are then cleared from the touched set.",
    inputSchema: {
      message: z.string().min(1),
      paths: z
        .array(z.string().min(1))
        .optional()
        .describe(
          "Optional subset of agent-touched paths to commit. Each must have been written via write_file or apply_patch in this run."
        ),
    },
  },
  async ({ message, paths }) => {
    try {
      let toStage: string[];
      if (paths && paths.length > 0) {
        toStage = [];
        for (const p of paths) {
          let norm: string;
          try {
            norm = toRepoRelPosix(repoRoot, p);
          } catch (e) {
            return errorResult(toMessage(e));
          }
          if (!touchedPaths.has(norm)) {
            return errorResult(
              `path was not modified by this agent: ${p} — only paths previously written via write_file or apply_patch can be committed`
            );
          }
          toStage.push(norm);
        }
      } else {
        toStage = Array.from(touchedPaths);
      }
      if (toStage.length === 0) {
        return errorResult(
          "no agent-touched paths to commit — call write_file or apply_patch first"
        );
      }
      await runGit(["add", "--", ...toStage], repoRoot);
      // Verify staging actually produced a diff. write_file with identical
      // content, or apply_patch that no-ops against current state, can leave
      // the index unchanged — refuse rather than create an empty commit.
      const { stdout: staged } = await runGit(
        ["diff", "--cached", "--name-only", "--", ...toStage],
        repoRoot
      );
      if (staged.trim().length === 0) {
        return errorResult("nothing staged — refusing to create an empty commit");
      }
      await runGit(["commit", "-m", message], repoRoot);
      const { stdout: hash } = await runGit(["rev-parse", "HEAD"], repoRoot);
      const { stdout: subject } = await runGit(
        ["log", "-1", "--pretty=format:%s"],
        repoRoot
      );
      // Drop committed paths from the touched set so the next fix-agent
      // starts clean. If a caller committed only a subset, remaining touched
      // paths stay for a subsequent commit.
      for (const p of toStage) touchedPaths.delete(p);
      return textResult({
        commitHash: hash.trim(),
        subject: subject.trim(),
        committedPaths: toStage,
      });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

// ════════════════════════════════════════════════════════════════════════════
// STATE TOOLS — read-only checks.
// ════════════════════════════════════════════════════════════════════════════

mcpServer.registerTool(
  "get_current_branch",
  {
    description:
      "Return the current branch name, or `null` if HEAD is detached (with the underlying commit hash).",
    inputSchema: {},
  },
  async () => {
    try {
      const { stdout } = await runGit(["rev-parse", "--abbrev-ref", "HEAD"], repoRoot);
      const name = stdout.trim();
      if (name === "HEAD") {
        const { stdout: hash } = await runGit(["rev-parse", "HEAD"], repoRoot);
        return textResult({ branch: null, detached: true, headCommit: hash.trim() });
      }
      return textResult({ branch: name, detached: false });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

mcpServer.registerTool(
  "get_head_commit",
  {
    description: "Return the HEAD commit: hash, author date, and subject.",
    inputSchema: {},
  },
  async () => {
    try {
      const sep = "\u001f";
      const { stdout } = await runGit(
        ["log", "-1", `--pretty=format:%H${sep}%aI${sep}%s`],
        repoRoot
      );
      const [hash, authorDate, subject] = stdout.split(sep);
      return textResult({ hash, authorDate, subject });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

// ════════════════════════════════════════════════════════════════════════════
// BRANCH TOOLS — orchestrator only.
// ════════════════════════════════════════════════════════════════════════════

mcpServer.registerTool(
  "create_branch",
  {
    description:
      "Create a new branch and switch to it (`git checkout -b`). Optional `from` ref to branch off something other than current HEAD.",
    inputSchema: {
      name: z.string().min(1),
      from: z.string().min(1).optional(),
    },
  },
  async ({ name, from }) => {
    try {
      await assertValidBranchName(name, repoRoot);
      const args = ["checkout", "-b", name];
      if (from) args.push(from);
      await runGit(args, repoRoot);
      return textResult({ branch: name, from: from ?? null });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

mcpServer.registerTool(
  "checkout_branch",
  {
    description: "Switch to an existing branch (`git checkout <name>`).",
    inputSchema: {
      name: z.string().min(1),
    },
  },
  async ({ name }) => {
    try {
      await assertValidBranchName(name, repoRoot);
      await runGit(["checkout", name], repoRoot);
      return textResult({ branch: name });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack ?? err.message : String(err));
  process.exit(1);
});
