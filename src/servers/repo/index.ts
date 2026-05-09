#!/usr/bin/env node
import { resolve } from "node:path";

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
      await runGitWithStdin(["apply", "--whitespace=nowarn", "-"], repoRoot, diff);
      return textResult({ applied: true });
    } catch (e) {
      return errorResult(toMessage(e));
    }
  }
);

mcpServer.registerTool(
  "commit",
  {
    description:
      "Stage and commit. If `paths` is provided, only those paths are staged; otherwise all changes are staged (`git add -A`). The commit message is passed exactly as given. Returns the new commit hash and subject.",
    inputSchema: {
      message: z.string().min(1),
      paths: z.array(z.string().min(1)).optional(),
    },
  },
  async ({ message, paths }) => {
    try {
      if (paths && paths.length > 0) {
        for (const p of paths) safeJoin(repoRoot, p);
        await runGit(["add", "--", ...paths], repoRoot);
      } else {
        await runGit(["add", "-A"], repoRoot);
      }
      // Refuse to make an empty commit — that almost always indicates the
      // fix-agent staged nothing and would otherwise leave a "fix" with no
      // changes, polluting the run.
      const { stdout: staged } = await runGit(["diff", "--cached", "--name-only"], repoRoot);
      if (staged.trim().length === 0) {
        return errorResult("nothing staged — refusing to create an empty commit");
      }
      await runGit(["commit", "-m", message], repoRoot);
      const { stdout: hash } = await runGit(["rev-parse", "HEAD"], repoRoot);
      const { stdout: subject } = await runGit(
        ["log", "-1", "--pretty=format:%s"],
        repoRoot
      );
      return textResult({ commitHash: hash.trim(), subject: subject.trim() });
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
