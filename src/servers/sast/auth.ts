import { readFile } from "node:fs/promises";

export type TokenProvider = () => Promise<string>;

/**
 * Build a JWT provider from env. Token never returned in tool responses, never
 * stored on the server object — held only inside this closure.
 *
 * Precedence: SAST_JWT_FILE (path) > SAST_JWT (inline). File is preferred so
 * the token does not appear in `ps` output or shell history. File is re-read
 * on every call so rotation works without restarting the MCP server.
 */
export function makeTokenProvider(): TokenProvider {
  const file = process.env.SAST_JWT_FILE?.trim();
  const inline = process.env.SAST_JWT?.trim();

  if (file) {
    return async () => {
      const raw = await readFile(file, "utf8");
      const tok = raw.trim();
      if (!tok) throw new Error(`SAST_JWT_FILE is empty: ${file}`);
      return tok;
    };
  }
  if (inline) {
    return async () => inline;
  }
  throw new Error(
    "Set SAST_JWT_FILE (path to a file containing the JWT) or SAST_JWT (inline) before starting the server."
  );
}
