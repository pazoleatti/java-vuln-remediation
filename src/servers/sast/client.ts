import { redactErrorMessage } from "../../shared/redact.js";
import type { TokenProvider } from "./auth.js";

export type RequestReportInput = {
  commitHash: string;
  distributionUrl: string;
};

/**
 * Thin HTTP client for the corporate SAST API (ASPAS). Contract:
 *   - POST {base}/api/v1/report
 *       body: { practice: "SAST", type: "EXTENDED", format: "JSON",
 *               hash: <commitHash>, distributionUrl }
 *       → { reportUuid, ... }
 *   - GET  {base}/api/v1/report/{uuid}                                  → full report JSON
 *
 * The token is held inside the `getToken` closure passed in; this class never
 * stores it as a field, so JSON.stringify(client) cannot leak it.
 */
export class SastClient {
  constructor(
    private readonly baseUrl: string,
    private readonly getToken: TokenProvider
  ) {
    if (!baseUrl) throw new Error("SAST_API_BASE_URL is required");
  }

  requestReport(input: RequestReportInput): Promise<unknown> {
    const body = {
      practice: "SAST",
      type: "EXTENDED",
      format: "JSON",
      hash: input.commitHash,
      distributionUrl: input.distributionUrl,
    };
    return this.fetchJson("POST", "/api/v1/report", body);
  }

  getReport(reportUuid: string): Promise<unknown> {
    return this.fetchJson("GET", `/api/v1/report/${encodeURIComponent(reportUuid)}`);
  }

  private async fetchJson(
    method: "GET" | "POST",
    path: string,
    body?: unknown
  ): Promise<unknown> {
    const token = await this.getToken();
    const url = `${this.baseUrl.replace(/\/+$/, "")}${path}`;

    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`SAST ${method} ${path} failed: ${redactErrorMessage(msg)}`);
    }

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(
        `SAST ${method} ${path} → ${res.status} ${res.statusText}: ${redactErrorMessage(text).slice(0, 1000)}`
      );
    }
    return (await res.json()) as unknown;
  }
}
