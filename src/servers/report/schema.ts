import * as z from "zod/v4";

export const vulnerabilityStatusSchema = z.enum([
  "pending",
  "rejected",
  "confirmed",
  "fixed",
  "fix_failed",
  "skipped_notexploit",
]);
export type VulnerabilityStatus = z.infer<typeof vulnerabilityStatusSchema>;

export const decisionSchema = z.object({
  type: z.string().min(1),
  comment: z.string().nullable(),
  author: z.string().nullable(),
  createDate: z.string().nullable(),
});
export type Decision = z.infer<typeof decisionSchema>;

export const vulnerabilityStateSchema = z.object({
  vulnerabilityHash: z.string().min(1),
  sastUuid: z.string().min(1),
  severity: z.string().nullable(),
  cwe: z.string().nullable(),
  title: z.string().nullable(),
  status: vulnerabilityStatusSchema,
  triageReasoning: z.string().nullable(),
  fixCommitHash: z.string().nullable(),
  fixSummary: z.string().nullable(),
  regressionInstructions: z.string().nullable(),
  failureReason: z.string().nullable(),
  decision: decisionSchema.nullable(),
  timestamps: z.object({
    triagedAt: z.string().nullable(),
    fixedAt: z.string().nullable(),
  }),
});
export type VulnerabilityState = z.infer<typeof vulnerabilityStateSchema>;

export const stateFileSchema = z.object({
  version: z.literal(1),
  vulnerabilities: z.array(vulnerabilityStateSchema),
});
export type StateFile = z.infer<typeof stateFileSchema>;

export const EMPTY_STATE: StateFile = { version: 1, vulnerabilities: [] };
