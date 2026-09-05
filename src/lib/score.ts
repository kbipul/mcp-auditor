import type { Finding, Severity } from "./rules";

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface ScoreResult {
  score: number; // 0..100
  grade: Grade;
  verdict: string;
}

/** Deduction per finding, and a per-rule cap so one noisy rule can't zero the config alone. */
const WEIGHT: Record<Severity, number> = { critical: 30, high: 15, medium: 7, low: 3 };
const CAP_MULTIPLIER = 2;

export function scoreFindings(findings: Finding[]): ScoreResult {
  const byRule = new Map<string, number>();
  let deduction = 0;

  for (const f of findings) {
    const w = WEIGHT[f.severity];
    const used = byRule.get(f.ruleId) ?? 0;
    const allowed = Math.max(0, w * CAP_MULTIPLIER - used);
    const applied = Math.min(w, allowed);
    byRule.set(f.ruleId, used + applied);
    deduction += applied;
  }

  const score = Math.max(0, 100 - deduction);
  const hasCritical = findings.some((f) => f.severity === "critical");
  const grade = toGrade(score, hasCritical);

  return { score, grade, verdict: verdictFor(score, hasCritical) };
}

function toGrade(score: number, hasCritical: boolean): Grade {
  if (hasCritical) return score >= 50 ? "D" : "F"; // criticals cap the grade
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function verdictFor(score: number, hasCritical: boolean): string {
  if (hasCritical)
    return "Do not connect this config yet. Contains patterns consistent with credential exposure, remote code execution or an unscoped filesystem grant.";
  if (score >= 90) return "Looks clean. A quick human read-through of each server is still good practice.";
  if (score >= 75) return "Mostly fine — review the flagged servers before connecting.";
  if (score >= 60) return "Connect only after fixing the flagged issues.";
  return "High risk — this config needs a full manual review before your agent touches it.";
}
