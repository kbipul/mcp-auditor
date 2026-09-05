import { parseConfig, type ParsedConfig } from "./config";
import { scan, type Finding, type Severity, SEVERITY_ORDER } from "./rules";
import { scoreFindings, type ScoreResult } from "./score";
import { buildMatrix, CAPABILITY_LABEL, type CapabilityMatrixRow } from "./capabilities";

export interface Report extends ScoreResult {
  cfg: ParsedConfig;
  findings: Finding[];
  counts: Record<Severity, number>;
  serverCount: number;
  matrix: CapabilityMatrixRow[];
}

export function analyze(text: string): Report {
  const cfg = parseConfig(text);
  const findings = cfg.valid ? scan(cfg) : cfg.error ? parseErrorFinding(cfg.error) : [];

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;

  return {
    ...scoreFindings(findings),
    cfg,
    findings,
    counts,
    serverCount: cfg.servers.length,
    matrix: buildMatrix(cfg.servers),
  };
}

function parseErrorFinding(error: string): Finding[] {
  return [
    {
      ruleId: "parse-error",
      severity: "low",
      title: "Couldn't parse this as an MCP config",
      detail: error,
      fix: "Paste the mcpServers block from your Claude Desktop / Cursor / VS Code config, as valid JSON.",
      line: 0,
      excerpt: "",
    },
  ];
}

/** Render a report as shareable markdown. */
export function reportToMarkdown(r: Report): string {
  const lines: string[] = [
    `# MCP Auditor report`,
    "",
    `**Grade ${r.grade} (${r.score}/100)** — ${r.verdict}`,
    "",
    `${r.serverCount} server${r.serverCount === 1 ? "" : "s"} · findings: ` +
      SEVERITY_ORDER.map((s) => `${r.counts[s]} ${s}`).join(", "),
    "",
  ];
  if (r.matrix.length) {
    lines.push("## Capability matrix", "");
    for (const row of r.matrix) {
      const caps = row.caps.length ? row.caps.map((c) => CAPABILITY_LABEL[c]).join(", ") : "none detected";
      lines.push(`- **${row.server.name}** — ${caps}`);
    }
    lines.push("");
  }
  for (const sev of SEVERITY_ORDER) {
    const group = r.findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    lines.push(`## ${sev.toUpperCase()}`);
    for (const f of group) {
      lines.push(`- **${f.title}**${f.line ? ` (line ${f.line})` : ""} — ${f.detail}`);
      if (f.excerpt) lines.push(`  - \`${f.excerpt.replace(/`/g, "'")}\``);
      lines.push(`  - Fix: ${f.fix}`);
    }
    lines.push("");
  }
  lines.push("---", "Scanned client-side by MCP Auditor — https://kbipul.github.io/mcp-auditor/");
  return lines.join("\n");
}
