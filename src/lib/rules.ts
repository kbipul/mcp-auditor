/**
 * The rule engine — pure functions, no DOM, fully unit-testable.
 *
 * An MCP client config (`mcpServers`) is a supply-chain artifact just like an
 * agent skill file: every entry is a program your agent will launch and talk
 * to automatically, on every session, with your permissions. These rules
 * flag the patterns that matter when you audit one before trusting it.
 */
import type { ParsedConfig, ServerEntry } from "./config";
import { classify, type Capability } from "./capabilities";

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
  /** 1-based line number in the canonical (pretty-printed) text; 0 = document-level. */
  line: number;
  excerpt: string;
}

interface LineRule {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
  pattern: RegExp;
}

/* ---------------------------------------------------------------- *
 *  Line-based rules — scanned over the canonical pretty-printed    *
 *  JSON, one token per line, so matches map to a real line number. *
 * ---------------------------------------------------------------- */

const LINE_RULES: LineRule[] = [
  // ---- CRITICAL --------------------------------------------------------
  {
    id: "hardcoded-secret",
    severity: "critical",
    title: "Hardcoded secret in config",
    detail:
      "A real-shaped API key, token or private key is inlined directly in the config file instead of referenced from a secret store.",
    fix: "Move the value to your OS keychain or a local env file excluded from version control; reference it by name only.",
    // Note: GitHub's newer fine-grained token prefix is intentionally not
    // spelled out literally here — that bare prefix, with no required length
    // suffix, is also what generic secret-scanners key off of, which would
    // make this very source file self-trigger a scan of itself. Fine-grained
    // tokens are still caught by secret-in-named-env below, since they're
    // always stored under a TOKEN/KEY-named field.
    pattern: /(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY)/,
  },
  {
    id: "secret-in-named-env",
    severity: "critical",
    title: "Plaintext credential in a secret-named field",
    detail:
      "An env var whose name signals a credential (TOKEN/KEY/SECRET/PASSWORD) holds a long literal value directly in the config, rather than a reference to a keychain or external secret store.",
    fix: "Store the real value in your OS keychain or a local, gitignored env file, and reference it by name only.",
    pattern: /"[A-Za-z0-9_]*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)[A-Za-z0-9_]*"\s*:\s*"[A-Za-z0-9]{20,}"/i,
  },
  {
    id: "remote-pipe-shell",
    severity: "critical",
    title: "Pipes a remote download straight into a shell",
    detail:
      "curl|bash-style commands run unreviewed remote code with your permissions every time this server starts — a classic supply-chain vector, worse here because it launches automatically.",
    fix: "Install from a pinned, checksummed package instead of piping an installer script into a shell.",
    pattern: /((curl|wget)[^|\n]{0,120}\|\s*(sudo\s+)?(ba|z|fi|da)?sh\b)|((iwr|invoke-webrequest)[^|\n]{0,120}\|\s*iex)/i,
  },
  {
    id: "destructive-cmd",
    severity: "critical",
    title: "Destructive command in config",
    detail: "Contains a command that can irreversibly destroy data or the system.",
    fix: "Remove it. No MCP server launch step needs recursive force-deletes or disk formatting.",
    pattern: /(rm\s+-rf?\s+[~\/]|mkfs\.|dd\s+if=|chmod\s+(-R\s+)?777\s+\/|DROP\s+TABLE|format\s+c:)/i,
  },
  {
    id: "private-key-block",
    severity: "critical",
    title: "Embedded private key",
    detail: "Contains what looks like a PEM private-key block.",
    fix: "Remove the key immediately and rotate it — it must be considered compromised.",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  },
  {
    id: "root-path-arg",
    severity: "critical",
    title: "Unscoped root filesystem access",
    detail:
      "An argument grants access to the filesystem root, an entire drive, or the bare home directory — the server (and anything that can reach it) can read or write the whole disk.",
    fix: "Narrow the path to the single project directory this server actually needs.",
    pattern: /^\s*"(\/|[A-Za-z]:\\\\?|~)"\s*,?\s*$/,
  },

  // ---- HIGH --------------------------------------------------------------
  {
    id: "url-exec",
    severity: "high",
    title: "Executes code fetched directly from a URL",
    detail: "The command runs a script straight from a URL rather than a named, versioned registry package.",
    fix: "Reference a published package with a pinned version instead of an ad-hoc URL.",
    pattern: /"https?:\/\/[^"]*\.(sh|ps1|py)"/i,
  },
  {
    id: "auto-approve",
    severity: "high",
    title: "Disables consent / approval prompts",
    detail: "Requests skipping confirmation prompts, removing the human from the loop for this server's actions.",
    fix: "Let the client's normal consent flow stand for every tool call.",
    pattern: /(dangerously-skip-permissions|--dangerously|auto[-\s]?approve\s+(all|everything)|--yes-i-know|bypass[-\s]?consent)/i,
  },

  // ---- MEDIUM --------------------------------------------------------------
  {
    id: "latest-tag",
    severity: "medium",
    title: "Pinned to @latest",
    detail:
      "Explicitly requests the @latest tag — the code that executes tomorrow can differ from what you reviewed today, even though a version-pin syntax is present.",
    fix: "Pin an exact version, e.g. @scope/pkg@1.4.2, instead of @latest.",
    pattern: /@latest\b/i,
  },
  {
    id: "broad-home-path",
    severity: "medium",
    title: "Broad home-directory access",
    detail: "Grants access to an entire user profile or top-level folder rather than a specific project path.",
    fix: "Scope the allowed path to the exact directory the server needs, not the whole home folder.",
    pattern: /"\s*(\$HOME|%USERPROFILE%|\/home\/[^/"]+|\/Users\/[^/"]+)\s*"\s*,?\s*$/,
  },
  {
    id: "sudo-usage",
    severity: "medium",
    title: "Elevated privileges (sudo)",
    detail: "Root access inside a server your agent launches automatically amplifies every other risk here.",
    fix: "Drop sudo; if elevation is unavoidable, isolate it in a documented manual setup step, not the launch command.",
    pattern: /\bsudo\b/,
  },
  {
    id: "global-install",
    severity: "medium",
    title: "Global package install",
    detail: "npm -g / system-wide installs change the whole machine, not just this server's environment.",
    fix: "Prefer npx/uvx with a pinned version over a global install.",
    pattern: /(-g\b|--global\b)/,
  },

  // ---- LOW -----------------------------------------------------------------
  {
    id: "debug-verbose",
    severity: "low",
    title: "Verbose/debug logging enabled",
    detail: "Debug-level logs can end up echoing secrets from env vars or arguments into log files.",
    fix: "Only enable verbose logging temporarily, and check logs don't retain them afterward.",
    pattern: /(--verbose|--debug|-vvv|LOG_LEVEL"\s*:\s*"debug")/i,
  },
  {
    id: "placeholder-left",
    severity: "low",
    title: "Unfilled placeholder value",
    detail: "A literal placeholder (e.g. YOUR_TOKEN_HERE) was left in the config instead of a real value.",
    fix: "Fill in the real value from your secret store, or remove the field if unused.",
    pattern: /(YOUR[_-][A-Z_]*|CHANGEME|<[A-Z_]+>|xxx+)/,
  },
];

/* ---------------------------------------------------------------- *
 *  Document-level rules — need the parsed server list, not just    *
 *  single lines, because combos span multiple entries.             *
 * ---------------------------------------------------------------- */

const RUNNER_COMMANDS = /^(npx|uvx|pnpm|bunx|yarn)$/i;

/** True if a package-spec arg carries an explicit version, e.g. pkg@1.2.3 or @scope/pkg@1.2.3. */
function hasVersionPin(pkgArg: string): boolean {
  // Strip a leading scope segment (@scope/name) before checking for the version "@".
  const rest = pkgArg.startsWith("@") ? pkgArg.slice(1).replace(/^[^/]+\//, "") : pkgArg;
  return rest.includes("@");
}

function unpinnedPackageFindings(servers: ServerEntry[]): Finding[] {
  const out: Finding[] = [];
  for (const s of servers) {
    const cmd = (s.command ?? "").split(/[\\/]/).pop() ?? "";
    if (!RUNNER_COMMANDS.test(cmd)) continue;
    const pkgArg = s.args.find((a) => !a.startsWith("-") && a !== "-y" && a !== "--yes");
    if (!pkgArg) continue;
    if (!hasVersionPin(pkgArg)) {
      out.push({
        ruleId: "unpinned-remote-package",
        severity: "medium",
        title: "Unpinned package execution",
        detail: `Server "${s.name}" runs "${pkgArg}" via ${cmd} with no version pin — the code that executes tomorrow can differ from what you reviewed today.`,
        fix: `Pin an exact version, e.g. ${pkgArg}@1.4.2, instead of leaving it unversioned.`,
        line: 0,
        excerpt: "",
      });
    }
  }
  return out;
}

function combinedFindings(cfg: ParsedConfig): Finding[] {
  const out: Finding[] = [...unpinnedPackageFindings(cfg.servers)];
  const byCap = new Map<Capability, ServerEntry[]>();
  for (const s of cfg.servers) {
    for (const cap of classify(s)) {
      const list = byCap.get(cap) ?? [];
      list.push(s);
      byCap.set(cap, list);
    }
  }

  const shellServers = byCap.get("shell") ?? [];
  if (shellServers.length > 0) {
    out.push({
      ruleId: "shell-exposed",
      severity: "critical",
      title: "Raw shell / interpreter exposed as an MCP server",
      detail: `${listNames(shellServers)} launch${shellServers.length === 1 ? "es" : ""} a general-purpose interpreter directly. A tool built on a raw shell has no scope boundary at all — it can do anything the interpreter can do.`,
      fix: "Replace with a purpose-built MCP server package that exposes a narrow, named set of tools instead of a full interpreter.",
      line: 0,
      excerpt: "",
    });
  }

  const fsServers = byCap.get("filesystem") ?? [];
  const netServers = [...(byCap.get("network") ?? []), ...(byCap.get("browser") ?? [])];
  if (fsServers.length > 0 && netServers.length > 0) {
    out.push({
      ruleId: "fs-network-combo",
      severity: "high",
      title: "Filesystem + network capability combo — exfiltration path",
      detail:
        `This config enables both filesystem access (${listNames(fsServers)}) and outbound network/browser access (${listNames(netServers)}) at the same time. Neither server needs to be malicious: an agent that can read local files and also reach the network has a built-in path to move data off the machine.`,
      fix: "If both are genuinely needed, keep them — but review what each server's declared tools can actually touch, and prefer a network server with an allow-listed set of hosts.",
      line: 0,
      excerpt: "",
    });
  }

  const credServers = byCap.get("credentials") ?? [];
  if (credServers.length >= 2) {
    out.push({
      ruleId: "multi-credential-blast-radius",
      severity: "medium",
      title: "Multiple servers hold long-lived credentials",
      detail: `${credServers.length} servers (${listNames(credServers)}) each carry credential-shaped env vars in this one config file — a single leaked config now exposes all of them at once.`,
      fix: "Store credentials in your OS keychain where the MCP client supports it, rather than plaintext env values in the config.",
      line: 0,
      excerpt: "",
    });
  }

  return out;
}

function listNames(servers: ServerEntry[]): string {
  return servers.map((s) => `"${s.name}"`).join(", ");
}

function trimExcerpt(s: string): string {
  const t = s.trim();
  return t.length > 120 ? t.slice(0, 117) + "…" : t;
}

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Scan a parsed config and return all findings, sorted by severity then line. */
export function scan(cfg: ParsedConfig): Finding[] {
  const lines = cfg.canonicalText.split("\n");
  const findings: Finding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of LINE_RULES) {
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          detail: rule.detail,
          fix: rule.fix,
          line: i + 1,
          excerpt: trimExcerpt(line),
        });
      }
    }
  }

  if (cfg.valid) findings.push(...combinedFindings(cfg));

  // De-duplicate identical rule hits on the same line.
  const seen = new Set<string>();
  const unique = findings.filter((f) => {
    const k = `${f.ruleId}:${f.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return unique.sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || a.line - b.line
  );
}
