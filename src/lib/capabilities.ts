/**
 * Capability classification — the heuristic core that makes combo detection
 * possible. Real MCP servers are launched as `command + args`, not declared
 * with a formal permission manifest, so we infer what a server can *reach*
 * from its package name, command and arguments.
 */
import type { ServerEntry } from "./config";

export type Capability = "filesystem" | "network" | "browser" | "shell" | "database" | "credentials";

export const CAPABILITY_LABEL: Record<Capability, string> = {
  filesystem: "Filesystem",
  network: "Network",
  browser: "Browser",
  shell: "Shell / exec",
  database: "Database",
  credentials: "Holds credentials",
};

// General-purpose interpreters: if one of these is the *command itself*
// (not just mentioned somewhere), the server can run arbitrary code by
// construction, not just within some MCP-scoped sandbox.
const RAW_INTERPRETERS = /^(bash|sh|zsh|cmd(\.exe)?|powershell(\.exe)?|pwsh|python3?|ruby|perl|node)$/i;

function haystackFor(s: ServerEntry): string {
  return [s.name, s.command ?? "", ...s.args, s.url ?? ""].join(" ").toLowerCase();
}

export function classify(s: ServerEntry): Set<Capability> {
  const caps = new Set<Capability>();
  const h = haystackFor(s);
  const cmdBase = (s.command ?? "").split(/[\\/]/).pop() ?? "";

  if (/(filesystem|file-?system|\bfs\b|allowed-director|--root\b|\bdirectory\b)/.test(h)) {
    caps.add("filesystem");
  }
  if (/(fetch|\bhttp\b|https?:\/\/|webhook|web-search|\bapi\b|requests?\b)/.test(h)) {
    caps.add("network");
  }
  if (/(puppeteer|playwright|browser|chrome-devtools|selenium)/.test(h)) {
    caps.add("browser");
    caps.add("network"); // a headless browser can always reach the network
  }
  if (/(postgres|mysql|sqlite|mongo|\bsql\b|redis|database)/.test(h)) {
    caps.add("database");
  }
  if (/(shell|\bexec\b|terminal|process-run|command-runner)/.test(h) || RAW_INTERPRETERS.test(cmdBase)) {
    caps.add("shell");
  }
  const secretish = /token|key|secret|password|credential|passwd|apikey/i;
  if (Object.keys(s.env).some((k) => secretish.test(k))) {
    caps.add("credentials");
  }

  return caps;
}

export interface CapabilityMatrixRow {
  server: ServerEntry;
  caps: Capability[];
}

export function buildMatrix(servers: ServerEntry[]): CapabilityMatrixRow[] {
  return servers.map((server) => ({ server, caps: Array.from(classify(server)) }));
}
