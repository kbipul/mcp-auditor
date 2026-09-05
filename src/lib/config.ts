/**
 * Parser for MCP client configs — the `mcpServers` block used by Claude
 * Desktop, Claude Code, Cursor, Windsurf and VS Code's MCP support. Also
 * accepts a bare `{ "name": { command/args/env/url } }` map without the
 * wrapper key, since some tools (and most copy-pasted snippets) omit it.
 *
 * We re-serialize to a canonical, pretty-printed form before handing text to
 * the line-based rule engine — that guarantees one JSON token per line, which
 * keeps line-numbered findings accurate regardless of how the input was
 * formatted (minified, tabs, whatever).
 */

export interface ServerEntry {
  name: string;
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string; // http/sse transport servers declare a URL instead of a command
  raw: unknown;
}

export interface ParsedConfig {
  valid: boolean;
  error?: string;
  servers: ServerEntry[];
  /** Pretty-printed JSON used for line-based scanning; falls back to raw text on parse failure. */
  canonicalText: string;
}

export function parseConfig(text: string): ParsedConfig {
  const trimmed = text.trim();
  if (!trimmed) {
    return { valid: false, error: "Nothing to scan yet — paste a config.", servers: [], canonicalText: "" };
  }

  let obj: unknown;
  try {
    obj = JSON.parse(trimmed);
  } catch (e) {
    return {
      valid: false,
      error: `Invalid JSON: ${e instanceof Error ? e.message : String(e)}`,
      servers: [],
      canonicalText: text,
    };
  }

  if (typeof obj !== "object" || obj === null) {
    return { valid: false, error: "Expected a JSON object.", servers: [], canonicalText: text };
  }

  const root = obj as Record<string, unknown>;
  const serverMap: Record<string, unknown> =
    root.mcpServers && typeof root.mcpServers === "object"
      ? (root.mcpServers as Record<string, unknown>)
      : root.servers && typeof root.servers === "object"
        ? (root.servers as Record<string, unknown>)
        : root;

  const entries = Object.entries(serverMap).filter(
    ([, v]) => typeof v === "object" && v !== null
  ) as [string, Record<string, unknown>][];

  const servers: ServerEntry[] = entries.map(([name, v]) => ({
    name,
    command: typeof v.command === "string" ? v.command : undefined,
    args: Array.isArray(v.args) ? v.args.map(String) : [],
    env:
      v.env && typeof v.env === "object"
        ? Object.fromEntries(
            Object.entries(v.env as Record<string, unknown>).map(([k, val]) => [k, String(val)])
          )
        : {},
    url: typeof v.url === "string" ? v.url : undefined,
    raw: v,
  }));

  if (servers.length === 0) {
    return {
      valid: false,
      error: 'Valid JSON, but no server entries found. Expected an "mcpServers" object (or a bare map of server name → { command, args, env }).',
      servers: [],
      canonicalText: JSON.stringify(obj, null, 2),
    };
  }

  return { valid: true, servers, canonicalText: JSON.stringify(obj, null, 2) };
}
