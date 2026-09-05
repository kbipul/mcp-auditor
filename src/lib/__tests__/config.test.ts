import { describe, it, expect } from "vitest";
import { parseConfig } from "../config";

describe("parseConfig", () => {
  it("flags empty input", () => {
    const r = parseConfig("");
    expect(r.valid).toBe(false);
  });

  it("flags invalid JSON", () => {
    const r = parseConfig("{ not json");
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/Invalid JSON/);
  });

  it("parses a standard mcpServers wrapper", () => {
    const r = parseConfig(
      JSON.stringify({
        mcpServers: { files: { command: "npx", args: ["-y", "server-filesystem", "/tmp"] } },
      })
    );
    expect(r.valid).toBe(true);
    expect(r.servers).toHaveLength(1);
    expect(r.servers[0].name).toBe("files");
    expect(r.servers[0].command).toBe("npx");
    expect(r.servers[0].args).toEqual(["-y", "server-filesystem", "/tmp"]);
  });

  it("parses a bare server map without a wrapper key", () => {
    const r = parseConfig(JSON.stringify({ git: { command: "npx", args: ["server-git"] } }));
    expect(r.valid).toBe(true);
    expect(r.servers[0].name).toBe("git");
  });

  it("extracts env vars as string values", () => {
    const r = parseConfig(
      JSON.stringify({ mcpServers: { web: { command: "npx", args: [], env: { TOKEN: "abc123" } } } })
    );
    expect(r.servers[0].env).toEqual({ TOKEN: "abc123" });
  });

  it("flags a valid-JSON object with no server entries", () => {
    const r = parseConfig(JSON.stringify({ hello: "world" }));
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/no server entries/);
  });

  it("rejects a JSON array or primitive", () => {
    expect(parseConfig("[1,2,3]").valid).toBe(false);
    expect(parseConfig("42").valid).toBe(false);
  });
});
