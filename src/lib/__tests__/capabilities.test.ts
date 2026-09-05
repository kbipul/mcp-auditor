import { describe, it, expect } from "vitest";
import { classify } from "../capabilities";
import type { ServerEntry } from "../config";

function server(over: Partial<ServerEntry>): ServerEntry {
  return { name: "s", command: undefined, args: [], env: {}, raw: {}, ...over };
}

describe("classify", () => {
  it("tags a filesystem server", () => {
    const caps = classify(
      server({ command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] })
    );
    expect(caps.has("filesystem")).toBe(true);
  });

  it("tags a network server from a fetch-shaped package name", () => {
    const caps = classify(server({ command: "npx", args: ["-y", "mcp-fetch"] }));
    expect(caps.has("network")).toBe(true);
  });

  it("tags browser servers as both browser and network", () => {
    const caps = classify(server({ command: "npx", args: ["-y", "playwright-mcp"] }));
    expect(caps.has("browser")).toBe(true);
    expect(caps.has("network")).toBe(true);
  });

  it("tags a raw shell interpreter as shell", () => {
    const caps = classify(server({ command: "bash", args: ["-c", "echo hi"] }));
    expect(caps.has("shell")).toBe(true);
  });

  it("does not tag an ordinary npx-launched package as shell", () => {
    const caps = classify(server({ command: "npx", args: ["-y", "@modelcontextprotocol/server-git"] }));
    expect(caps.has("shell")).toBe(false);
  });

  it("tags credentials from a secret-shaped env var name", () => {
    const caps = classify(server({ command: "npx", args: [], env: { GITHUB_TOKEN: "x" } }));
    expect(caps.has("credentials")).toBe(true);
  });

  it("does not tag credentials for an unrelated env var", () => {
    const caps = classify(server({ command: "npx", args: [], env: { NODE_ENV: "production" } }));
    expect(caps.has("credentials")).toBe(false);
  });
});
