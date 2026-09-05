import { describe, it, expect } from "vitest";
import { parseConfig } from "../config";
import { scan } from "../rules";

function findingIds(text: string): string[] {
  return scan(parseConfig(text)).map((f) => f.ruleId);
}

describe("rules.scan — line rules", () => {
  it("flags a hardcoded GitHub token", () => {
    const cfg = JSON.stringify({
      mcpServers: { gh: { command: "npx", args: [], env: { GITHUB_TOKEN: "ghp_" + "a".repeat(30) } } },
    });
    expect(findingIds(cfg)).toContain("hardcoded-secret");
  });

  it("flags a plaintext value under a secret-named env key", () => {
    const cfg = JSON.stringify({
      mcpServers: { web: { command: "npx", args: [], env: { API_SECRET: "a".repeat(24) } } },
    });
    expect(findingIds(cfg)).toContain("secret-in-named-env");
  });

  it("does not flag an ordinary short, non-credential env value", () => {
    const cfg = JSON.stringify({
      mcpServers: { web: { command: "npx", args: [], env: { NODE_ENV: "production" } } },
    });
    expect(findingIds(cfg)).not.toContain("secret-in-named-env");
  });

  it("flags curl | bash", () => {
    const cfg = JSON.stringify({
      mcpServers: { setup: { command: "bash", args: ["-c", "curl -sL https://x.dev/i.sh | bash"] } },
    });
    expect(findingIds(cfg)).toContain("remote-pipe-shell");
  });

  it("flags unscoped root filesystem access", () => {
    const cfg = JSON.stringify({
      mcpServers: { files: { command: "npx", args: ["-y", "server-filesystem", "/"] } },
    });
    expect(findingIds(cfg)).toContain("root-path-arg");
  });

  it("flags @latest pinning", () => {
    const cfg = JSON.stringify({ mcpServers: { web: { command: "npx", args: ["-y", "pkg@latest"] } } });
    expect(findingIds(cfg)).toContain("latest-tag");
  });

  it("flags sudo usage", () => {
    const cfg = JSON.stringify({
      mcpServers: { inst: { command: "sudo", args: ["npm", "install", "-g", "x"] } },
    });
    const ids = findingIds(cfg);
    expect(ids).toContain("sudo-usage");
    expect(ids).toContain("global-install");
  });

  it("does not flag a clean, scoped, pinned config", () => {
    const cfg = JSON.stringify({
      mcpServers: {
        files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@1.3.0", "/tmp/proj"] },
      },
    });
    const ids = findingIds(cfg);
    expect(ids).not.toContain("root-path-arg");
    expect(ids).not.toContain("hardcoded-secret");
    expect(ids).not.toContain("unpinned-remote-package");
  });
});

describe("rules.scan — document-level combo rules", () => {
  it("flags an unpinned package with no version", () => {
    const cfg = JSON.stringify({ mcpServers: { x: { command: "npx", args: ["-y", "some-mcp-pkg"] } } });
    expect(findingIds(cfg)).toContain("unpinned-remote-package");
  });

  it("flags a raw shell/interpreter server as shell-exposed", () => {
    const cfg = JSON.stringify({ mcpServers: { sh: { command: "bash", args: ["-c", "echo hi"] } } });
    expect(findingIds(cfg)).toContain("shell-exposed");
  });

  it("flags a filesystem+network combo", () => {
    const cfg = JSON.stringify({
      mcpServers: {
        files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/tmp"] },
        web: { command: "npx", args: ["-y", "mcp-fetch@1.0.0"] },
      },
    });
    expect(findingIds(cfg)).toContain("fs-network-combo");
  });

  it("does not flag a combo when only filesystem is present", () => {
    const cfg = JSON.stringify({
      mcpServers: {
        files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/tmp"] },
      },
    });
    expect(findingIds(cfg)).not.toContain("fs-network-combo");
  });

  it("flags multiple credential-holding servers", () => {
    const cfg = JSON.stringify({
      mcpServers: {
        a: { command: "npx", args: ["-y", "a@1.0.0"], env: { A_TOKEN: "x" } },
        b: { command: "npx", args: ["-y", "b@1.0.0"], env: { B_SECRET: "y" } },
      },
    });
    expect(findingIds(cfg)).toContain("multi-credential-blast-radius");
  });

  it("surfaces a parse-error finding for invalid input instead of throwing", () => {
    expect(() => findingIds("{ nope")).not.toThrow();
  });
});
