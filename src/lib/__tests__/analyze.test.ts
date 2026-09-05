import { describe, it, expect } from "vitest";
import { analyze, reportToMarkdown } from "../analyze";
import { SAMPLES } from "../samples";

describe("analyze — integration over the built-in samples", () => {
  it("grades the clean sample A or B with no critical findings", () => {
    const r = analyze(SAMPLES.find((s) => s.id === "clean")!.text);
    expect(r.counts.critical).toBe(0);
    expect(["A", "B"]).toContain(r.grade);
  });

  it("grades the sketchy sample worse than clean but with no critical findings", () => {
    const r = analyze(SAMPLES.find((s) => s.id === "sketchy")!.text);
    expect(r.counts.critical).toBe(0);
    expect(r.counts.medium).toBeGreaterThan(0);
  });

  it("grades the hostile sample F with multiple critical findings", () => {
    const r = analyze(SAMPLES.find((s) => s.id === "malicious")!.text);
    expect(r.grade).toBe("F");
    expect(r.counts.critical).toBeGreaterThan(1);
    const ids = r.findings.map((f) => f.ruleId);
    expect(ids).toContain("fs-network-combo");
    expect(ids).toContain("shell-exposed");
    expect(ids).toContain("secret-in-named-env");
  });

  it("orders the clean sample better than the hostile one", () => {
    const clean = analyze(SAMPLES.find((s) => s.id === "clean")!.text);
    const hostile = analyze(SAMPLES.find((s) => s.id === "malicious")!.text);
    expect(clean.score).toBeGreaterThan(hostile.score);
  });

  it("handles empty input without throwing", () => {
    const r = analyze("");
    expect(r.serverCount).toBe(0);
    expect(r.findings.length).toBeGreaterThan(0); // the "nothing to scan" notice
  });

  it("renders a markdown report containing the grade and capability matrix", () => {
    const r = analyze(SAMPLES.find((s) => s.id === "malicious")!.text);
    const md = reportToMarkdown(r);
    expect(md).toMatch(/Grade F/);
    expect(md).toMatch(/Capability matrix/);
  });
});
