import { useMemo, useState, useCallback, useRef } from "react";
import { analyze, reportToMarkdown } from "./lib/analyze";
import { SEVERITY_ORDER, type Severity } from "./lib/rules";
import { SAMPLES } from "./lib/samples";
import { CAPABILITY_LABEL, type Capability } from "./lib/capabilities";

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const CAP_ORDER: Capability[] = ["shell", "filesystem", "network", "browser", "database", "credentials"];

export default function App() {
  const [text, setText] = useState(SAMPLES[2].text); // open on the hostile one — that's the wow
  const [activeSample, setActiveSample] = useState("malicious");
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [copied, setCopied] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const report = useMemo(() => analyze(text), [text]);

  const visible = useMemo(
    () => (filter === "all" ? report.findings : report.findings.filter((f) => f.severity === filter)),
    [report, filter]
  );

  const loadSample = (id: string) => {
    const s = SAMPLES.find((x) => x.id === id)!;
    setText(s.text);
    setActiveSample(id);
    setFilter("all");
  };

  const onFile = useCallback(async (file: File) => {
    const content = await file.text();
    setText(content);
    setActiveSample("");
    setFilter("all");
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const f = e.dataTransfer.files?.[0];
      if (f) void onFile(f);
    },
    [onFile]
  );

  const copyReport = async () => {
    await navigator.clipboard.writeText(reportToMarkdown(report));
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  return (
    <div className="app" onDrop={onDrop} onDragOver={(e) => e.preventDefault()}>
      <header>
        <div className="title">
          <h1>
            MCP<span className="accent">Auditor</span>
          </h1>
          <p className="sub">
            Audit your MCP server config <em>before</em> your agent does. Hardcoded secrets, unpinned
            remote execution, root filesystem access, and dangerous capability combos like
            filesystem+network exfiltration paths — scanned entirely in your browser. Nothing is
            uploaded.
          </p>
        </div>
        <a className="gh" href="https://github.com/kbipul/mcp-auditor" target="_blank" rel="noreferrer">
          View source
        </a>
      </header>

      <section className="samples">
        <span className="samples-label">Try one:</span>
        {SAMPLES.map((s) => (
          <button
            key={s.id}
            className={`chip ${activeSample === s.id ? "chip-on" : ""}`}
            onClick={() => loadSample(s.id)}
            title={s.blurb}
          >
            {s.label}
          </button>
        ))}
        <button className="chip chip-ghost" onClick={() => fileRef.current?.click()}>
          Upload a file…
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,.txt"
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void onFile(f);
          }}
        />
        <span className="hint">…or drop a claude_desktop_config.json anywhere on this page</span>
      </section>

      <main>
        <div className="pane">
          <div className="pane-head">
            <h2>MCP config</h2>
            <span className="meta">
              {report.serverCount} server{report.serverCount === 1 ? "" : "s"}
            </span>
          </div>
          <textarea
            spellCheck={false}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setActiveSample("");
            }}
            placeholder='Paste an mcpServers config here, e.g. { "mcpServers": { "files": { "command": "npx", "args": [...] } } }'
            aria-label="MCP config contents"
          />
        </div>

        <div className="pane">
          <div className="pane-head">
            <h2>Report</h2>
            <button className="chip chip-ghost" onClick={copyReport} disabled={!text.trim()}>
              {copied ? "Copied ✓" : "Copy as markdown"}
            </button>
          </div>

          <div className={`verdict grade-${report.grade}`}>
            <div className="grade-badge">{report.grade}</div>
            <div className="verdict-text">
              <strong>{report.score}/100</strong>
              <p>{report.verdict}</p>
            </div>
          </div>

          {report.matrix.length > 0 && (
            <div className="matrix">
              <h3>Capability matrix</h3>
              <table>
                <thead>
                  <tr>
                    <th>Server</th>
                    {CAP_ORDER.map((c) => (
                      <th key={c} title={CAPABILITY_LABEL[c]}>
                        {CAPABILITY_LABEL[c]}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {report.matrix.map((row) => (
                    <tr key={row.server.name}>
                      <td className="server-name">{row.server.name}</td>
                      {CAP_ORDER.map((c) => (
                        <td key={c} className="cap-cell">
                          {row.caps.includes(c) ? <span className={`dot cap-${c}`} /> : null}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="counts">
            <button
              className={`count-pill ${filter === "all" ? "on" : ""}`}
              onClick={() => setFilter("all")}
            >
              All <b>{report.findings.length}</b>
            </button>
            {SEVERITY_ORDER.map((s) => (
              <button
                key={s}
                className={`count-pill sev-${s} ${filter === s ? "on" : ""}`}
                onClick={() => setFilter(filter === s ? "all" : s)}
                disabled={report.counts[s] === 0}
              >
                {SEV_LABEL[s]} <b>{report.counts[s]}</b>
              </button>
            ))}
          </div>

          <div className="findings">
            {visible.length === 0 && (
              <div className="empty">
                {report.findings.length === 0
                  ? "No findings. Still worth a human read — a scanner catches patterns, not intent."
                  : "Nothing at this severity."}
              </div>
            )}
            {visible.map((f, i) => (
              <article key={`${f.ruleId}-${f.line}-${i}`} className={`finding sev-${f.severity}`}>
                <div className="finding-head">
                  <span className={`tag sev-${f.severity}`}>{SEV_LABEL[f.severity]}</span>
                  <h3>{f.title}</h3>
                  {f.line > 0 && <span className="line">line {f.line}</span>}
                </div>
                {f.excerpt && <pre className="excerpt">{f.excerpt}</pre>}
                <p className="detail">{f.detail}</p>
                <p className="fix">
                  <span>Fix</span> {f.fix}
                </p>
              </article>
            ))}
          </div>
        </div>
      </main>

      <footer>
        <p>
          <b>What this is and isn't.</b> MCP Auditor is a static pattern scanner over the config text —
          it infers capability from command/package names and arguments, not from the server's actual
          declared tools. A clean report means "nothing obvious found in the launch config", never
          "safe". Read each server's own documentation before you trust it.
        </p>
        <p className="by">
          Built by{" "}
          <a href="https://www.kumarbipul.com" target="_blank" rel="noreferrer">
            Kumar Bipul
          </a>{" "}
          · Day 7 of{" "}
          <a href="https://github.com/kbipul/kb-daily-builds" target="_blank" rel="noreferrer">
            kb-daily-builds
          </a>{" "}
          · sibling to{" "}
          <a href="https://github.com/kbipul/skill-scan" target="_blank" rel="noreferrer">
            SkillScan
          </a>
        </p>
      </footer>
    </div>
  );
}
