import type { Analysis } from "@/lib/api";

const VERDICT: Record<Analysis["verdict"], { text: string; cls: string }> = {
  no_strong_signals: { text: "No strong signs of AI generation or unsafe content", cls: "good" },
  inconclusive: { text: "Inconclusive", cls: "warn" },
  elevated: { text: "Elevated risk", cls: "bad" },
  not_assessed: { text: "Not assessed", cls: "neutral" },
};

const KIND: Record<string, string> = {
  image: "Image",
  video: "Video",
  audio: "Audio",
  pdf: "PDF document",
  office: "Office document",
  legacy_office: "Legacy Office document",
  text: "Text",
  archive: "Archive",
  executable: "Program",
  other: "Unrecognized file",
};

export function AnalysisPanel({ analysis }: { analysis: Analysis | null }) {
  if (!analysis) {
    return (
      <div className="card">
        <h2>Content analysis</h2>
        <p className="muted">
          ProofChain has not seen this file, so there is no analysis. Upload the file itself to analyze it.
        </p>
      </div>
    );
  }
  const v = VERDICT[analysis.verdict];
  const findings = analysis.safety?.findings ?? [];
  return (
    <div className="card">
      <h2>Content analysis</h2>
      <p>
        <span className={`pill ${v.cls}`}>{v.text}</span>{" "}
        <span className="muted small">
          {KIND[analysis.kind] || analysis.kind}
          {analysis.ai_risk !== null && analysis.ai_risk !== undefined && (
            <> · AI-generation likelihood {Math.round(analysis.ai_risk * 100)}%</>
          )}
        </span>
      </p>
      {analysis.note && <p className="muted">{analysis.note}</p>}

      {findings.length > 0 && (
        <div className={`banner ${analysis.safety!.level === "danger" ? "bad" : "warn"}`}>
          <h2 style={{ fontSize: 15 }}>
            {analysis.safety!.level === "danger" ? "Unsafe content found" : "Handle with caution"}
          </h2>
          {findings.map((f) => (
            <p key={f.id} className="small" style={{ marginTop: 6 }}>
              <b>{f.label}.</b> {f.detail}
            </p>
          ))}
        </div>
      )}
      {analysis.safety && findings.length === 0 && (
        <p className="small">
          <span className="pill good">File safety</span>{" "}
          <span className="muted">No macros, scripts, disguised file types or other risky structures found.</span>
        </p>
      )}

      {analysis.signals.map((s) => (
        <div className="component" key={s.id}>
          <div className="head">
            <span>{s.label}</span>
            {s.score !== null && <span>{Math.round(s.score * 100)}%</span>}
          </div>
          {s.score !== null && (
            <div className="bar">
              <i style={{ width: `${Math.round(s.score * 100)}%` }} />
            </div>
          )}
          <div className="muted small">{s.detail}</div>
        </div>
      ))}
      <p className="muted small">
        These results are probabilistic. Detectors miss some AI content and wrongly flag some genuine content, and the
        safety checks are structural, not an antivirus scan. Treat this as a reason to look closer, never as proof.
      </p>
    </div>
  );
}
