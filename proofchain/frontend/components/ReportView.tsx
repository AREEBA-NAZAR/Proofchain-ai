import Link from "next/link";
import { API_URL, formatSize, formatTime, shortAddr, shortHash, type Report } from "@/lib/api";
import { AnalysisPanel } from "./AnalysisPanel";

const BAND = {
  high: { text: "High", cls: "good" },
  moderate: { text: "Moderate", cls: "warn" },
  low: { text: "Low", cls: "bad" },
  unregistered: { text: "Unregistered", cls: "neutral" },
};
const SEVERITY = { high: "bad", medium: "warn", info: "neutral" };

function StatusBanner({ report }: { report: Report }) {
  const fc = report.file_check;
  if (fc && !fc.match) {
    return (
      <div className="banner bad">
        <h2>✕ File does not match</h2>
        <p>{fc.message}</p>
      </div>
    );
  }
  if (report.status === "verified") {
    return (
      <div className="banner good">
        <h2>✓ {fc ? "File matches a registered record" : "Registered record found"}</h2>
        <p>
          {fc ? fc.message + " " : ""}Registered {formatTime(report.record!.timestamp)} by{" "}
          {report.identity?.name || shortAddr(report.record!.creator)}.
        </p>
      </div>
    );
  }
  if (report.status === "revoked") {
    return (
      <div className="banner warn">
        <h2>! Record revoked</h2>
        <p>The creator registered this content and later withdrew their attestation.</p>
      </div>
    );
  }
  return (
    <div className="banner neutral">
      <h2>No record found</h2>
      <p>
        {fc?.message ||
          "Nothing is registered for this fingerprint. That does not mean the content is fake, only that it has no provenance record here."}
      </p>
    </div>
  );
}

export function ReportView({ report }: { report: Report }) {
  const { record, identity, trust } = report;
  const band = BAND[trust.band];
  return (
    <>
      <StatusBanner report={report} />

      <div className="grid2">
        <div className="card">
          <h2>Trust score</h2>
          <div className="score">
            <b>{trust.score}</b>
            <span className="muted">/ {trust.max}</span>
            <span className={`pill ${band.cls}`}>{band.text}</span>
          </div>
          {trust.components.map((c) => (
            <div className="component" key={c.id}>
              <div className="head">
                <span>{c.label}</span>
                <span>
                  {c.points} / {c.max}
                </span>
              </div>
              <div className="bar">
                <i style={{ width: `${(c.points / c.max) * 100}%` }} />
              </div>
              <div className="muted small">{c.detail}</div>
            </div>
          ))}
        </div>

        <div className="card">
          <h2>Provenance record</h2>
          {record ? (
            <dl>
              <dt>Verification ID</dt>
              <dd className="mono">{record.short_id}</dd>
              {report.asset && (report.asset.title || report.asset.filename) && (
                <>
                  <dt>Title</dt>
                  <dd>
                    {report.asset.title || report.asset.filename}{" "}
                    <span className="muted small">({formatSize(report.asset.size)})</span>
                  </dd>
                </>
              )}
              <dt>Creator</dt>
              <dd>
                {identity ? (
                  <>
                    {identity.name}{" "}
                    <span className={`pill ${identity.verified ? "good" : "neutral"}`}>
                      {identity.verified ? "verified identity" : "self-declared"}
                    </span>
                    <br />
                  </>
                ) : null}
                <Link className="mono" href={`/dashboard?creator=${record.creator}`}>
                  {record.creator}
                </Link>
              </dd>
              <dt>Registered</dt>
              <dd>{formatTime(record.timestamp)}</dd>
              <dt>Version</dt>
              <dd>{record.version}</dd>
              <dt>Fingerprint</dt>
              <dd className="mono">{record.content_hash}</dd>
              {record.tx_hash && (
                <>
                  <dt>Transaction</dt>
                  <dd className="mono">
                    {record.tx_hash} <span className="muted">(block {record.block_number})</span>
                  </dd>
                </>
              )}
              <dt>Network</dt>
              <dd>
                {report.chain.network} <span className="muted small mono">{shortAddr(report.chain.contract)}</span>
              </dd>
              <dt>Times checked</dt>
              <dd>{report.verification_count}</dd>
            </dl>
          ) : (
            <dl>
              <dt>Fingerprint</dt>
              <dd className="mono">{report.content_hash}</dd>
              <dt>Network</dt>
              <dd>{report.chain.network}</dd>
            </dl>
          )}
          {record && (
            <div className="row" style={{ marginTop: 16, alignItems: "flex-end" }}>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img className="qr" src={`${API_URL}/api/verify/${record.content_hash}/qr.png`} alt="QR code linking to this verification page" />
              <div className="small">
                <div className="muted">Scan to verify</div>
                {!record.revoked && <Link href={`/register?parent=${record.short_id}`}>Register a new version →</Link>}
              </div>
            </div>
          )}
        </div>
      </div>

      {report.flags.length > 0 && (
        <div className="card">
          <h2>Flags on this record</h2>
          {report.flags.map((f) => (
            <p key={f.id}>
              <span className={`pill ${SEVERITY[f.severity]}`}>{f.kind.replace(/_/g, " ")}</span> {f.detail}{" "}
              {f.related_hash && <Link href={`/verify/${f.related_hash}`}>View related record</Link>}
            </p>
          ))}
        </div>
      )}

      {report.lineage.length > 1 && (
        <div className="card">
          <h2>Version history</h2>
          <ul className="timeline">
            {report.lineage.map((r) => (
              <li key={r.content_hash} className={r.content_hash === report.content_hash ? "current" : ""}>
                <b>Version {r.version}</b>
                {r.title ? ` · ${r.title}` : ""} {r.revoked && <span className="pill warn">revoked</span>}{" "}
                {r.content_hash === report.content_hash && <span className="pill neutral">this record</span>}
                <div className="small muted">
                  {formatTime(r.timestamp)} ·{" "}
                  <Link className="mono" href={`/verify/${r.content_hash}`}>
                    {shortHash(r.content_hash)}
                  </Link>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      <AnalysisPanel analysis={report.analysis} />

      <div className="disclaimer">
        {report.disclaimers.map((d) => (
          <p key={d}>{d}</p>
        ))}
      </div>
    </>
  );
}
