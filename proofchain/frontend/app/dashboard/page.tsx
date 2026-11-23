"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, formatTime, shortAddr, type Flag, type Identity, type RecordInfo, type Stats } from "@/lib/api";

const SEVERITY = { high: "bad", medium: "warn", info: "neutral" };
type CreatorView = { address: string; identity: Identity | null; records: RecordInfo[]; flags: Flag[] };

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [records, setRecords] = useState<RecordInfo[]>([]);
  const [flags, setFlags] = useState<Flag[]>([]);
  const [creator, setCreator] = useState<string | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setCreator(new URLSearchParams(window.location.search).get("creator"));
  }, []);

  useEffect(() => {
    setError("");
    const load = creator
      ? api<CreatorView>(`/api/creators/${creator}`).then((c) => {
          setRecords(c.records);
          setFlags(c.flags);
          setIdentity(c.identity);
        })
      : Promise.all([api<RecordInfo[]>("/api/records"), api<Flag[]>("/api/flags")]).then(([r, f]) => {
          setRecords(r);
          setFlags(f);
          setIdentity(null);
        });
    Promise.all([load, api<Stats>("/api/stats").then(setStats)]).catch((e) => setError(e.message));
  }, [creator]);

  const pick = (address: string | null) => {
    setCreator(address);
    window.history.replaceState(null, "", address ? `/dashboard?creator=${address}` : "/dashboard");
  };

  return (
    <>
      <h1>Investigation dashboard</h1>
      <p className="muted">Indexed provenance records, registration patterns and linked evidence.</p>
      {error && <div className="error">{error}</div>}

      {stats && (
        <div className="tiles">
          <div className="tile"><b>{stats.records}</b><span className="muted small">Records ({stats.revoked} revoked)</span></div>
          <div className="tile"><b>{stats.creators}</b><span className="muted small">Creators</span></div>
          <div className="tile"><b>{stats.verifications}</b><span className="muted small">Checks ({stats.mismatches} mismatches)</span></div>
          <div className="tile"><b>{stats.flags_serious}</b><span className="muted small">Serious flags ({stats.flags} total)</span></div>
        </div>
      )}

      {creator && (
        <div className="card">
          <h2>Creator</h2>
          <dl>
            <dt>Wallet</dt>
            <dd className="mono">{creator}</dd>
            <dt>Identity</dt>
            <dd>
              {identity ? (
                <>
                  {identity.name}{" "}
                  <span className={`pill ${identity.verified ? "good" : "neutral"}`}>
                    {identity.verified ? "verified identity" : "self-declared"}
                  </span>
                </>
              ) : (
                <span className="muted">Anonymous wallet</span>
              )}
            </dd>
          </dl>
          <button className="secondary" style={{ marginTop: 14 }} onClick={() => pick(null)}>
            ← All creators
          </button>
        </div>
      )}

      <div className="card">
        <h2>Flags{creator ? " for this creator" : ""}</h2>
        {flags.length === 0 ? (
          <p className="muted">No suspicious registration patterns detected.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Flag</th><th>Record</th><th>Creator</th><th>Detail</th></tr>
              </thead>
              <tbody>
                {flags.map((f) => (
                  <tr key={f.id}>
                    <td><span className={`pill ${SEVERITY[f.severity]}`}>{f.kind.replace(/_/g, " ")}</span></td>
                    <td><Link className="mono" href={`/verify/${f.content_hash}`}>{f.short_id}</Link></td>
                    <td><a className="mono" href="#" onClick={(e) => { e.preventDefault(); pick(f.creator); }}>{shortAddr(f.creator)}</a></td>
                    <td>
                      {f.detail}{" "}
                      {f.related_hash && <Link href={`/verify/${f.related_hash}`}>Related record</Link>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2>{creator ? "Records by this creator" : "Recent records"}</h2>
        {records.length === 0 ? (
          <p className="muted">
            Nothing registered yet. <Link href="/register">Register a file</Link>
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>ID</th><th>Title</th><th>Creator</th><th>Version</th><th>AI risk</th><th>Registered</th></tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.content_hash}>
                    <td><Link className="mono" href={`/verify/${r.content_hash}`}>{r.short_id}</Link></td>
                    <td>{r.title || <span className="muted">—</span>} {r.revoked && <span className="pill warn">revoked</span>}</td>
                    <td><a className="mono" href="#" onClick={(e) => { e.preventDefault(); pick(r.creator); }}>{shortAddr(r.creator)}</a></td>
                    <td>{r.version}</td>
                    <td>{r.risk === null ? <span className="muted">n/a</span> : `${Math.round(r.risk * 100)}%`}</td>
                    <td>{formatTime(r.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
