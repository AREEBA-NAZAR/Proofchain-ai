"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { FileDrop } from "@/components/FileDrop";
import { ReportView } from "@/components/ReportView";
import { postFile, type Report } from "@/lib/api";

export default function Home() {
  const router = useRouter();
  const [id, setId] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function checkFile(f: File) {
    setFile(f);
    setReport(null);
    setError("");
    setBusy(true);
    try {
      setReport(await postFile<Report>("/api/verify/file", f));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h1>Verify digital content</h1>
      <p className="muted" style={{ maxWidth: 640 }}>
        Check whether a file matches a provenance record on the blockchain, who registered it, and how it has changed.
        No account needed.
      </p>

      <div className="grid2" style={{ marginTop: 24 }}>
        <div className="card">
          <h2>Check a file</h2>
          <FileDrop file={file} onFile={checkFile} hint="Fingerprinted on the server and discarded. Never stored." />
          {busy && <p className="muted" style={{ marginTop: 12 }}>Computing fingerprint and checking the registry…</p>}
        </div>
        <form
          className="card"
          onSubmit={(e) => {
            e.preventDefault();
            if (id.trim()) router.push(`/verify/${encodeURIComponent(id.trim())}`);
          }}
        >
          <h2>Enter a verification ID</h2>
          <label htmlFor="vid">Verification ID or SHA-256 fingerprint</label>
          <div className="row">
            <input id="vid" type="text" placeholder="PC-1A2B3C4D5E6F" value={id} onChange={(e) => setId(e.target.value)} />
            <button type="submit" disabled={!id.trim()}>
              Verify
            </button>
          </div>
          <p className="muted small" style={{ marginTop: 12 }}>
            Scanning a ProofChain QR code brings you straight to the record.
          </p>
        </form>
      </div>

      {error && <div className="error">{error}</div>}
      {report && <ReportView report={report} />}
    </>
  );
}
