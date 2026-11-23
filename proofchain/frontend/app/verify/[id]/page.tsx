"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { FileDrop } from "@/components/FileDrop";
import { ReportView } from "@/components/ReportView";
import { api, postFile, type Report } from "@/lib/api";

export default function VerifyPage() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<Report | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setReport(null);
    setFile(null);
    setError("");
    api<Report>(`/api/verify/${id}`)
      .then(setReport)
      .catch((e) => setError(e.message));
  }, [id]);

  async function compare(f: File) {
    if (!report) return;
    setFile(f);
    setBusy(true);
    setError("");
    try {
      setReport(await postFile<Report>("/api/verify/file", f, { expected: report.content_hash }));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h1>Verification report</h1>
      {error && <div className="error">{error}</div>}
      {!report && !error && <p className="muted">Reading the record from the blockchain…</p>}
      {report && (
        <>
          <ReportView report={report} />
          {report.record && (
            <div className="card" style={{ marginTop: 16 }}>
              <h2>Do you have the file?</h2>
              <p className="muted">
                Drop it here to confirm it is byte-for-byte identical to what was registered.
              </p>
              <FileDrop file={file} onFile={compare} hint="Fingerprinted and discarded. Never stored." />
              {busy && <p className="muted" style={{ marginTop: 12 }}>Comparing…</p>}
            </div>
          )}
        </>
      )}
    </>
  );
}
