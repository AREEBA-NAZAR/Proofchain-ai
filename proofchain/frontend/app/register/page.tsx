"use client";

import { ZeroHash } from "ethers";
import Link from "next/link";
import { useEffect, useState } from "react";
import { AnalysisPanel } from "@/components/AnalysisPanel";
import { FileDrop } from "@/components/FileDrop";
import {
  API_URL, api, formatTime, postFile, shortAddr, signInWallet,
  type AnalyzeResult, type ChainConfig, type Identity, type RecordInfo, type Report,
} from "@/lib/api";
import { connectDev, connectInjected, explainTxError, hasInjectedWallet, registry, type Wallet } from "@/lib/wallet";

export default function RegisterPage() {
  const [cfg, setCfg] = useState<ChainConfig | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [parentId, setParentId] = useState("");
  const [analysis, setAnalysis] = useState<AnalyzeResult | null>(null);
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [name, setName] = useState("");
  const [done, setDone] = useState<RecordInfo | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api<ChainConfig>("/api/config").then(setCfg).catch((e) => setError(e.message));
    const parent = new URLSearchParams(window.location.search).get("parent");
    if (parent) setParentId(parent);
  }, []);

  /** Run an async step with shared busy/error handling. */
  async function step(label: string, fn: () => Promise<void>) {
    setBusy(label);
    setError("");
    try {
      await fn();
    } catch (e: any) {
      setError(e?.revert || e?.code ? explainTxError(e) : e.message);
    } finally {
      setBusy("");
    }
  }

  const analyze = () =>
    step("Fingerprinting and analyzing…", async () => {
      setDone(null);
      let activeWallet = wallet;
      if (cfg?.walletAuthRequired && !activeWallet) {
        activeWallet = await connectInjected(cfg);
        setWallet(activeWallet);
        const creator = await api<{ identity: Identity | null }>(`/api/creators/${activeWallet.address}`);
        setIdentity(creator.identity);
      }
      const token = cfg?.walletAuthRequired && activeWallet
        ? await signInWallet(activeWallet.address, (message) => activeWallet!.signer.signMessage(message))
        : undefined;
      setAuthToken(token ?? null);
      setAnalysis(await postFile<AnalyzeResult>("/api/analyze", file!, { title, description }, token));
    });

  const connect = (fn: () => Promise<Wallet>) =>
    step("Connecting wallet…", async () => {
      const w = await fn();
      setWallet(w);
      const creator = await api<{ identity: Identity | null }>(`/api/creators/${w.address}`);
      setIdentity(creator.identity);
    });

  const saveIdentity = () =>
    step("Saving identity on-chain…", async () => {
      const tx = await registry(cfg!, wallet!.signer).setIdentity(name.trim(), "");
      await tx.wait();
      setIdentity({ name: name.trim(), metadata_uri: "", verified: false, registered_at: 0 });
      setName("");
    });

  const register = () =>
    step("Waiting for the transaction…", async () => {
      const token = cfg?.walletAuthRequired && wallet
        ? await signInWallet(wallet.address, (message) => wallet.signer.signMessage(message))
        : authToken;
      setAuthToken(token ?? null);
      let parentHash = ZeroHash;
      if (parentId.trim()) {
        const parent = await api<Report>(`/api/verify/${encodeURIComponent(parentId.trim())}`);
        if (!parent.record) throw new Error("The previous version you entered is not registered.");
        if (parent.record.creator.toLowerCase() !== wallet!.address.toLowerCase())
          throw new Error("Only the wallet that registered the previous version can add a new version.");
        parentHash = parent.record.content_hash;
      }
      const tx = await registry(cfg!, wallet!.signer).register(analysis!.content_hash, parentHash, analysis!.metadata_uri);
      await tx.wait();
      setDone(
        await api<RecordInfo>("/api/records/confirm", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          body: JSON.stringify({ content_hash: analysis!.content_hash, tx_hash: tx.hash }),
        }),
      );
    });

  if (done) {
    const url = `${window.location.origin}/verify/${done.content_hash}`;
    return (
      <>
        <h1>Registered</h1>
        <div className="banner good">
          <h2>✓ Provenance record created</h2>
          <p>
            Version {done.version}, registered {formatTime(done.timestamp)} by {shortAddr(done.creator)}.
          </p>
        </div>
        <div className="card row" style={{ alignItems: "flex-start", gap: 20 }}>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img className="qr" src={`${API_URL}/api/verify/${done.content_hash}/qr.png`} alt="QR code for this record" />
          <dl style={{ flex: 1, minWidth: 260 }}>
            <dt>Verification ID</dt>
            <dd className="mono">{done.short_id}</dd>
            <dt>Public link</dt>
            <dd className="mono">
              <Link href={`/verify/${done.content_hash}`}>{url}</Link>
            </dd>
            <dt>Transaction</dt>
            <dd className="mono">{done.tx_hash}</dd>
          </dl>
        </div>
        <p className="muted">
          Share the ID, link or QR code alongside your file. Keep the original file unchanged: any edit produces a
          different fingerprint.
        </p>
        <button className="secondary" onClick={() => { setDone(null); setAnalysis(null); setFile(null); setParentId(""); }}>
          Register another file
        </button>
      </>
    );
  }

  return (
    <div className="steps">
      <h1>Register content</h1>
      <p className="muted" style={{ maxWidth: 640 }}>
        Record a file's fingerprint on the blockchain, signed by your wallet. The file itself never leaves the analysis
        step and is not stored.
      </p>
      {error && <div className="error">{error}</div>}

      <div className="card">
        <h2 className="step-title">Choose and analyze the file</h2>
        <FileDrop file={file} onFile={(f) => { setFile(f); setAnalysis(null); }} />
        <div className="grid2">
          <div>
            <label htmlFor="title">Title (optional)</label>
            <input id="title" type="text" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div>
            <label htmlFor="parent">New version of (optional)</label>
            <input id="parent" type="text" placeholder="PC-… of the previous version" value={parentId} onChange={(e) => setParentId(e.target.value)} />
          </div>
        </div>
        <label htmlFor="desc">Description (optional)</label>
        <textarea id="desc" maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />
        <div style={{ marginTop: 14 }}>
          <button onClick={analyze} disabled={!file || !cfg || !!busy}>
            {busy.startsWith("Fingerprinting") ? busy : "Analyze file"}
          </button>
        </div>
      </div>

      {analysis && (
        <>
          <div className="card">
            <h2>Fingerprint</h2>
            <p className="mono">{analysis.content_hash}</p>
            {analysis.already_registered && (
              <div className="banner warn" style={{ marginBottom: 0 }}>
                <p>
                  This exact file was already registered by {shortAddr(analysis.already_registered.creator)} on{" "}
                  {formatTime(analysis.already_registered.timestamp)}.{" "}
                  <Link href={`/verify/${analysis.content_hash}`}>View the record</Link>
                </p>
              </div>
            )}
          </div>
          <AnalysisPanel analysis={analysis.analysis} />
        </>
      )}

      {analysis && !analysis.already_registered && (
        <div className="card">
          <h2 className="step-title">Sign with your wallet</h2>
          {!wallet ? (
            <>
              <p className="muted">
                Your wallet address becomes the creator of the record. You pay the network fee
                {cfg?.rpcUrl ? " (free on the local test chain)" : ""}.
              </p>
              <div className="row">
                <button onClick={() => connect(() => connectInjected(cfg!))} disabled={!cfg || !!busy || !hasInjectedWallet()}>
                  Connect browser wallet
                </button>
                {cfg?.rpcUrl &&
                  [1, 2, 3].map((i) => (
                    <button key={i} className="secondary" onClick={() => connect(() => connectDev(cfg, i))} disabled={!!busy}>
                      Local dev account #{i}
                    </button>
                  ))}
              </div>
              {!hasInjectedWallet() && <p className="muted small" style={{ marginTop: 10 }}>No browser wallet detected. Install MetaMask to use your own wallet.</p>}
            </>
          ) : (
            <>
              <dl>
                <dt>Wallet</dt>
                <dd className="mono">{wallet.address} <span className="muted">({wallet.label})</span></dd>
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
              {!identity?.verified && (
                <div className="row" style={{ marginTop: 10 }}>
                  <input type="text" maxLength={80} placeholder={identity ? "Change display name" : "Add a display name (optional)"} value={name} onChange={(e) => setName(e.target.value)} />
                  <button className="secondary" onClick={saveIdentity} disabled={!name.trim() || !!busy}>
                    Save name
                  </button>
                </div>
              )}
              <div className="row" style={{ marginTop: 16 }}>
                <button onClick={register} disabled={!!busy}>
                  {busy || "Register on blockchain"}
                </button>
                <button className="secondary" onClick={() => { setWallet(null); setIdentity(null); }} disabled={!!busy}>
                  Switch wallet
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
