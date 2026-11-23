// End-to-end smoke test against a running local node + backend:
//   analyze -> register on-chain -> confirm -> verify -> new version -> tamper check -> revoke
// Run:  npx hardhat run scripts/e2e.js --network localhost
const assert = require("assert");
const crypto = require("crypto");
const hre = require("hardhat");
const deployment = require("../deployments/localhost.json");

const API = process.env.API_URL || "http://127.0.0.1:8000";

async function api(path, init) {
  const res = await fetch(API + path, init);
  const body = await res.json();
  if (!res.ok) throw new Error(`${path} -> ${res.status} ${JSON.stringify(body)}`);
  return body;
}

function upload(path, bytes, name, fields = {}) {
  const form = new FormData();
  form.append("file", new Blob([bytes]), name);
  for (const [k, v] of Object.entries(fields)) form.append(k, v);
  return api(path, { method: "POST", body: form });
}

async function main() {
  const [admin, alice] = await hre.ethers.getSigners();
  const registry = await hre.ethers.getContractAt("ProvenanceRegistry", deployment.address);
  const run = crypto.randomBytes(8).toString("hex"); // unique content per run
  const v1 = Buffer.from(`ProofChain e2e document ${run} - version 1`);
  const v2 = Buffer.from(`ProofChain e2e document ${run} - version 2`);

  const cfg = await api("/api/config");
  assert.equal(cfg.address, deployment.address);

  // 1. analyze + register v1
  const a1 = await upload("/api/analyze", v1, "report.txt", { title: "E2E report" });
  assert.equal(a1.content_hash, "0x" + crypto.createHash("sha256").update(v1).digest("hex"));
  assert.equal((await api(`/api/verify/${a1.content_hash}`)).status, "not_found");

  const tx1 = await registry.connect(alice).register(a1.content_hash, hre.ethers.ZeroHash, a1.metadata_uri);
  await tx1.wait();
  const rec1 = await api("/api/records/confirm", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ content_hash: a1.content_hash, tx_hash: tx1.hash }),
  });
  assert.equal(rec1.creator, alice.address);
  assert.equal(rec1.tx_hash, tx1.hash);
  assert.ok(rec1.block_number > 0);

  // 2. verify by short id; anonymous wallet
  let report = await api(`/api/verify/${rec1.short_id}`);
  assert.equal(report.status, "verified");
  const anonScore = report.trust.score;

  // 3. identity: self-declare, then admin attests
  await (await registry.connect(alice).setIdentity(`Alice Press ${run}`, "")).wait();
  await (await registry.connect(admin).setVerified(alice.address, true)).wait();
  report = await api(`/api/verify/${a1.content_hash}`);
  assert.equal(report.identity.verified, true);
  assert.ok(report.trust.score > anonScore);

  // 4. new version registered directly on-chain, never confirmed: verify must still find it
  const a2 = await upload("/api/analyze", v2, "report-v2.txt");
  await (await registry.connect(alice).register(a2.content_hash, a1.content_hash, a2.metadata_uri)).wait();
  report = await api(`/api/verify/${a1.content_hash}`);
  assert.deepEqual(report.lineage.map((r) => r.version), [1, 2]);
  assert.equal(report.lineage[1].content_hash, a2.content_hash);

  // 5. tamper check
  const ok = await upload("/api/verify/file", v1, "report.txt", { expected: rec1.short_id });
  assert.equal(ok.file_check.match, true);
  const bad = await upload("/api/verify/file", Buffer.concat([v1, Buffer.from(" ")]), "report.txt", {
    expected: rec1.short_id,
  });
  assert.equal(bad.file_check.match, false);

  // 6. QR
  const qr = await fetch(`${API}/api/verify/${rec1.short_id}/qr.png`);
  assert.equal(qr.headers.get("content-type"), "image/png");

  // 7. revoke
  await (await registry.connect(alice).revoke(a2.content_hash, "superseded")).wait();
  report = await api(`/api/verify/${a2.content_hash}`);
  assert.equal(report.status, "revoked");
  assert.ok(report.trust.score <= 35);

  console.log(`E2E OK — ${rec1.short_id} trust ${anonScore} -> ${(await api(`/api/verify/${a1.content_hash}`)).trust.score}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
