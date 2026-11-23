# ProofChain AI

Verify the authenticity, origin and history of digital content.

A creator uploads a file, ProofChain fingerprints it (SHA-256), analyzes it for signs of manipulation,
and the creator's wallet registers the fingerprint on a blockchain. Anyone can later check a file or a
verification ID against that record, with no account.

**What a record proves, and what it doesn't.** A blockchain record proves that a wallet registered a
fingerprint at a point in time and that the record has not changed since. It does not prove the content
is true, or that the registrant is the original author. AI analysis is probabilistic and is always
presented that way.

## Status: working prototype

| Area | State |
|---|---|
| Smart contract (`ProvenanceRegistry`) | Done. Records, versions, revocation, identities. 12 tests. |
| Backend API (FastAPI) | Done. 12 tests plus an end-to-end script against a live chain. |
| Public verification portal | Done. By file, ID or QR code. |
| Register flow | Done. MetaMask, or unlocked Hardhat accounts on a local chain. |
| Trust score | Done. Four named components, every point explained. |
| Fraud rules | Done. Burst registration, near-duplicate from another wallet, high AI risk. |
| Investigation dashboard | Basic. Stats, flags, records, per-creator view. |
| Image analysis | Pretrained AI-image classifier (SMOGY, Swin) plus forensic heuristics. |
| Text and documents | Pretrained AI-text classifier (TMR RoBERTa, English) on .txt/.html/.pdf/.docx/.pptx/.odt text; images embedded in PDFs and Office files go through the image classifier. |
| Video | 8 sampled frames through the image classifier. Detects fully generated footage, **not** face-swap or lip-sync deepfakes. Audio track not analyzed. |
| Audio | Metadata markers only. No synthetic-voice model. |
| File safety (all types) | Structural checks: executables, disguised or mismatched file types, Office macros, remote templates, PDF JavaScript/launch actions, archives hiding programs, obfuscated HTML, hidden Unicode. Not an antivirus. |
| Sepolia, PostgreSQL, IPFS | Supported by configuration, not yet exercised. |

## Run it locally

Requirements: Node 20+, Python 3.11–3.13.

```bash
# 1. Local blockchain (keep running)
cd contracts
npm install
npx hardhat node

# 2. Deploy the contract (new terminal)
cd contracts
npx hardhat run scripts/deploy.js --network localhost

# 3. API (new terminal)
cd backend
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt     # macOS/Linux: .venv/bin/python
.venv\Scripts\python ml/download_detector.py               # ~850 MB of detector models (optional)
.venv\Scripts\python -m uvicorn app.main:create_app --factory --port 8000

# 4. Web app (new terminal)
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. On Windows, `.\dev.ps1` does steps 1–4 in one go once dependencies are installed.

Try it: **Register** → drop a file → Analyze → pick *Local dev account #1* → Register. Then open the
verification link, drop the same file to see a match, and an edited copy to see a mismatch.

The local chain is in memory. After restarting it, redeploy and delete `backend/data/proofchain.db`.

### Tests

```bash
cd contracts && npx hardhat test
cd backend   && .venv\Scripts\python -m pytest
cd contracts && npx hardhat run scripts/e2e.js --network localhost   # needs chain + API running
```

## How it fits together

```
 Browser (Next.js) ── upload ──▶ FastAPI ──▶ SHA-256 + analysis ──▶ DB index (SQLite/PostgreSQL)
        │                           │                                metadata (local / IPFS)
        │ wallet signs tx           │ read-only JSON-RPC
        ▼                           ▼
        ProvenanceRegistry contract (Hardhat local → Sepolia)
```

- **The server never holds a private key.** Registration transactions are signed by the creator's
  wallet in the browser; the wallet address is the creator signature. The API only reads the chain.
- **The chain is the source of truth.** Every verification reads the record live from the contract.
  The database is an index for listing, lineage and fraud queries, and is rebuilt lazily from the chain.
- **Files are not stored.** Uploads are hashed and analyzed in memory. Only the fingerprint, a
  perceptual hash, analysis results and the metadata you type are kept.
- **Verification IDs** are `PC-` plus the first 12 hex characters of the fingerprint. The full
  fingerprint also works.

### Trust score (0–100)

| Component | Max | Basis |
|---|---|---|
| Blockchain provenance | 30 | Registered and not revoked |
| Creator identity | 20 | Anonymous 3 · self-declared 8 · admin-attested 20 |
| Content analysis | 30 | `30 × (1 − risk)`, where risk is the worse of AI-generation likelihood and file safety (caution 0.5, danger 0.9); neutral 15 when the type cannot be scored |
| Registration pattern | 20 | Minus 10 per medium flag, 20 per high flag |

Revoked records are capped at 35. Logic: [backend/app/trust.py](backend/app/trust.py).

### Layout

```
contracts/   Solidity contract, Hardhat tests, deploy + e2e scripts
backend/     FastAPI app (app/), tests, optional detector training script (ml/)
frontend/    Next.js app: / (verify), /register, /verify/[id], /dashboard
```

## Configuration

Backend settings are environment variables; see [backend/.env.example](backend/.env.example).

- **PostgreSQL + IPFS + shared rate limiting:** `docker compose up -d`, then set `DATABASE_URL`,
  `IPFS_API_URL`, and/or `RATE_LIMIT_REDIS_URL` in `backend/.env` for the services you use.
- **Sepolia:** fill in [contracts/.env.example](contracts/.env.example) as `contracts/.env`, run
  `npx hardhat run scripts/deploy.js --network sepolia`, then set `RPC_URL` and `DEPLOYMENT_FILE`
  for the backend. Use a throwaway deployer key holding test ETH only.
- **Frontend API location:** `NEXT_PUBLIC_API_URL` (default `http://127.0.0.1:8000`).
- **API abuse limits:** sliding-window limits default to 120 requests/minute per client and 20 uploads/minute
  for `/api/analyze` and `/api/verify/file`. Configure with `API_RATE_LIMIT_PER_MINUTE` and
  `UPLOAD_RATE_LIMIT_PER_MINUTE`. Without Redis these limits are per-process; set `RATE_LIMIT_REDIS_URL`
  to use the shared Redis sliding window included in `docker-compose.yml` across workers/instances.
  Configure Uvicorn's trusted proxy IPs (`--proxy-headers --forwarded-allow-ips=<proxy addresses>`) when
  deploying behind a reverse proxy; the app does not trust arbitrary forwarded headers.
- **Detector models:** fetched by [backend/ml/download_detector.py](backend/ml/download_detector.py) into
  `backend/models/` and run with ONNX Runtime. Without them the backend falls back to heuristics and
  safety checks. The image model is licensed **CC BY-NC 4.0 (non-commercial only)**; the text model is MIT.
  To use your own image model instead, see [backend/ml/train_detector.py](backend/ml/train_detector.py).

## Known limits and next steps

1. **Measure the detectors.** Both are third-party models used as-is. The image model's own card reports
   76–91% accuracy on generators outside its training set, and it also flags some CGI and rendered art.
   Text detectors misfire on formulaic or translated writing. Evaluate on a labelled set before making
   claims, and replace the non-commercial image model before any commercial use.
   A holdout-set evaluator is available at `backend/ml/evaluate_detector.py`; give it separate `real/`
   and `fake/` folders with labeled images. It reports confusion counts, precision, recall, specificity,
   F1 and ROC AUC at the product's 0.6 threshold. No labeled evaluation corpus is included in this repository.
2. **Anyone can register anything first.** Registration proves priority on this registry, not
   authorship. Near-duplicate flags help; verified identities are the real mitigation.
3. **Identity verification is a single admin key.** Move to a multisig or an attester allow-list.
4. **No API authentication** yet; add it before exposing the API publicly. Rate limiting is in place (see Configuration).
5. **No event indexer.** Records registered outside the web app are indexed the first time someone
   verifies them. A background `Registered` log follower would close that gap.
6. **Face-swap/lip-sync deepfake and synthetic-voice models**, C2PA manifest validation, PDF signature
   validation, and scanning inside archives.
7. **Deployment:** Dockerfiles for the API and web app, CI, a Sepolia deployment.
