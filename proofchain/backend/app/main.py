import hashlib
import io
import asyncio
import logging
import re
import secrets
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import qrcode
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from eth_keys import keys
from eth_utils import keccak, to_checksum_address
import jwt
from jwt import PyJWTError
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from . import fraud
from .analysis import OnnxTextDetector, analyze, hamming, load_detector
from .chain import ChainClient, ChainRecord, ChainUnavailable
from .config import Settings, get_settings
from .models import Asset, Base, Flag, IndexerCursor, Record, VerificationEvent
from .storage import Storage
from .trust import DISCLAIMERS, compute_trust

HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
SHORT_RE = re.compile(r"^PC-([0-9A-F]{12})$")
MAX_FAMILY = 200
log = logging.getLogger(__name__)


def short_id(content_hash: str) -> str:
    return "PC-" + content_hash[2:14].upper()


class ConfirmBody(BaseModel):
    content_hash: str = Field(pattern=r"^0x[0-9a-fA-F]{64}$")
    tx_hash: str | None = Field(default=None, pattern=r"^0x[0-9a-fA-F]{64}$")


class AuthVerifyBody(BaseModel):
    address: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    nonce: str = Field(min_length=24, max_length=80)
    signature: str = Field(pattern=r"^0x[0-9a-fA-F]{130}$")


def create_app(settings: Settings | None = None, chain=None) -> FastAPI:
    settings = settings or get_settings()
    public_app_url = f"https://{settings.public_app_host}" if settings.public_app_host else settings.public_app_url
    if settings.wallet_auth_required and not settings.auth_token_secret:
        raise ValueError("AUTH_TOKEN_SECRET is required when WALLET_AUTH_REQUIRED is enabled.")

    if settings.database_url.startswith("sqlite:///"):
        Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    engine = create_engine(settings.database_url, connect_args=connect_args)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(engine, expire_on_commit=False)

    chain = chain or ChainClient(settings.rpc_url, settings.deployment_file)
    storage = Storage(settings.storage_dir, settings.ipfs_api_url)
    detector = load_detector(settings.detector_onnx, settings.detector_weights)
    text_detector = OnnxTextDetector(settings.text_detector_dir)
    max_bytes = settings.max_upload_mb * 1024 * 1024
    redis_client = None
    if settings.rate_limit_redis_url:
        from redis.asyncio import Redis

        redis_client = Redis.from_url(settings.rate_limit_redis_url, decode_responses=True)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        indexer_task = asyncio.create_task(indexer_loop()) if settings.indexer_enabled else None
        try:
            yield
        finally:
            if indexer_task:
                indexer_task.cancel()
                with suppress(asyncio.CancelledError):
                    await indexer_task
            if redis_client:
                await redis_client.aclose()
            if isinstance(chain, ChainClient):
                chain.close()

    app = FastAPI(title="ProofChain AI", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Keep expensive public upload routes tighter than ordinary API reads.
    # The client address comes from the ASGI connection; forwarded headers are
    # deliberately not read here because they can be spoofed unless a proxy is
    # explicitly trusted and configured.
    rate_windows: dict[tuple[str, str], deque[float]] = {}
    rate_lock = threading.Lock()
    upload_paths = {"/api/analyze", "/api/verify/file"}
    auth_challenges: dict[tuple[str, str], tuple[str, int]] = {}
    auth_lock = threading.Lock()
    redis_window_script = """
        local key, now, member, max_count = KEYS[1], tonumber(ARGV[1]), ARGV[2], tonumber(ARGV[3])
        local window = 60000
        redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
        local count = redis.call('ZCARD', key)
        if count >= max_count then
            local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
            local retry = math.max(1, math.ceil((tonumber(oldest[2]) + window - now) / 1000))
            redis.call('PEXPIRE', key, window)
            return {0, retry}
        end
        redis.call('ZADD', key, now, member)
        redis.call('PEXPIRE', key, window)
        return {1, 0}
    """

    @app.middleware("http")
    async def rate_limit(request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        group = "upload" if request.url.path in upload_paths else "api"
        limit = settings.upload_rate_limit_per_minute if group == "upload" else settings.api_rate_limit_per_minute
        if redis_client:
            try:
                accepted, retry_after = await redis_client.eval(
                    redis_window_script,
                    1,
                    f"proofchain:rate:{group}:{client}",
                    int(time.time() * 1000),
                    uuid.uuid4().hex,
                    limit,
                )
            except Exception:
                return JSONResponse(
                    status_code=503,
                    content={"detail": "The shared rate limiter is unavailable."},
                )
            if not accepted:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please try again shortly."},
                    headers={"Retry-After": str(retry_after)},
                )
            return await call_next(request)

        now = time.monotonic()
        key = (client, group)
        with rate_lock:
            if key not in rate_windows and len(rate_windows) >= 4096:
                expired = [k for k, entries in rate_windows.items() if not entries or now - entries[-1] >= 60]
                for old_key in expired:
                    rate_windows.pop(old_key, None)
                if len(rate_windows) >= 4096:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Rate limiter is at capacity. Please try again shortly."},
                        headers={"Retry-After": "60"},
                    )
            window = rate_windows.setdefault(key, deque())
            while window and now - window[0] >= 60:
                window.popleft()
            if len(window) >= limit:
                retry_after = max(1, int(60 - (now - window[0])))
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please try again shortly."},
                    headers={"Retry-After": str(retry_after)},
                )
            window.append(now)
        return await call_next(request)

    @app.exception_handler(ChainUnavailable)
    def chain_down(_: Request, exc: ChainUnavailable):
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    def get_db():
        with SessionLocal() as db:
            yield db

    # --------------------------------------------------------------- helpers

    async def read_upload(file: UploadFile) -> bytes:
        data = await file.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise HTTPException(413, f"File exceeds the {settings.max_upload_mb} MB limit.")
        if not data:
            raise HTTPException(400, "The uploaded file is empty.")
        return data

    def ensure_analysis(db: Session, content_hash: str, data: bytes, filename: str, mime: str) -> None:
        """Analyze a file being verified if we have never seen these bytes, so
        the report carries real AI signals instead of a neutral placeholder.
        Only the results are kept, never the file."""
        if db.get(Asset, content_hash) is not None:
            return
        result = analyze(data, filename, detector, text_detector)
        db.add(Asset(content_hash=content_hash, filename=filename, mime=mime, size=len(data),
                     analysis=result, phash=result.get("phash")))
        db.flush()

    def resolve_id(db: Session, raw: str) -> str:
        """Accept a full hash (with or without 0x) or a short PC-XXXXXXXXXXXX id."""
        value = raw.strip()
        lowered = value.lower()
        if not lowered.startswith("0x") and re.fullmatch(r"[0-9a-f]{64}", lowered):
            lowered = "0x" + lowered
        if HASH_RE.match(lowered):
            return lowered
        m = SHORT_RE.match(value.upper())
        if m:
            prefix = "0x" + m.group(1).lower()
            matches = db.scalars(select(Record.content_hash).where(Record.content_hash.startswith(prefix))).all()
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise HTTPException(409, "This short ID is ambiguous. Use the full fingerprint.")
            raise HTTPException(404, "No record found for this verification ID.")
        raise HTTPException(400, "Enter a verification ID (PC-…) or a 64-character SHA-256 fingerprint.")

    def upsert_record(db: Session, cr: ChainRecord) -> Record:
        rec = db.get(Record, cr.content_hash)
        if rec is None:
            rec = Record(**cr.to_dict())
            db.add(rec)
        else:
            rec.revoked = cr.revoked
        return rec

    def index_family(db: Session, cr: ChainRecord) -> None:
        """Index the whole version lineage of a record from the chain."""
        new: list[Record] = []
        seen = {cr.content_hash}
        if db.get(Record, cr.content_hash) is None:
            new.append(upsert_record(db, cr))
        # Walk up to the root…
        cursor = cr
        while cursor.parent_hash and cursor.parent_hash not in seen and len(seen) < MAX_FAMILY:
            parent = chain.get_record(cursor.parent_hash)
            if parent is None:
                break
            seen.add(parent.content_hash)
            if db.get(Record, parent.content_hash) is None:
                new.append(upsert_record(db, parent))
            cursor = parent
        # …then down through every descendant.
        queue = [cursor.content_hash]
        descended = {cursor.content_hash}
        while queue and len(descended) < MAX_FAMILY:
            for child_hash in chain.get_children(queue.pop(0)):
                if child_hash in descended:
                    continue
                descended.add(child_hash)
                queue.append(child_hash)
                if db.get(Record, child_hash) is None:
                    child = chain.get_record(child_hash)
                    if child is not None:
                        new.append(upsert_record(db, child))
        db.flush()
        for rec in sorted(new, key=lambda r: r.timestamp):
            fraud.evaluate(db, rec)

    def index_chain_once() -> None:
        deployment = chain.deployment
        latest = max(0, chain.ping() - settings.indexer_confirmations)
        cursor_name = f"registered:{deployment['chainId']}:{deployment['address'].lower()}"
        with SessionLocal() as db:
            cursor = db.get(IndexerCursor, cursor_name)
            start = cursor.block_number + 1 if cursor else int(deployment.get("deployBlock", latest))
            if start > latest:
                return
            while start <= latest:
                end = min(start + 999, latest)
                events = chain.get_registered_events(start, end)
                for cr, tx_hash, block_number in events:
                    rec = upsert_record(db, cr)
                    rec.tx_hash, rec.block_number = tx_hash, block_number
                    fraud.evaluate(db, rec)
                if cursor is None:
                    cursor = IndexerCursor(name=cursor_name, block_number=end)
                    db.add(cursor)
                else:
                    cursor.block_number = end
                db.commit()
                start = end + 1

    async def indexer_loop() -> None:
        while True:
            try:
                await asyncio.to_thread(index_chain_once)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Registry event indexer failed; it will retry.")
            await asyncio.sleep(settings.indexer_poll_seconds)

    def authenticated_wallet(request: Request) -> str | None:
        if not settings.wallet_auth_required:
            return None
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise HTTPException(401, "Sign in with your wallet to continue.")
        try:
            claims = jwt.decode(
                header[7:], settings.auth_token_secret, algorithms=["HS256"],
                audience="proofchain", issuer=public_app_url,
            )
            return str(claims["sub"]).lower()
        except (PyJWTError, KeyError, TypeError):
            raise HTTPException(401, "Wallet session expired. Sign in again.")

    def record_dict(rec: Record, db: Session) -> dict:
        asset = db.get(Asset, rec.content_hash)
        return {
            "content_hash": rec.content_hash,
            "short_id": short_id(rec.content_hash),
            "creator": rec.creator,
            "timestamp": rec.timestamp,
            "version": rec.version,
            "revoked": rec.revoked,
            "parent_hash": rec.parent_hash,
            "root_hash": rec.root_hash,
            "metadata_uri": rec.metadata_uri,
            "tx_hash": rec.tx_hash,
            "block_number": rec.block_number,
            "title": (asset.title or asset.filename) if asset else "",
            "kind": (asset.analysis or {}).get("kind") if asset else None,
            "risk": (asset.analysis or {}).get("risk") if asset else None,
        }

    def flag_dict(f: Flag) -> dict:
        return {
            "id": f.id, "content_hash": f.content_hash, "short_id": short_id(f.content_hash),
            "creator": f.creator, "kind": f.kind, "severity": f.severity, "detail": f.detail,
            "related_hash": f.related_hash, "created_at": f.created_at.isoformat(),
        }

    def asset_dict(asset: Asset | None) -> dict | None:
        if asset is None:
            return None
        return {
            "filename": asset.filename, "title": asset.title, "description": asset.description,
            "mime": asset.mime, "size": asset.size, "analyzed_at": asset.created_at.isoformat(),
        }

    def build_report(db: Session, content_hash: str, method: str) -> dict:
        """The public verification report. Reads the record live from the chain."""
        cr = chain.get_record(content_hash)
        asset = db.get(Asset, content_hash)
        analysis = asset.analysis if asset else None

        record = identity = None
        lineage: list[dict] = []
        flags: list[dict] = []
        if cr is not None:
            upsert_record(db, cr)
            index_family(db, cr)
            db.flush()
            rec = db.get(Record, content_hash)
            record = record_dict(rec, db)
            ident = chain.get_identity(cr.creator)
            identity = ident.to_dict() if ident else None
            family = db.scalars(
                select(Record).where(Record.root_hash == cr.root_hash).order_by(Record.version, Record.timestamp)
            ).all()
            lineage = [record_dict(r, db) for r in family]
            flags = [flag_dict(f) for f in db.scalars(select(Flag).where(Flag.content_hash == content_hash))]

        status = "not_found" if cr is None else ("revoked" if cr.revoked else "verified")
        db.add(VerificationEvent(content_hash=content_hash, method=method, result=status))
        db.commit()
        checks = db.scalar(
            select(func.count()).select_from(VerificationEvent).where(VerificationEvent.content_hash == content_hash)
        )

        return {
            "content_hash": content_hash,
            "short_id": short_id(content_hash),
            "status": status,
            "record": record,
            "identity": identity,
            "asset": asset_dict(asset),
            "analysis": analysis,
            "lineage": lineage,
            "flags": flags,
            "trust": compute_trust(record, identity, analysis, flags),
            "verification_count": checks,
            "chain": chain.info(),
            "verify_url": f"{public_app_url}/verify/{content_hash}",
            "disclaimers": DISCLAIMERS,
        }

    # ---------------------------------------------------------------- routes

    @app.get("/api/health")
    def health():
        try:
            block = chain.ping()
            info = chain.info()
            chain_status = {"ok": True, "block": block, **info}
        except ChainUnavailable as exc:
            chain_status = {"ok": False, "error": str(exc)}
        return {
            "status": "ok",
            "chain": chain_status,
            "analysis_engine": "heuristic-forensics-v1" + ("+cnn" if detector.available else ""),
            "detector": getattr(detector, "name", "custom model") if detector.available else None,
            "detector_error": detector.error,
            "text_detector": text_detector.name if text_detector.available else None,
            "text_detector_error": text_detector.error,
            "storage": "ipfs" if settings.ipfs_api_url else "local",
        }

    @app.get("/api/config")
    def config():
        d = chain.deployment
        return {
            "chainId": d["chainId"], "network": d["network"], "address": d["address"],
            "abi": d["abi"], "rpcUrl": settings.rpc_url if d["chainId"] == 31337 else None,
            "walletAuthRequired": settings.wallet_auth_required,
        }

    @app.get("/api/auth/challenge")
    def auth_challenge(address: str):
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            raise HTTPException(400, "Invalid wallet address.")
        lower = address.lower()
        nonce = secrets.token_urlsafe(24)
        now = int(time.time())
        expires = now + 120
        domain = urlparse(public_app_url).netloc
        message = (
            "ProofChain wallet sign-in\n"
            f"Domain: {domain}\n"
            f"URI: {public_app_url}\n"
            f"Address: {lower}\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {datetime.fromtimestamp(now, timezone.utc).isoformat()}\n"
            f"Expiration Time: {datetime.fromtimestamp(expires, timezone.utc).isoformat()}"
        )
        with auth_lock:
            expired = [key for key, (_, exp) in auth_challenges.items() if exp <= now]
            for key in expired:
                auth_challenges.pop(key, None)
            if len(auth_challenges) >= 4096:
                raise HTTPException(503, "Sign-in is temporarily busy. Please retry shortly.")
            auth_challenges[(lower, nonce)] = (message, expires)
        return {"nonce": nonce, "message": message}

    @app.post("/api/auth/verify")
    def auth_verify(body: AuthVerifyBody):
        if not settings.wallet_auth_required:
            raise HTTPException(404, "Wallet sign-in is not enabled.")
        now = int(time.time())
        with auth_lock:
            challenge = auth_challenges.pop((body.address.lower(), body.nonce), None)
        if challenge is None or challenge[1] <= now:
            raise HTTPException(401, "Sign-in challenge expired. Request a new one.")
        try:
            message = challenge[0].encode("utf-8")
            digest = keccak(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message)
            raw_signature = bytes.fromhex(body.signature[2:])
            recovery_id = raw_signature[64]
            if recovery_id >= 27:
                recovery_id -= 27
            if recovery_id not in (0, 1):
                raise ValueError("Invalid signature recovery id")
            signature = keys.Signature(vrs=(
                recovery_id,
                int.from_bytes(raw_signature[:32], "big"),
                int.from_bytes(raw_signature[32:64], "big"),
            ))
            public_key = signature.recover_public_key_from_msg_hash(digest)
            signer = to_checksum_address(keccak(public_key.to_bytes())[-20:])
        except Exception:
            raise HTTPException(401, "Wallet signature could not be verified.")
        if signer.lower() != body.address.lower():
            raise HTTPException(401, "Wallet signature does not match the requested address.")
        expires = datetime.now(timezone.utc) + timedelta(seconds=settings.auth_token_ttl_seconds)
        token = jwt.encode(
            {"sub": signer.lower(), "iss": public_app_url, "aud": "proofchain", "exp": expires},
            settings.auth_token_secret,
            algorithm="HS256",
        )
        return {"access_token": token, "token_type": "bearer", "expires_in": settings.auth_token_ttl_seconds}

    @app.post("/api/analyze")
    async def analyze_file(
        file: UploadFile = File(...),
        title: str = Form("", max_length=200),
        description: str = Form("", max_length=2000),
        db: Session = Depends(get_db),
        wallet: str | None = Depends(authenticated_wallet),
    ):
        """Fingerprint + analyze a file and prepare the metadata to register.
        The file is processed in memory and not stored."""
        data = await read_upload(file)
        content_hash = "0x" + hashlib.sha256(data).hexdigest()
        filename = Path(file.filename or "file").name[:255]
        result = analyze(data, filename, detector, text_detector)

        metadata_uri = storage.put_json({
            "schema": "proofchain/metadata/v1",
            "content_hash": content_hash,
            "title": title or filename,
            "description": description,
            "filename": filename,
            "mime": file.content_type or "",
            "size": len(data),
            "analysis": {k: result.get(k) for k in ("engine", "risk", "ai_risk", "verdict", "declared_generator")},
        })

        asset = db.get(Asset, content_hash)
        if asset is None:
            asset = Asset(content_hash=content_hash)
            db.add(asset)
        cr = chain.get_record(content_hash)
        if cr is None:
            # Until it is registered, the latest uploader's description wins.
            asset.filename, asset.title, asset.description = filename, title, description
            asset.metadata_uri = metadata_uri
        asset.mime, asset.size = file.content_type or "", len(data)
        asset.analysis, asset.phash = result, result.get("phash")
        db.commit()

        return {
            "content_hash": content_hash,
            "short_id": short_id(content_hash),
            "filename": filename,
            "size": len(data),
            "mime": file.content_type or "",
            "analysis": result,
            "metadata_uri": asset.metadata_uri or metadata_uri,
            "already_registered": cr.to_dict() if cr else None,
        }

    @app.post("/api/records/confirm")
    def confirm(body: ConfirmBody, db: Session = Depends(get_db), wallet: str | None = Depends(authenticated_wallet)):
        """Called after the wallet's registration transaction is mined. We do not
        trust the caller: the record is read back from the chain."""
        content_hash = body.content_hash.lower()
        cr = chain.get_record(content_hash)
        if cr is None:
            raise HTTPException(404, "No on-chain record for this fingerprint yet.")
        if wallet and wallet != cr.creator.lower():
            raise HTTPException(403, "Sign in with the wallet that registered this fingerprint.")
        rec = upsert_record(db, cr)
        if body.tx_hash and rec.tx_hash is None:
            block = chain.find_registration_tx(body.tx_hash.lower(), content_hash)
            if block is not None:
                rec.tx_hash, rec.block_number = body.tx_hash.lower(), block
        index_family(db, cr)
        db.flush()
        fraud.evaluate(db, rec)
        db.commit()
        return record_dict(rec, db)

    @app.get("/api/verify/{identifier}")
    def verify(identifier: str, db: Session = Depends(get_db)):
        return build_report(db, resolve_id(db, identifier), "id")

    @app.post("/api/verify/file")
    async def verify_file(
        file: UploadFile = File(...),
        expected: str | None = Form(None),
        db: Session = Depends(get_db),
    ):
        """Hash an uploaded file and check it against the registry. If `expected`
        is given, also report whether the file matches that specific record."""
        data = await read_upload(file)
        content_hash = "0x" + hashlib.sha256(data).hexdigest()
        filename = Path(file.filename or "file").name[:255]

        if not expected:
            ensure_analysis(db, content_hash, data, filename, file.content_type or "")
            report = build_report(db, content_hash, "file")
            report["file_check"] = {
                "filename": filename, "computed_hash": content_hash, "match": report["status"] != "not_found",
                "message": (
                    "This exact file is registered." if report["status"] == "verified"
                    else "This exact file was registered, but the record has been revoked."
                    if report["status"] == "revoked"
                    else "No record exists for this exact file. If it was altered in any way — even "
                         "re-saved or resized — its fingerprint no longer matches the original."
                ),
            }
            return report

        expected_hash = resolve_id(db, expected)
        if expected_hash == content_hash:
            ensure_analysis(db, content_hash, data, filename, file.content_type or "")
            report = build_report(db, content_hash, "file")
            report["file_check"] = {
                "filename": filename, "computed_hash": content_hash, "match": report["status"] != "not_found",
                "message": "The file is byte-for-byte identical to the registered content."
                if report["status"] != "not_found" else "The fingerprints match, but no such record exists on-chain.",
            }
            return report

        report = build_report(db, expected_hash, "id")
        similarity = None
        registered_asset = db.get(Asset, expected_hash)
        if registered_asset and registered_asset.phash:
            uploaded_phash = analyze(data, filename, None).get("phash")
            if uploaded_phash:
                similarity = 64 - hamming(uploaded_phash, registered_asset.phash)
        message = "This file does NOT match the registered record: its fingerprint is different."
        if similarity is not None and similarity >= 58:
            message += " It looks visually near-identical, so it is probably a modified or re-encoded copy."
        elif chain.get_record(content_hash) is not None:
            message += " However, this file has its own separate registration."
        report["file_check"] = {
            "filename": filename, "computed_hash": content_hash, "match": False,
            "visual_similarity": similarity, "message": message,
        }
        db.add(VerificationEvent(content_hash=expected_hash, method="file", result="mismatch"))
        db.commit()
        return report

    @app.get("/api/verify/{identifier}/qr.png")
    def qr(identifier: str, db: Session = Depends(get_db)):
        content_hash = resolve_id(db, identifier)
        img = qrcode.make(f"{public_app_url}/verify/{content_hash}", box_size=8, border=2)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return Response(buf.getvalue(), media_type="image/png", headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/api/records")
    def list_records(creator: str | None = None, limit: int = 50, db: Session = Depends(get_db)):
        q = select(Record).order_by(Record.timestamp.desc()).limit(max(1, min(limit, 200)))
        if creator:
            q = q.where(func.lower(Record.creator) == creator.lower())
        return [record_dict(r, db) for r in db.scalars(q)]

    @app.get("/api/flags")
    def list_flags(limit: int = 100, db: Session = Depends(get_db)):
        q = select(Flag).order_by(Flag.created_at.desc(), Flag.id.desc()).limit(max(1, min(limit, 500)))
        return [flag_dict(f) for f in db.scalars(q)]

    @app.get("/api/creators/{address}")
    def creator(address: str, db: Session = Depends(get_db)):
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            raise HTTPException(400, "Invalid address.")
        ident = chain.get_identity(address)
        records = db.scalars(
            select(Record).where(func.lower(Record.creator) == address.lower()).order_by(Record.timestamp.desc())
        ).all()
        flags = db.scalars(select(Flag).where(func.lower(Flag.creator) == address.lower())).all()
        return {
            "address": address,
            "identity": ident.to_dict() if ident else None,
            "records": [record_dict(r, db) for r in records],
            "flags": [flag_dict(f) for f in flags],
        }

    @app.get("/api/stats")
    def stats(db: Session = Depends(get_db)):
        count = lambda model, *where: db.scalar(select(func.count()).select_from(model).where(*where))  # noqa: E731
        return {
            "records": count(Record),
            "revoked": count(Record, Record.revoked.is_(True)),
            "creators": db.scalar(select(func.count(func.distinct(Record.creator)))),
            "analyzed": count(Asset),
            "verifications": count(VerificationEvent),
            "mismatches": count(VerificationEvent, VerificationEvent.result == "mismatch"),
            "flags": count(Flag),
            "flags_serious": count(Flag, Flag.severity.in_(["medium", "high"])),
        }

    @app.get("/api/metadata/{digest}")
    def metadata(digest: str, db: Session = Depends(get_db)):
        normalized = digest.lower()
        doc = storage.get_json(normalized)
        if doc is not None:
            return doc
        # Local object files may be ephemeral on container hosts. The indexed
        # asset row is durable, so reconstruct this public metadata document.
        asset = db.scalar(select(Asset).where(Asset.metadata_uri == f"sha256://{normalized}"))
        if asset is None:
            raise HTTPException(404, "Metadata not found.")
        return {
            "schema": "proofchain/metadata/v1",
            "content_hash": asset.content_hash,
            "title": asset.title or asset.filename,
            "description": asset.description,
            "filename": asset.filename,
            "mime": asset.mime,
            "size": asset.size,
            "analysis": {
                key: (asset.analysis or {}).get(key)
                for key in ("engine", "risk", "ai_risk", "verdict", "declared_generator")
            },
        }

    return app
