"""API tests against an in-memory fake of the registry contract."""

import io
import time
import zipfile

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image, PngImagePlugin

from app.chain import ChainIdentity, ChainRecord, ChainUnavailable
from app.config import Settings
from app.main import create_app

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BOB = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"


class FakeChain:
    def __init__(self):
        self.records: dict[str, ChainRecord] = {}
        self.identities: dict[str, ChainIdentity] = {}
        self.down = False
        self.clock = int(time.time())

    def _check(self):
        if self.down:
            raise ChainUnavailable("node down")

    def register(self, content_hash, creator, parent=None, uri=""):
        p = self.records.get(parent) if parent else None
        self.clock += 1
        self.records[content_hash] = ChainRecord(
            content_hash=content_hash, creator=creator, timestamp=self.clock,
            version=p.version + 1 if p else 1, revoked=False, parent_hash=parent,
            root_hash=p.root_hash if p else content_hash, metadata_uri=uri,
        )

    def info(self):
        return {"network": "fake", "chainId": 31337, "contract": "0x" + "11" * 20}

    @property
    def deployment(self):
        return {"network": "fake", "chainId": 31337, "address": "0x" + "11" * 20, "abi": []}

    def ping(self):
        self._check()
        return 1

    def get_record(self, content_hash):
        self._check()
        return self.records.get(content_hash)

    def get_children(self, content_hash):
        self._check()
        return [h for h, r in self.records.items() if r.parent_hash == content_hash]

    def get_identity(self, address):
        self._check()
        return self.identities.get(address)

    def find_registration_tx(self, tx_hash, content_hash):
        return 7 if content_hash in self.records else None


def png(seed: int, size=(256, 256), text: dict | None = None) -> bytes:
    rng = np.random.default_rng(seed)
    base = np.linspace(0, 255, size[0] * size[1]).reshape(size[1], size[0])
    arr = np.clip(base[..., None] + rng.normal(0, 12, (size[1], size[0], 3)), 0, 255).astype(np.uint8)
    info = PngImagePlugin.PngInfo()
    for k, v in (text or {}).items():
        info.add_text(k, v)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "PNG", pnginfo=info)
    return buf.getvalue()


@pytest.fixture
def env(tmp_path):
    chain = FakeChain()
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 't.db').as_posix()}",
        storage_dir=str(tmp_path / "objects"),
        detector_weights=str(tmp_path / "none.pt"),
        detector_onnx=str(tmp_path / "none.onnx"),
        text_detector_dir=str(tmp_path / "none-text"),
        max_upload_mb=1,
    )
    return TestClient(create_app(settings, chain=chain)), chain


def upload(client, data, name="photo.png", **form):
    return client.post("/api/analyze", files={"file": (name, data, "image/png")}, data=form)


def test_analyze_returns_fingerprint_and_signals(env):
    client, _ = env
    r = upload(client, png(1), title="Sunset")
    assert r.status_code == 200
    body = r.json()
    assert body["content_hash"].startswith("0x") and len(body["content_hash"]) == 66
    assert body["short_id"].startswith("PC-")
    assert body["already_registered"] is None
    a = body["analysis"]
    assert a["kind"] == "image" and a["analyzed"] and 0 <= a["risk"] <= 1
    assert {s["id"] for s in a["signals"]} >= {"metadata", "ela", "spectrum", "noise"}
    digest = body["metadata_uri"].removeprefix("sha256://")
    assert client.get(f"/api/metadata/{digest}").json()["title"] == "Sunset"


def test_declared_ai_generator_is_flagged_as_high_risk(env):
    client, _ = env
    a = upload(client, png(2, text={"parameters": "a cat, Steps: 20, Model: Stable Diffusion XL"})).json()["analysis"]
    assert a["declared_generator"] == "Stable Diffusion"
    assert a["risk"] >= 0.95 and a["verdict"] == "elevated"


def test_every_file_type_is_analyzed_and_safety_checked(env):
    client, chain = env

    def run(name, data):
        return client.post("/api/analyze", files={"file": (name, data)}).json()["analysis"]

    # Plain data: nothing to score, nothing unsafe.
    a = run("data.csv", b"a,b\n1,2\n")
    assert a["kind"] == "text" and a["risk"] is None and a["safety"]["level"] == "none"

    # PDF: structural facts are reported; JavaScript that runs on open is dangerous.
    a = run("c.pdf", b"%PDF-1.7\n/CreationDate (D:20240101)\n%%EOF\nmore\n%%EOF\n")
    assert a["kind"] == "pdf" and a["safety"]["level"] == "none"
    assert any("2 saved revision" in s["detail"] for s in a["signals"])
    a = run("f.pdf", b"%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (x) >> >>\n%%EOF")
    assert a["safety"]["level"] == "danger" and a["risk"] == 0.9 and a["ai_risk"] is None

    # A program named like a document.
    a = run("invoice.pdf", b"MZ" + b"\x90" * 100)
    ids = {f["id"] for f in a["safety"]["findings"]}
    assert a["kind"] == "executable" and {"executable", "type_mismatch"} <= ids
    assert "double_extension" in {f["id"] for f in run("photo.jpg.exe", b"MZ" + b"\x90" * 100)["safety"]["findings"]}

    # Office document with macros; archive hiding a program.
    def zipped(files):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, body in files.items():
                zf.writestr(name, body)
        return buf.getvalue()

    macro_doc = zipped({"word/document.xml": "<w:p><w:t>Hello</w:t></w:p>", "word/vbaProject.bin": b"\0"})
    a = run("invoice.docm", macro_doc)
    assert a["kind"] == "office" and [f["id"] for f in a["safety"]["findings"]] == ["macros"]
    a = run("bundle.zip", zipped({"readme.txt": "hi", "setup.exe": b"MZ"}))
    assert a["kind"] == "archive" and a["safety"]["level"] == "danger"

    # HTML asking for a password is a caution, not a danger.
    a = run("login.html", b"<html><form><input type=\"password\"></form></html>")
    assert a["safety"]["level"] == "caution" and a["risk"] == 0.5

    # Unknown binary: fingerprint only.
    a = run("blob.dat", bytes(range(256)) * 4)
    assert a["kind"] == "other" and a["risk"] is None

    # Registering an unsafe file raises a flag and costs trust.
    h = client.post("/api/analyze", files={"file": ("invoice.docm", macro_doc)}).json()["content_hash"]
    chain.register(h, ALICE)
    client.post("/api/records/confirm", json={"content_hash": h})
    report = client.get(f"/api/verify/{h}").json()
    assert [f["kind"] for f in report["flags"]] == ["unsafe_content"]
    assert next(c for c in report["trust"]["components"] if c["id"] == "ai")["points"] == 3


def test_upload_limits(env):
    client, _ = env
    assert upload(client, b"").status_code == 400
    assert upload(client, b"x" * (1024 * 1024 + 1)).status_code == 413


def test_api_and_upload_rate_limits(tmp_path):
    chain = FakeChain()
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'limited.db').as_posix()}",
        storage_dir=str(tmp_path / "objects"),
        detector_weights=str(tmp_path / "none.pt"),
        detector_onnx=str(tmp_path / "none.onnx"),
        text_detector_dir=str(tmp_path / "none-text"),
        api_rate_limit_per_minute=2,
        upload_rate_limit_per_minute=1,
    )
    with TestClient(create_app(settings, chain=chain)) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/health").status_code == 200
        limited = client.get("/api/health")
        assert limited.status_code == 429 and "Retry-After" in limited.headers

        assert upload(client, png(12)).status_code == 200
        limited_upload = upload(client, png(13))
        assert limited_upload.status_code == 429 and "Retry-After" in limited_upload.headers


def test_unregistered_content_is_not_found(env):
    client, _ = env
    h = upload(client, png(3)).json()["content_hash"]
    report = client.get(f"/api/verify/{h}").json()
    assert report["status"] == "not_found"
    assert report["trust"]["band"] == "unregistered"
    assert report["record"] is None and report["disclaimers"]


def test_register_confirm_verify_flow(env):
    client, chain = env
    data = png(4)
    h = upload(client, data, title="Original").json()["content_hash"]

    assert client.post("/api/records/confirm", json={"content_hash": h}).status_code == 404

    chain.register(h, ALICE)
    rec = client.post("/api/records/confirm", json={"content_hash": h, "tx_hash": "0x" + "ab" * 32}).json()
    assert rec["creator"] == ALICE and rec["block_number"] == 7 and rec["title"] == "Original"

    for ident in (h, h[2:], h.upper().replace("0X", "0x"), rec["short_id"], rec["short_id"].lower()):
        report = client.get(f"/api/verify/{ident}").json()
        assert report["status"] == "verified", ident
    assert report["verification_count"] == 5
    assert report["trust"]["band"] in ("moderate", "high")
    assert sum(c["points"] for c in report["trust"]["components"]) == report["trust"]["score"]

    # Same bytes verify; a single changed byte does not.
    ok = client.post("/api/verify/file", files={"file": ("a.png", data)}, data={"expected": h}).json()
    assert ok["file_check"]["match"] is True
    bad = client.post("/api/verify/file", files={"file": ("a.png", data + b"\0")}, data={"expected": h}).json()
    assert bad["file_check"]["match"] is False and "NOT match" in bad["file_check"]["message"]
    assert bad["file_check"]["visual_similarity"] == 64
    lone = client.post("/api/verify/file", files={"file": ("a.png", data + b"\0")}).json()
    assert lone["status"] == "not_found" and lone["file_check"]["match"] is False
    # Checking an unknown file still analyzes it, so the AI component is real, not neutral.
    assert lone["analysis"]["analyzed"] and lone["analysis"]["risk"] is not None
    ai = next(c for c in lone["trust"]["components"] if c["id"] == "ai")
    assert ai["points"] == round(30 * (1 - lone["analysis"]["risk"]))

    assert client.get("/api/stats").json()["mismatches"] == 1
    qr = client.get(f"/api/verify/{rec['short_id']}/qr.png")
    assert qr.status_code == 200 and qr.content.startswith(b"\x89PNG")


def test_identity_raises_trust_and_revocation_caps_it(env):
    client, chain = env
    h = upload(client, png(5)).json()["content_hash"]
    chain.register(h, ALICE)
    client.post("/api/records/confirm", json={"content_hash": h})
    anon = client.get(f"/api/verify/{h}").json()["trust"]["score"]

    chain.identities[ALICE] = ChainIdentity("Alice Press", "", True, 1)
    verified = client.get(f"/api/verify/{h}").json()
    assert verified["identity"]["verified"] and verified["trust"]["score"] == anon + 17

    chain.records[h].revoked = True
    revoked = client.get(f"/api/verify/{h}").json()
    assert revoked["status"] == "revoked" and revoked["trust"]["score"] <= 35
    assert revoked["trust"]["band"] == "low"


def test_lineage_is_indexed_from_chain_even_if_never_confirmed(env):
    client, chain = env
    v1, v2, v3 = ("0x" + c * 64 for c in "abc")
    chain.register(v1, ALICE)
    chain.register(v2, ALICE, parent=v1)
    chain.register(v3, ALICE, parent=v2)

    report = client.get(f"/api/verify/{v2}").json()
    assert [r["content_hash"] for r in report["lineage"]] == [v1, v2, v3]
    assert [r["version"] for r in report["lineage"]] == [1, 2, 3]
    assert len(client.get("/api/records", params={"creator": ALICE.lower()}).json()) == 3
    assert len(client.get(f"/api/creators/{ALICE}").json()["records"]) == 3


def test_near_duplicate_from_another_wallet_is_flagged(env):
    client, chain = env
    original = png(6)
    img = Image.open(io.BytesIO(original))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=85)  # re-encoded copy: new hash, same picture
    copy = buf.getvalue()

    h1 = upload(client, original).json()["content_hash"]
    chain.register(h1, ALICE)
    client.post("/api/records/confirm", json={"content_hash": h1})

    h2 = upload(client, copy, name="copy.jpg").json()["content_hash"]
    assert h1 != h2
    chain.register(h2, BOB)
    client.post("/api/records/confirm", json={"content_hash": h2})
    client.post("/api/records/confirm", json={"content_hash": h2})  # idempotent

    flags = client.get("/api/flags").json()
    assert [(f["kind"], f["severity"], f["related_hash"]) for f in flags] == [("near_duplicate", "high", h1)]
    report = client.get(f"/api/verify/{h2}").json()
    pattern = next(c for c in report["trust"]["components"] if c["id"] == "pattern")
    assert pattern["points"] == 0
    assert client.get(f"/api/verify/{h1}").json()["flags"] == []


def test_burst_registration_is_flagged(env):
    client, chain = env
    hashes = [f"0x{i:064x}" for i in range(1, 11)]
    for h in hashes:
        chain.register(h, BOB)
        client.post("/api/records/confirm", json={"content_hash": h})
    flags = client.get("/api/flags").json()
    assert [f["kind"] for f in flags] == ["burst_registration"]
    assert flags[0]["content_hash"] == hashes[-1]


def test_bad_ids_and_chain_outage(env):
    client, chain = env
    assert client.get("/api/verify/not-an-id").status_code == 400
    assert client.get("/api/verify/PC-000000000000").status_code == 404
    assert client.get("/api/metadata/zz").status_code == 404
    chain.down = True
    assert client.get("/api/verify/0x" + "a" * 64).status_code == 503
    assert client.get("/api/health").json()["chain"]["ok"] is False
