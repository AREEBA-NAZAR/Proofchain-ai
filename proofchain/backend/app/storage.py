"""Content-addressed storage for provenance metadata.

Local disk by default; IPFS (Kubo HTTP API) when `ipfs_api_url` is configured.
Only small metadata documents are stored — never the user's file.
"""

import hashlib
import json
import re
from pathlib import Path

import httpx

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class Storage:
    def __init__(self, storage_dir: str, ipfs_api_url: str | None = None):
        self.dir = Path(storage_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ipfs_api_url = ipfs_api_url.rstrip("/") if ipfs_api_url else None

    def put_json(self, doc: dict) -> str:
        """Store a JSON document and return its URI (ipfs://<cid> or sha256://<digest>)."""
        payload = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(payload).hexdigest()
        (self.dir / digest).write_bytes(payload)  # always keep a local copy
        if self.ipfs_api_url:
            try:
                resp = httpx.post(
                    f"{self.ipfs_api_url}/api/v0/add",
                    params={"pin": "true", "cid-version": "1"},
                    files={"file": ("metadata.json", payload, "application/json")},
                    timeout=20,
                )
                resp.raise_for_status()
                return f"ipfs://{resp.json()['Hash']}"
            except (httpx.HTTPError, KeyError, ValueError):
                pass  # fall back to the local content address
        return f"sha256://{digest}"

    def get_json(self, digest: str) -> dict | None:
        if not _DIGEST.match(digest):
            return None
        path = self.dir / digest
        if not path.is_file():
            return None
        return json.loads(path.read_bytes())
