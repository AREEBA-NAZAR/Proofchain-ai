"""Read-only client for the ProvenanceRegistry contract.

The backend never holds a private key: registrations are signed and sent by the
creator's own wallet in the browser. Here we only read state over JSON-RPC.
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx
from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address

ZERO_HASH = "0x" + "00" * 32
REGISTERED_TOPIC = "0x" + keccak(
    text="Registered(bytes32,address,bytes32,bytes32,uint32,uint64,string)"
).hex()


class ChainUnavailable(Exception):
    """The RPC node is unreachable or the contract is not deployed."""


@dataclass
class ChainRecord:
    content_hash: str
    creator: str
    timestamp: int
    version: int
    revoked: bool
    parent_hash: str | None
    root_hash: str
    metadata_uri: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ChainIdentity:
    name: str
    metadata_uri: str
    verified: bool
    registered_at: int

    def to_dict(self) -> dict:
        return asdict(self)


def _selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def _b32(hex_hash: str) -> bytes:
    return bytes.fromhex(hex_hash[2:])


class ChainClient:
    def __init__(self, rpc_url: str, deployment_file: str, timeout: float = 10.0):
        self.rpc_url = rpc_url
        self.deployment_file = Path(deployment_file)
        self._http = httpx.Client(timeout=timeout)
        self._deployment: dict | None = None
        self._deployment_mtime: float | None = None

    # ------------------------------------------------------------ deployment

    @property
    def deployment(self) -> dict:
        """Deployment info, reloaded when the file changes (e.g. after a redeploy)."""
        try:
            mtime = self.deployment_file.stat().st_mtime
        except OSError as exc:
            raise ChainUnavailable(
                f"No deployment file at {self.deployment_file}. Deploy the contract first."
            ) from exc
        if self._deployment is None or mtime != self._deployment_mtime:
            self._deployment = json.loads(self.deployment_file.read_text())
            self._deployment_mtime = mtime
        return self._deployment

    @property
    def address(self) -> str:
        return self.deployment["address"]

    def info(self) -> dict:
        d = self.deployment
        return {"network": d["network"], "chainId": d["chainId"], "contract": d["address"]}

    # ------------------------------------------------------------------- rpc

    def _rpc(self, method: str, params: list):
        try:
            resp = self._http.post(
                self.rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            )
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ChainUnavailable(f"Cannot reach the blockchain node at {self.rpc_url}.") from exc
        if "error" in body:
            raise ChainUnavailable(f"RPC error from node: {body['error'].get('message', body['error'])}")
        return body["result"]

    def _call(self, signature: str, arg_types: list[str], args: list, out_types: list[str]):
        data = _hex(_selector(signature) + encode(arg_types, args))
        result = self._rpc("eth_call", [{"to": self.address, "data": data}, "latest"])
        raw = bytes.fromhex(result[2:])
        if not raw:
            raise ChainUnavailable(
                f"No contract found at {self.address}. Was the chain restarted? Redeploy the contract."
            )
        return decode(out_types, raw)

    # ----------------------------------------------------------------- reads

    def ping(self) -> int:
        return int(self._rpc("eth_blockNumber", []), 16)

    def get_record(self, content_hash: str) -> ChainRecord | None:
        key = _b32(content_hash)
        (registered,) = self._call("isRegistered(bytes32)", ["bytes32"], [key], ["bool"])
        if not registered:
            return None
        ((creator, ts, version, revoked, parent, root, uri),) = self._call(
            "getRecord(bytes32)",
            ["bytes32"],
            [key],
            ["(address,uint64,uint32,bool,bytes32,bytes32,string)"],
        )
        parent_hex = _hex(parent)
        return ChainRecord(
            content_hash=content_hash,
            creator=to_checksum_address(creator),
            timestamp=ts,
            version=version,
            revoked=revoked,
            parent_hash=None if parent_hex == ZERO_HASH else parent_hex,
            root_hash=_hex(root),
            metadata_uri=uri,
        )

    def get_children(self, content_hash: str) -> list[str]:
        (children,) = self._call(
            "getChildren(bytes32)", ["bytes32"], [_b32(content_hash)], ["bytes32[]"]
        )
        return [_hex(c) for c in children]

    def get_identity(self, address: str) -> ChainIdentity | None:
        name, uri, verified, registered_at = self._call(
            "identities(address)", ["address"], [address], ["string", "string", "bool", "uint64"]
        )
        if registered_at == 0:
            return None
        return ChainIdentity(name=name, metadata_uri=uri, verified=verified, registered_at=registered_at)

    def find_registration_tx(self, tx_hash: str, content_hash: str) -> int | None:
        """Return the block number if `tx_hash` really is the transaction that
        registered `content_hash` on our contract, else None."""
        receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
        if not receipt or receipt.get("status") != "0x1":
            return None
        for log in receipt.get("logs", []):
            topics = log.get("topics", [])
            if (
                log.get("address", "").lower() == self.address.lower()
                and len(topics) > 1
                and topics[0].lower() == REGISTERED_TOPIC
                and topics[1].lower() == content_hash.lower()
            ):
                return int(receipt["blockNumber"], 16)
        return None
