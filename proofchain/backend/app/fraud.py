"""Rule-based detection of suspicious registration patterns.

Flags are leads for a human investigator, not verdicts.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from .analysis import hamming
from .models import Asset, Flag, Record

BURST_WINDOW_S = 600
BURST_THRESHOLD = 10
NEAR_DUPLICATE_BITS = 6
AI_RISK_THRESHOLD = 0.6


def _add_flag(db: Session, record: Record, kind: str, severity: str, detail: str, related: str | None = None) -> None:
    exists = db.scalar(select(Flag).where(Flag.content_hash == record.content_hash, Flag.kind == kind))
    if exists is None:
        db.add(Flag(content_hash=record.content_hash, creator=record.creator, kind=kind,
                    severity=severity, detail=detail, related_hash=related))


def evaluate(db: Session, record: Record) -> None:
    """Run all rules for a newly indexed record. Idempotent."""
    # 1. Burst: many registrations from one wallet in a short window.
    recent = db.scalars(
        select(Record.content_hash).where(
            Record.creator == record.creator,
            Record.timestamp > record.timestamp - BURST_WINDOW_S,
            Record.timestamp <= record.timestamp,
        )
    ).all()
    if len(recent) >= BURST_THRESHOLD:
        _add_flag(db, record, "burst_registration", "medium",
                  f"{len(recent)} registrations from this wallet within {BURST_WINDOW_S // 60} minutes.")

    asset = db.get(Asset, record.content_hash)
    if asset is None:
        return

    # 2. Near-duplicate of content registered earlier by a different wallet.
    if asset.phash:
        earlier = db.execute(
            select(Asset.content_hash, Asset.phash, Record.creator)
            .join(Record, Record.content_hash == Asset.content_hash)
            .where(
                Asset.phash.is_not(None),
                Asset.content_hash != record.content_hash,
                Record.creator != record.creator,
                Record.timestamp <= record.timestamp,
            )
        ).all()
        for other_hash, other_phash, other_creator in earlier:
            distance = hamming(asset.phash, other_phash)
            if distance <= NEAR_DUPLICATE_BITS:
                _add_flag(
                    db, record, "near_duplicate", "high",
                    f"Visually near-identical (distance {distance}/64) to content registered earlier by "
                    f"{other_creator}. Possibly a re-registered or altered copy.",
                    related=other_hash,
                )
                break

    # 3. Registered content failed a file-safety check.
    safety = (asset.analysis or {}).get("safety") or {}
    if safety.get("level") == "danger":
        labels = ", ".join(f["label"].lower() for f in safety.get("findings", []) if f["severity"] == "danger")
        _add_flag(db, record, "unsafe_content", "medium", f"Registered file has safety findings: {labels}.")

    # 4. Content with elevated AI risk was registered (informational).
    risk = (asset.analysis or {}).get("ai_risk", (asset.analysis or {}).get("risk"))
    if risk is not None and risk >= AI_RISK_THRESHOLD:
        generator = (asset.analysis or {}).get("declared_generator")
        _add_flag(db, record, "ai_risk", "info",
                  f"Registered content has elevated AI/manipulation risk ({risk:.0%})"
                  + (f"; metadata declares {generator}." if generator else "."))
