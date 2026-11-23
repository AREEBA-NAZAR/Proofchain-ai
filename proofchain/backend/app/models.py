from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Asset(Base):
    """A file someone analyzed. Keyed by its SHA-256; the file itself is not kept."""

    __tablename__ = "assets"

    content_hash: Mapped[str] = mapped_column(String(66), primary_key=True)  # 0x + sha256
    filename: Mapped[str] = mapped_column(String(255), default="")
    title: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    mime: Mapped[str] = mapped_column(String(100), default="")
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    phash: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    metadata_uri: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Record(Base):
    """Index of on-chain records. The chain is the source of truth; this is a cache
    that makes listing, lineage and fraud queries cheap."""

    __tablename__ = "records"

    content_hash: Mapped[str] = mapped_column(String(66), primary_key=True)
    creator: Mapped[str] = mapped_column(String(42), index=True)
    timestamp: Mapped[int] = mapped_column(BigInteger, index=True)
    version: Mapped[int] = mapped_column(Integer)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    root_hash: Mapped[str] = mapped_column(String(66), index=True)
    metadata_uri: Mapped[str] = mapped_column(String(500), default="")
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    indexed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Flag(Base):
    __tablename__ = "flags"
    __table_args__ = (UniqueConstraint("content_hash", "kind", name="uq_flag_hash_kind"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    content_hash: Mapped[str] = mapped_column(String(66), index=True)
    creator: Mapped[str] = mapped_column(String(42), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10))  # info | medium | high
    detail: Mapped[str] = mapped_column(Text, default="")
    related_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VerificationEvent(Base):
    __tablename__ = "verification_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    content_hash: Mapped[str] = mapped_column(String(66), index=True)
    method: Mapped[str] = mapped_column(String(10))  # id | file
    result: Mapped[str] = mapped_column(String(20))  # verified | revoked | not_found | mismatch
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IndexerCursor(Base):
    """Last finalized block scanned by the registry event indexer."""

    __tablename__ = "indexer_cursors"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    block_number: Mapped[int] = mapped_column(BigInteger)
