from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.discovery.models import Base


class AssetRow(Base):
    __tablename__ = "assets"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    scope_id: Mapped[str] = mapped_column(ForeignKey("discovery_scopes.id"))
    name: Mapped[str] = mapped_column(String(120))
    asset_kind: Mapped[str] = mapped_column(String(32))
    owner: Mapped[str | None] = mapped_column(String(120))
    notes: Mapped[str] = mapped_column(String(2000))
    revision: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    registration_source: Mapped[str] = mapped_column(String(16), default="manual", server_default="manual")
    identity_status: Mapped[str] = mapped_column(String(24), default="manual_confirmed",
                                                server_default="manual_confirmed")
    __table_args__ = (CheckConstraint("revision >= 1"),)


class AssetLinkRow(Base):
    __tablename__ = "asset_discovery_links"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    discovery_host_id: Mapped[str] = mapped_column(ForeignKey("discovery_hosts.id"), unique=True)
    confirmed_at: Mapped[str] = mapped_column(String(40))
    reason: Mapped[str] = mapped_column(String(500))
    actor: Mapped[str] = mapped_column(String(32))
    __table_args__ = (Index("ix_asset_links_asset_sequence", "asset_id", "sequence"),)


class AssetAuditRow(Base):
    __tablename__ = "asset_audit_events"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    discovery_host_id: Mapped[str | None] = mapped_column(ForeignKey("discovery_hosts.id"))
    action: Mapped[str] = mapped_column(String(24))
    reason: Mapped[str] = mapped_column(String(500))
    actor: Mapped[str] = mapped_column(String(32))
    asset_revision: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[str] = mapped_column(String(40))
    details: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (
        CheckConstraint("action IN ('registered','linked','unlinked','updated')"),
        Index("ix_asset_audit_asset_sequence", "asset_id", "sequence"),
    )


class AssetDecisionRow(Base):
    """One durable decision per discovery; retries never undo a human unlink."""
    __tablename__ = "asset_identity_decisions"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    discovery_host_id: Mapped[str] = mapped_column(ForeignKey("discovery_hosts.id"), unique=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    outcome: Mapped[str] = mapped_column(String(24))
    rule: Mapped[str] = mapped_column(String(64))
    evidence: Mapped[dict] = mapped_column(JSON)
    decided_at: Mapped[str] = mapped_column(String(40))
