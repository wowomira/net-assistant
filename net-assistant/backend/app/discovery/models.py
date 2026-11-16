from sqlalchemy import CheckConstraint, Float, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ScopeRow(Base):
    __tablename__ = "discovery_scopes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    revision: Mapped[int] = mapped_column(Integer)
    config_hash: Mapped[str] = mapped_column(String(64))
    config: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[str] = mapped_column(String(40))


class JobRow(Base):
    __tablename__ = "discovery_jobs"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    scope_id: Mapped[str] = mapped_column(ForeignKey("discovery_scopes.id"))
    scope_revision: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(20))
    started_at: Mapped[str] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40))
    config_snapshot: Mapped[dict] = mapped_column(JSON)
    coverage: Mapped[dict] = mapped_column(JSON)
    error_code: Mapped[str | None] = mapped_column(String(80))
    trigger: Mapped[str] = mapped_column(String(16), default="manual", server_default="manual")
    schedule_run_id: Mapped[str | None] = mapped_column(ForeignKey("scheduled_scan_runs.id"))
    __table_args__ = (
        CheckConstraint("state IN ('running','completed','partial','failed','interrupted')"),
    )


class HostRow(Base):
    __tablename__ = "discovery_hosts"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("discovery_jobs.id"))
    # Retain the historical SQLite declaration; SQLite does not enforce VARCHAR
    # length. IPv6 persistence is integration-tested without migrating work DBs.
    address: Mapped[str] = mapped_column(String(15))
    mac: Mapped[str | None] = mapped_column(String(32))
    discovery_methods: Mapped[list] = mapped_column(JSON)
    context: Mapped[dict] = mapped_column(JSON)
    confidence: Mapped[str] = mapped_column(String(40))
    management_status: Mapped[str] = mapped_column(String(24), default="discovered")
    collection_access: Mapped[str] = mapped_column(String(24), default="not_enrolled")
    asset_kind: Mapped[str] = mapped_column(String(32), default="unknown")
    observed_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (UniqueConstraint("job_id", "address"),)


class ProbeRow(Base):
    __tablename__ = "discovery_probes"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("discovery_jobs.id"))
    address: Mapped[str] = mapped_column(String(15))
    phase: Mapped[str] = mapped_column(String(20))
    method: Mapped[str] = mapped_column(String(20))
    port: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(40))
    duration_ms: Mapped[float] = mapped_column(Float)
    reason_code: Mapped[str | None] = mapped_column(String(80))
    evidence: Mapped[dict] = mapped_column(JSON)
    observed_at: Mapped[str] = mapped_column(String(40))
    __table_args__ = (
        CheckConstraint("port IS NULL OR (port >= 1 AND port <= 65535)"),
        CheckConstraint("duration_ms >= 0"),
        Index("ix_discovery_probes_job_address", "job_id", "address", "sequence"),
    )
