from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from app.discovery.models import Base


class SwitchDeviceRow(Base):
    __tablename__ = "switch_devices"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    scope_key: Mapped[str] = mapped_column(String(64))
    address: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(512))
    object_id: Mapped[str] = mapped_column(String(512))
    first_seen_at: Mapped[str] = mapped_column(String(40))
    last_seen_at: Mapped[str] = mapped_column(String(40))


class SwitchRunRow(Base):
    __tablename__ = "switch_collection_runs"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("switch_devices.id"))
    scope_key: Mapped[str] = mapped_column(String(64))
    address: Mapped[str] = mapped_column(String(128))
    profile_id: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(20))
    started_at: Mapped[str] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40))
    error_code: Mapped[str | None] = mapped_column(String(80))
    snapshot: Mapped[dict | None] = mapped_column(JSON(none_as_null=True))
    __table_args__ = (
        CheckConstraint("state IN ('running','completed','partial','failed','ignored','interrupted')"),
        CheckConstraint("(state IN ('completed','partial') AND snapshot IS NOT NULL AND device_id IS NOT NULL) "
                        "OR (state NOT IN ('completed','partial') AND snapshot IS NULL)"),
        Index("ix_switch_runs_device_sequence", "device_id", "sequence"),
    )
