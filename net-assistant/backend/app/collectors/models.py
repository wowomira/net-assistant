from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.discovery.models import Base


class NetworkDeviceRow(Base):
    __tablename__ = "network_devices"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    label: Mapped[str] = mapped_column(String(120))
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    source: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[str] = mapped_column(String(40))


class NetworkRunRow(Base):
    __tablename__ = "network_collection_runs"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("network_devices.id"))
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id"))
    state: Mapped[str] = mapped_column(String(20))
    started_at: Mapped[str] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40))
    observed_at: Mapped[str | None] = mapped_column(String(40))
    error_code: Mapped[str | None] = mapped_column(String(80))
    snapshot: Mapped[dict | None] = mapped_column(JSON(none_as_null=True))
    __table_args__ = (
        CheckConstraint("state IN ('running','completed','failed','interrupted')"),
        CheckConstraint("(state = 'completed' AND snapshot IS NOT NULL AND observed_at IS NOT NULL) "
                        "OR (state != 'completed' AND snapshot IS NULL AND observed_at IS NULL)"),
        Index("ix_network_runs_device_sequence", "device_id", "sequence"),
    )
