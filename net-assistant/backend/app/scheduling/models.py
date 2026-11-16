from sqlalchemy import CheckConstraint, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.discovery.models import Base


class ScheduledRunRow(Base):
    __tablename__ = "scheduled_scan_runs"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True)
    schedule_name: Mapped[str] = mapped_column(String(120))
    local_date: Mapped[str] = mapped_column(String(10))
    state: Mapped[str] = mapped_column(String(24))
    started_at: Mapped[str] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40))
    error_code: Mapped[str | None] = mapped_column(String(80))
    config_snapshot: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (
        UniqueConstraint("schedule_name", "local_date"),
        CheckConstraint("state IN ('running','completed','partial','failed','interrupted')"),
    )
