"""Explicit fixed UTC offset: China uses +480 minutes, independent of host locale."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DailyPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)
    name: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")
    enabled: bool = True
    at: str = Field(default="09:00", pattern=r"^\d{2}:\d{2}$")
    utc_offset_minutes: int = Field(default=480, ge=-720, le=840, strict=True)
    scan_config: Path
    database: Path
    report_directory: Path

    @field_validator("at")
    @classmethod
    def valid_time(cls, value):
        datetime.strptime(value, "%H:%M")
        return value

    @field_validator("scan_config", "database", "report_directory")
    @classmethod
    def absolute(cls, value):
        if not value.is_absolute():
            raise ValueError("Paths in a loaded daily plan must be absolute.")
        return value.resolve()

    def local_now(self, now=None):
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("The schedule clock must be timezone-aware.")
        return now.astimezone(timezone(timedelta(minutes=self.utc_offset_minutes)))

    def is_due(self, now=None):
        local = self.local_now(now)
        return self.enabled and local.strftime("%H:%M") >= self.at


def load_plan(path):
    path = Path(path).resolve()
    values = json.loads(path.read_text(encoding="utf-8-sig"))
    for key in ("scan_config", "database", "report_directory"):
        if key in values:
            values[key] = str((path.parent / values[key]).resolve())
    return DailyPlan.model_validate(values)
