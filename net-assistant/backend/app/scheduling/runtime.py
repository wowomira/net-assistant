"""Atomic heartbeat evidence, separate from scan results and the SQLite schema."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from typing import Literal

from app.discovery.config import load_settings


STALE_SECONDS = 90


class Invocation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["disabled", "not_due", "already_attempted", "busy", "completed",
                    "partial", "failed", "interrupted", "timeout", "invocation_failed"]
    checkedAt: str
    errorCode: str | None = None


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schemaVersion: Literal[1] = 1
    identity: str
    instanceId: str
    state: Literal["running", "checking", "stopped", "error"]
    heartbeatAt: str
    startedAt: str | None = None
    lastCheckedAt: str | None = None
    lastInvocation: Invocation | None = None
    errorCode: str | None = None


def runtime_path(plan) -> Path:
    return plan.database.parent / "runtime" / f"{plan.name}.json"


def plan_identity(plan) -> str:
    # Detect changed schedules/scopes rather than reporting an old worker as current.
    value = {"plan": plan.model_dump(mode="json"),
             "scan": load_settings(plan.scan_config).snapshot()}
    return sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def write_runtime(plan, values, *, identity=None):
    model = Heartbeat.model_validate({**values, "identity": identity or plan_identity(plan)})
    path = runtime_path(plan)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(model.model_dump_json())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_runtime(plan, *, now=None):
    """Read only: a fresh heartbeat is evidence, not proof of future execution."""
    unknown = {"state": "unknown", "reasonCode": "heartbeat_missing",
               "heartbeatAt": None, "startedAt": None, "lastCheckedAt": None,
               "lastInvocation": None, "errorCode": None}
    path = runtime_path(plan)
    try:
        if path.stat().st_size > 32768:
            return {**unknown, "reasonCode": "heartbeat_invalid"}
        record = Heartbeat.model_validate_json(path.read_text(encoding="utf-8"))
        if record.identity != plan_identity(plan):
            return {**unknown, "reasonCode": "configuration_changed"}
        stamp = datetime.fromisoformat(record.heartbeatAt.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("Naive heartbeat.")
        age = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
        if age < -5:
            return {**unknown, "reasonCode": "clock_mismatch"}
        values = record.model_dump(exclude={"schemaVersion", "identity", "instanceId"})
        if age > STALE_SECONDS and record.state != "stopped":
            return {**values, "state": "stale", "reasonCode": "heartbeat_expired"}
        return {**values, "reasonCode": None}
    except FileNotFoundError:
        return unknown
    except (OSError, ValueError, TypeError):
        return {**unknown, "reasonCode": "heartbeat_invalid"}
