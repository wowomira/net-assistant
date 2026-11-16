from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def safe_text(value: str, maximum: int = 512) -> str:
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value)[:maximum]


def bounded_evidence(evidence: dict) -> dict:
    raw = json.dumps(evidence, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(raw.encode("utf-8")) <= 2048:
        return json.loads(raw)
    return {"truncated": True, "preview": safe_text(raw, 450)}


@dataclass(frozen=True)
class ProbeResult:
    address: str
    method: str
    status: str
    duration_ms: float = 0
    port: int | None = None
    reason_code: str | None = None
    evidence: dict = field(default_factory=dict)
    observed_at: str = field(default_factory=utc_now)
    phase: str = "discovery"
