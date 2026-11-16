from datetime import datetime, timezone
import json

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.discovery.types import safe_text, utc_now
from app.monitoring.config import MonitoringPlan


class GatusError(RuntimeError):
    pass


class Result(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    status: int | None = None
    duration: int = Field(ge=0)
    success: bool
    timestamp: str
    errors: list[str] = Field(default_factory=list, max_length=32)


class Status(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    key: str
    results: list[Result] | None


def _observed(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Observation must include its timezone.")
    if (parsed - datetime.now(timezone.utc)).total_seconds() > 60:
        raise ValueError("Observation timestamp is in the future.")
    return parsed


class GatusClient:
    def __init__(self, plan: MonitoringPlan, *, http=None):
        self.plan = plan
        self.http = http

    async def statuses(self):
        if self.http is not None:
            return await self._statuses(self.http)
        async with httpx.AsyncClient(
            base_url=self.plan.api_url, trust_env=False, follow_redirects=False,
            timeout=5, headers={"Accept-Encoding": "identity"},
        ) as http:
            return await self._statuses(http)

    async def _statuses(self, http):
        try:
            async with http.stream("GET", "/api/v1/endpoints/statuses",
                                   params={"page": 1, "pageSize": 100},
                                   headers={"Accept-Encoding": "identity"}) as response:
                if response.status_code != 200:
                    raise GatusError("gatus_unavailable")
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise GatusError("gatus_invalid_response")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > 4 * 1024 * 1024:
                        raise GatusError("gatus_invalid_response")
            payload = json.loads(data)
            if not isinstance(payload, list) or len(payload) > 2000:
                raise ValueError("Expected endpoint statuses array.")
            statuses = [Status.model_validate(item) for item in payload]
            if len({item.key for item in statuses}) != len(statuses):
                raise ValueError("Duplicate upstream endpoint keys.")
            by_key = {item.key: item for item in statuses}
            items = []
            for endpoint in self.plan.endpoints:
                raw = by_key.get(endpoint.key)
                history = []
                for row in sorted((raw.results or []) if raw else [],
                                  key=lambda result: _observed(result.timestamp)):
                    history.append({
                        "success": row.success, "statusCode": row.status,
                        "durationMs": row.duration / 1_000_000,
                        "observedAt": row.timestamp,
                        "errors": [safe_text(error, 512) for error in row.errors],
                    })
                latest = history[-1] if history else None
                state = "not_configured" if raw is None else "no_data"
                if latest:
                    age = (datetime.now(timezone.utc) - _observed(latest["observedAt"])).total_seconds()
                    state = ("stale" if age > endpoint.interval_seconds * 3 + endpoint.timeout_seconds
                             else "up" if latest["success"] else "down")
                items.append({
                    "id": endpoint.id, "key": endpoint.key, "url": endpoint.url,
                    "assetId": str(endpoint.asset_id) if endpoint.asset_id else None,
                    "associationSource": "operator_config" if endpoint.asset_id else None,
                    "status": state, "latest": latest, "history": history,
                    "historyLimit": 100, "source": "gatus",
                })
            return {"status": "available", "source": "gatus", "fetchedAt": utc_now(), "items": items}
        except GatusError:
            raise
        except httpx.HTTPError as error:
            raise GatusError("gatus_unavailable") from error
        except (ValueError, TypeError, KeyError) as error:
            raise GatusError("gatus_invalid_response") from error
