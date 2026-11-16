"""Typed scheduler observability; no management or scan-triggering HTTP endpoint."""
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, FastAPI, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import SQLAlchemyError

from app.discovery.api import ApiError, Page, View
from app.discovery.config import load_settings
from app.discovery.types import utc_now
from app.scheduling.config import load_plan
from app.scheduling.status import recent_runs, schedule_status


class InvocationView(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["disabled", "not_due", "already_attempted", "busy", "completed",
                    "partial", "failed", "interrupted", "timeout", "invocation_failed"]
    checkedAt: str
    errorCode: str | None = None


class WorkerView(View):
    state: Literal["unknown", "running", "checking", "stopped", "error", "stale"]
    reason_code: str | None = None
    heartbeat_at: str | None = None
    started_at: str | None = None
    last_checked_at: str | None = None
    last_invocation: InvocationView | None = None
    error_code: str | None = None


class DatabaseView(View):
    state: Literal["missing", "available", "unavailable", "not_checked"]
    reason_code: str | None = None


class ScheduleView(View):
    name: str
    enabled: bool
    daily_at: str
    utc_offset_minutes: int
    local_date: str
    next_due_at: str | None


class ScheduledRunView(View):
    id: str
    schedule_name: str
    local_date: str
    state: Literal["running", "completed", "partial", "failed", "interrupted"]
    started_at: str
    finished_at: str | None
    error_code: str | None
    job_id: str | None


class CapabilitiesView(View):
    network_discovery: Literal[True] = True
    automatic_asset_registration: Literal[True] = True
    manual_scan_entry: Literal["local_cli"] = "local_cli"
    daily_discovery_entry: Literal["independent_worker"] = "independent_worker"
    windows_service_adapter: Literal[True] = True
    cross_platform_probe_parity: Literal[False] = False
    host_metrics: Literal[False] = False
    verified_host_identity: Literal[False] = False
    continuous_inspection: Literal[False] = False
    incident_recovery_rules: Literal[False] = False
    authenticated_write_api: Literal[False] = False


class SchedulerView(View):
    checked_at: str
    configured: bool
    schedule: ScheduleView | None
    worker: WorkerView
    database: DatabaseView
    today_status: Literal["unconfigured", "disabled", "not_due", "pending", "unknown",
                          "running", "completed", "partial", "failed", "interrupted"]
    latest_run: ScheduledRunView | None
    today_run: ScheduledRunView | None
    capabilities: CapabilitiesView


def install_scheduler_api(app: FastAPI, database_path: Path, config_path: Path | None):
    router = APIRouter(prefix="/api/v1/scheduler", tags=["scheduler (read only)"])

    def configured_plan():
        if config_path is None:
            return None
        try:
            plan = load_plan(config_path)
            if plan.database != database_path.resolve():
                raise ValueError("Schedule and HTTP database mismatch.")
            load_settings(plan.scan_config)  # parse scope, no adapter lookup or probe
            return plan
        except (OSError, ValueError, TypeError, KeyError):
            raise ApiError(503, "scheduler_configuration_invalid", "调度配置不可读取或与当前巡检数据库不一致。")

    @router.get("", response_model=SchedulerView, operation_id="getSchedulerStatus",
                summary="读取调度心跳与扫描结果；不会触发扫描")
    def get_status():
        plan = configured_plan()
        if plan is None:
            value = {
                "configured": False, "schedule": None,
                "worker": {"state": "unknown", "reasonCode": "schedule_not_configured"},
                "database": {"state": "not_checked", "reasonCode": None},
                "todayStatus": "unconfigured", "latestRun": None, "todayRun": None,
            }
        else:
            value = schedule_status(plan)
        return SchedulerView.model_validate({
            **value, "checkedAt": utc_now(), "capabilities": CapabilitiesView(),
        })

    @router.get("/runs", response_model=Page[ScheduledRunView], operation_id="listScheduledRuns",
                summary="分页读取该计划的自动扫描记录，不包含手动扫描")
    def list_runs(limit: int = Query(50, ge=1, le=200),
                  cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        plan = configured_plan()
        if plan is None:
            return {"items": [], "next_cursor": None}
        try:
            return recent_runs(plan, limit=limit, cursor=cursor)
        except (SQLAlchemyError, ValueError, OSError):
            raise ApiError(503, "database_unavailable", "巡检数据库尚未就绪或暂不可读取。")

    app.include_router(router)
