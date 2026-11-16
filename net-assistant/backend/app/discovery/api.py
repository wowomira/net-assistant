from pathlib import Path
from typing import Generic, Literal, TypeVar
from uuid import uuid4

from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel
from sqlalchemy.exc import SQLAlchemyError

from app.discovery.store import Database
from app.discovery.models import ProbeRow
from sqlalchemy import select
from sqlalchemy.orm import Session
import re


class View(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


T = TypeVar("T")


class Page(View, Generic[T]):
    items: list[T]
    next_cursor: str | None


class JobView(View):
    id: str
    scope_id: str
    scope_revision: int
    state: Literal["running", "completed", "partial", "failed", "interrupted"]
    started_at: str
    finished_at: str | None
    config_snapshot: dict
    coverage: dict
    error_code: str | None
    trigger: Literal["manual", "scheduled"] = "manual"
    schedule_run_id: str | None = None


class PortScanView(View):
    scope: str
    planned: int
    attempted: int
    open: int
    refused: int
    timeout: int
    unreachable: int
    error: int
    unattempted: int
    complete: bool
    filtered: int = 0
    open_or_filtered: int = 0
    closed_or_filtered: int = 0
    unfiltered: int = 0


class ServiceView(View):
    port: int
    transport: str
    protocol: str | None
    product: str | None
    version: str | None
    identification: str
    port_hint: str | None
    evidence_methods: list[str]
    detection_method: str | None = None
    tool_confidence: int | None = None


class ScreenshotView(View):
    status: str
    captured_at: str | None
    probe_id: str | None
    reason_code: str | None


class WebsiteView(View):
    url: str
    scheme: str
    port: int
    status: str
    status_code: int | None
    title: str | None
    server: str | None
    redirect_location: str | None
    tls_status: str
    duration_ms: float
    observed_at: str
    screenshot: ScreenshotView


class HostView(View):
    id: str
    job_id: str
    address: str
    mac: str | None
    discovery_methods: list[str]
    confidence: Literal["direct_response", "candidate_only"]
    management_status: Literal["discovered", "managed"]
    collection_access: Literal["not_enrolled", "granted", "revoked"]
    asset_kind: str
    observed_at: str
    open_ports: list[int]
    hostname: str | None = None
    hostname_source: str | None = None
    name_status: str = "not_collected"
    mac_status: str = "not_collected"
    port_scan: PortScanView | None = None
    services: list[ServiceView] = Field(default_factory=list)
    websites: list[WebsiteView] = Field(default_factory=list)
    name_candidates: list[dict] = Field(default_factory=list)
    vendor_hint: dict | None = None
    os_candidates: list[dict] = Field(default_factory=list)
    os_detection: dict = Field(default_factory=lambda: {"status": "not_collected"})
    asset_source: Literal["network_discovery"] = "network_discovery"
    # 尚无主机采集器，缺失值为 null；不能补成 0 或伪造实时指标。
    host_metrics: None = None
    host_metrics_status: Literal["not_collected"] = "not_collected"
    asset_id: str | None = None
    association_status: Literal["unlinked", "linked"] = "unlinked"


class ProbeView(View):
    id: str
    job_id: str
    address: str
    phase: str
    method: str
    port: int | None
    status: str
    duration_ms: float
    reason_code: str | None
    evidence: dict
    observed_at: str


class ProbeValue(View):
    status: str
    evidence: dict


class ProbeChange(View):
    address: str
    phase: str
    method: str
    port: int | None
    before: ProbeValue
    after: ProbeValue


class MacChange(View):
    address: str
    before: str | None
    after: str | None


class ComparisonView(View):
    status: Literal["available", "unavailable"]
    reason_code: Literal["no_previous_job", "configuration_changed", "incomplete_scan"] | None
    baseline_job_id: str | None
    added_addresses: list[str]
    not_observed_addresses: list[str]
    mac_changes: list[MacChange]
    probe_changes: list[ProbeChange]


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


def _job_view(record):
    record = dict(record)
    record["config_snapshot"] = {to_camel(key): value for key, value in record["config_snapshot"].items()}
    return JobView.model_validate(record)


def install_discovery_api(app: FastAPI, database_path: Path):
    database = Database(database_path, readonly=True)
    router = APIRouter(prefix="/api/v1/discovery-jobs", tags=["discovery (read only)"])

    @app.middleware("http")
    async def request_metadata(request: Request, call_next):
        request.state.request_id = getattr(request.state, "request_id", str(uuid4()))
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        if request.url.path.startswith("/api/v1/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def error_response(request, status, code, message):
        return JSONResponse(status_code=status, content={
            "code": code, "message": message,
            "requestId": getattr(request.state, "request_id", str(uuid4())), "fieldErrors": [],
        })

    @app.exception_handler(ApiError)
    async def api_error(request, error):
        return error_response(request, error.status, error.code, error.message)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, _):
        return error_response(request, 503, "database_unavailable", "巡检数据库尚未初始化或暂不可读取。")

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        response = error_response(request, 422, "validation_error", "请求参数不符合接口约定。")
        import json
        body = json.loads(response.body)
        body["fieldErrors"] = [
            {"field": ".".join(map(str, item["loc"])), "message": item["msg"], "type": item["type"]}
            for item in error.errors()
        ]
        return JSONResponse(status_code=422, content=body)

    def require_job(job_id):
        record = database.get_job(job_id)
        if record is None:
            raise ApiError(404, "job_not_found", "找不到该发现任务。")
        return record

    @router.get("", response_model=Page[JobView], operation_id="listDiscoveryJobs")
    def list_jobs(limit: int = Query(50, ge=1, le=200),
                  cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        page = database.list_jobs(limit, cursor)
        return Page[JobView](items=[_job_view(item) for item in page["items"]],
                             next_cursor=page["next_cursor"])

    @router.get("/{job_id}", response_model=JobView, operation_id="getDiscoveryJob")
    def get_job(job_id: str):
        return _job_view(require_job(job_id))

    @router.get("/{job_id}/hosts", response_model=Page[HostView], operation_id="listDiscoveredHosts")
    def list_hosts(job_id: str, limit: int = Query(50, ge=1, le=200),
                   cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        require_job(job_id)
        return database.list_hosts(job_id, limit, cursor)

    @router.get("/{job_id}/screenshots/{probe_id}", response_class=FileResponse,
                operation_id="getWebsiteScreenshot")
    def screenshot(job_id: str, probe_id: str):
        # Artifact identity comes only from a successful probe in the requested job.
        with Session(database.engine) as session:
            row = session.scalar(select(ProbeRow).where(
                ProbeRow.id == probe_id, ProbeRow.job_id == job_id,
                ProbeRow.method == "screenshot", ProbeRow.status == "captured"))
            filename = row.evidence.get("file", "") if row else ""
        if not isinstance(filename, str) or not re.fullmatch(r"[a-f0-9]{32}\.png", filename):
            raise ApiError(404, "screenshot_not_found", "找不到该次截图。")
        root = (database.path.parent / "artifacts" / "screenshots").resolve()
        path = root / filename
        if not path.is_file() or path.resolve().parent != root:
            raise ApiError(404, "screenshot_not_found", "截图文件不存在。")
        return FileResponse(path, media_type="image/png",
                            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    @router.get("/{job_id}/comparison", response_model=ComparisonView,
                operation_id="getDiscoveryComparison")
    def comparison(job_id: str):
        from app.discovery.report import compare_snapshot
        snapshot = database.scan_snapshot(job_id)
        if snapshot is None:
            raise ApiError(404, "job_not_found", "找不到该发现任务。")
        return compare_snapshot(snapshot)

    @router.get("/{job_id}/probes", response_model=Page[ProbeView], operation_id="listDiscoveryProbes")
    def list_probes(
        job_id: str, limit: int = Query(50, ge=1, le=200),
        cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$"),
        address: str | None = None, method: str | None = None, status: str | None = None,
    ):
        require_job(job_id)
        return database.list_probes(job_id, limit, cursor, address, method, status)

    app.include_router(router)
