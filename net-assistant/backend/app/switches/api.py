"""Read-only switch API. No credential mutation, collection trigger or arbitrary target API."""
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Query
from app.discovery.api import ApiError, Page, View
from app.discovery.store import Database
from app.switches.config import load_switch_plan
from app.switches.store import SwitchStore
from app.switches.worker import read_runtime


class SwitchRunView(View):
    id: str
    device_id: str | None
    address: str
    profile_id: str
    state: Literal["running", "completed", "partial", "failed", "ignored", "interrupted"]
    started_at: str
    finished_at: str | None
    error_code: str | None
    snapshot: dict | None


class SwitchDeviceView(View):
    id: str
    address: str
    name: str
    object_id: str
    vendor: Literal["Ruijie"]
    device_kind: Literal["switch_product", "unverified_network_device"]
    asset_id: None = None
    identity_verified: Literal[False] = False
    first_seen_at: str
    last_seen_at: str
    latest: SwitchRunView | None


def install_switch_api(app, database_path: Path, config_path: Path | None = None):
    store = SwitchStore(Database(database_path, readonly=True))
    router = APIRouter(prefix="/api/v1", tags=["switches (read only)"])

    @router.get("/switches/status", operation_id="getSwitchCollectionStatus")
    def status():
        if config_path is None:
            return {"configured": False, "state": "not_configured", "reasonCode": "switch_plan_required",
                    "heartbeatAt": None, "lastCycle": None, "nextDueAt": None}
        try:
            plan = load_switch_plan(config_path)
            if plan.database != database_path.resolve():
                raise ValueError("Database mismatch.")
            runtime = read_runtime(plan)
            return {**runtime, "configured": True, "enabled": plan.enabled,
                    "authorizedAddressCount": len(plan.addresses()), "targetCount": len(plan.addresses()),
                    "profileCount": len(plan.profiles),
                    # API and SCM processes can inherit different environments.
                    "readyProfileCount": runtime.get("readyProfileCount"),
                    "intervalSeconds": plan.interval_seconds, "source": "snmpv3_readonly"}
        except (OSError, ValueError, TypeError, KeyError):
            raise ApiError(503, "switch_configuration_invalid", "交换机接入配置不可读取或与当前数据库不一致。")

    @router.get("/switches", response_model=Page[SwitchDeviceView], operation_id="listSwitches")
    def devices(limit: int = Query(50, ge=1, le=200),
                cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        return store.devices(limit, cursor)

    @router.get("/switch-collection-runs", response_model=Page[SwitchRunView], operation_id="listSwitchAttempts")
    def runs(limit: int = Query(50, ge=1, le=200),
             cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        return store.runs(limit, cursor)

    def require_device(device_id):
        item = store.device(device_id)
        if item is None:
            raise ApiError(404, "switch_not_found", "找不到该交换机管理端点。")
        return item

    @router.get("/switches/{device_id}", response_model=SwitchDeviceView, operation_id="getSwitch")
    def device(device_id: str):
        return require_device(device_id)

    @router.get("/switches/{device_id}/snapshots/latest", response_model=SwitchRunView,
                operation_id="getLatestSwitchSnapshot")
    def latest(device_id: str):
        item = require_device(device_id)
        if item["latest"] is None:
            raise ApiError(404, "switch_snapshot_not_found", "该设备暂无采集记录。")
        return item["latest"]

    @router.get("/switches/{device_id}/snapshots", response_model=Page[SwitchRunView],
                operation_id="listSwitchSnapshots")
    def history(device_id: str, limit: int = Query(50, ge=1, le=200),
                cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        require_device(device_id)
        return store.runs(limit, cursor, device_id)

    @router.get("/switch-snapshots/{run_id}", response_model=SwitchRunView, operation_id="getSwitchSnapshot")
    def snapshot(run_id: str):
        item = store.run(run_id)
        if item is None:
            raise ApiError(404, "switch_snapshot_not_found", "找不到该交换机采集记录。")
        return item

    app.include_router(router)
