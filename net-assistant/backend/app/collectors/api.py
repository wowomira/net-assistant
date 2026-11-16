"""Read only: GET never collects, migrates, or registers a local host."""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Query

from app.collectors.contracts import NetworkSnapshot
from app.collectors.store import NetworkStore
from app.discovery.api import ApiError, Page, View
from app.discovery.store import Database


class DeviceView(View):
    id: str
    label: str
    asset_id: str | None
    association_source: Literal["operator_config"] | None
    source: Literal["windows_native"]
    created_at: str


class SnapshotView(View):
    id: str
    device_id: str
    asset_id: str | None
    source: Literal["windows_native"]
    association_source: Literal["operator_config"] | None
    state: Literal["running", "completed", "failed", "interrupted"]
    started_at: str
    finished_at: str | None
    observed_at: str | None
    error_code: str | None
    snapshot: NetworkSnapshot | None


def install_network_api(app, database_path):
    store = NetworkStore(Database(database_path, readonly=True))
    router = APIRouter(prefix="/api/v1", tags=["local network snapshots (read only)"])

    @router.get("/network-devices", response_model=Page[DeviceView], operation_id="listNetworkDevices")
    def devices(limit: int = Query(50, ge=1, le=200),
                cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        return store.devices(limit, cursor)

    @router.get("/network-devices/{device_id}/snapshots/latest",
                response_model=SnapshotView, operation_id="getLatestNetworkSnapshot")
    def latest(device_id: UUID):
        row = store.latest(str(device_id))
        if row is None:
            raise ApiError(404, "network_snapshot_not_found", "该设备还没有网络采集记录。")
        return row

    @router.get("/network-devices/{device_id}/snapshots",
                response_model=Page[SnapshotView], operation_id="listNetworkSnapshots")
    def history(device_id: UUID, limit: int = Query(50, ge=1, le=200),
                cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        return store.history(str(device_id), limit, cursor)

    @router.get("/network-snapshots/{run_id}", response_model=SnapshotView,
                operation_id="getNetworkSnapshot")
    def get(run_id: UUID):
        row = store.get(str(run_id))
        if row is None:
            raise ApiError(404, "network_snapshot_not_found", "找不到该网络采集记录。")
        return row

    app.include_router(router)
