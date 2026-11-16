from pathlib import Path

from fastapi import APIRouter, FastAPI

from app.discovery.api import ApiError
from app.monitoring.client import GatusClient, GatusError
from app.monitoring.config import load_plan


def install_monitoring_api(app: FastAPI, plan_path: Path | None):
    router = APIRouter(prefix="/api/v1/monitoring", tags=["Gatus monitoring (read only)"])

    async def read():
        if plan_path is None:
            return {"status": "not_configured", "source": "gatus", "fetchedAt": None, "items": []}
        try:
            plan = load_plan(plan_path)
        except (OSError, ValueError):
            raise ApiError(503, "monitoring_config_invalid", "监控配置不可读取或不符合约定。")
        try:
            return await GatusClient(plan).statuses()
        except GatusError as error:
            raise ApiError(503, str(error), "Gatus 暂不可用或返回了无效数据。")

    @router.get("", operation_id="getMonitoring")
    async def monitoring():
        return await read()

    @router.get("/{endpoint_id}", operation_id="getMonitorHistory")
    async def history(endpoint_id: str):
        result = await read()
        item = next((item for item in result["items"] if item["id"] == endpoint_id), None)
        if item is None:
            raise ApiError(404, "monitor_not_found", "未配置该监控对象。")
        return {**item, "fetchedAt": result["fetchedAt"]}

    app.include_router(router)
