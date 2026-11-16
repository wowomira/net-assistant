"""Process liveness only; database and scheduler readiness are not implemented."""

from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel, ConfigDict


class LivenessResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["alive"] = "alive"


router = APIRouter(prefix="/health", tags=["system"])


@router.get(
    "/live",
    response_model=LivenessResponse,
    operation_id="getLiveness",
    summary="检查后端进程是否能响应",
    description="仅表示进程存活，不代表数据库、调度器或被测设备正常。",
)
async def get_liveness(response: Response) -> LivenessResponse:
    response.headers["Cache-Control"] = "no-store"
    return LivenessResponse()
