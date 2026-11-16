"""HTTP contract for controlled terminal commands; frontend never supplies SSH addresses."""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Query, Request
from pydantic import Field

from app.auth.api import require_principal
from app.discovery.api import ApiError, View
from app.terminal.catalog import VENDORS, catalog
from app.terminal.config import load_plan
from app.terminal.service import TerminalService


class OpenInput(View):
    target_id: str = Field(min_length=1, max_length=64)


class PrepareInput(View):
    command_id: str = Field(min_length=1, max_length=64)
    parameters: dict = Field(default_factory=dict, max_length=8)


class ConfirmInput(View):
    first_confirmed: bool = Field(strict=True)
    phrase: str = Field(min_length=1, max_length=64)


class ExecuteInput(View):
    confirmation_token: str | None = Field(default=None, min_length=32, max_length=128)


class EmptyInput(View):
    pass


class ConfigurationPreviewInput(View):
    target_id: str = Field(min_length=1, max_length=64)
    parameters: dict = Field(default_factory=dict, max_length=50)


class ConfigurationRunInput(View):
    plan_id: str | None = Field(default=None, min_length=1, max_length=64)


class SessionView(View):
    id: str
    target_id: str
    state: str
    created_at: str
    updated_at: str
    error_code: str | None
    mode: str


class StepView(View):
    command: str
    status: str


class OperationView(View):
    id: str
    session_id: str
    command_id: str
    commands: list[str]
    risk: str
    state: str
    requires_double_confirmation: bool
    expires_at: str
    created_at: str
    updated_at: str
    output: str | None
    steps: list[StepView]
    error_code: str | None
    business_verified: bool
    automatic_save: bool


def install_terminal(app, database_path: Path, config_path: Path | None):
    plan = load_plan(config_path)
    service = TerminalService(database_path, plan)
    app.state.terminal = service
    previous_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with previous_lifespan(application):
            service.start()
            try:
                yield
            finally:
                service.stop()

    app.router.lifespan_context = lifespan
    router = APIRouter(prefix="/api/v1/terminal", tags=["controlled terminal"])

    @router.get("/vendors", operation_id="listTerminalVendors")
    def vendors(request: Request):
        require_principal(request)
        return {"items": VENDORS, "realDeviceVerified": False}

    @router.get("/targets", operation_id="listTerminalTargets")
    def targets(request: Request):
        principal = require_principal(request)
        return {"items": [t.view() for t in plan.targets if principal.username in t.allowed_users]}

    @router.get("/commands", operation_id="listTerminalCommands")
    def commands(request: Request, vendor: str | None = None, target_id: str | None = Query(None, alias="targetId")):
        principal = require_principal(request)
        target = service.target(target_id, principal) if target_id else None
        if target and vendor and target.vendor != vendor:
            raise ApiError(422, "vendor_target_mismatch", "厂商与目标设备配置不一致。")
        return {"items": catalog(target.vendor if target else vendor, target)}

    @router.get("/configuration-templates", operation_id="listConfigurationTemplates")
    def templates(request: Request):
        require_principal(request)
        return {"items": [], "executionSupported": False}

    @router.get("/configuration-templates/{template_id}", operation_id="getConfigurationTemplate")
    def template(template_id: str, request: Request):
        require_principal(request)
        raise ApiError(404, "configuration_template_not_found", "尚未登记该配置模板。")

    @router.post("/configuration-templates/{template_id}/preview", operation_id="previewConfigurationTemplate")
    def configuration_preview(template_id: str, body: ConfigurationPreviewInput, request: Request):
        service.operator(require_principal(request))
        # No template -> no plan ID, no generated command, no network side effect.
        raise ApiError(404, "configuration_template_not_found", "尚未登记该配置模板，不能生成配置计划。")

    @router.post("/configuration-plans/{plan_id}/confirm", operation_id="confirmConfigurationPlan")
    def configuration_confirm(plan_id: str, body: ConfirmInput, request: Request):
        service.operator(require_principal(request))
        raise ApiError(404, "configuration_plan_not_found", "没有可确认的真实配置计划。")

    @router.post("/configuration-runs", operation_id="createConfigurationRun")
    def configuration_run(body: ConfigurationRunInput, request: Request):
        principal = require_principal(request)
        service.operator(principal)
        raise ApiError(501, "configuration_execution_not_implemented", "尚未登记一键配置方案，不执行任何设备操作。")

    @router.get("/configuration-runs/{run_id}", operation_id="getConfigurationRun")
    def configuration_result(run_id: str, request: Request):
        require_principal(request)
        raise ApiError(404, "configuration_run_not_found", "没有该配置执行记录。")

    @router.post("/sessions", response_model=SessionView, operation_id="openTerminalSession")
    def open_session(body: OpenInput, request: Request):
        return service.open(require_principal(request), body.target_id)

    @router.get("/sessions/{session_id}", response_model=SessionView, operation_id="getTerminalSession")
    def session(session_id: str, request: Request):
        return service.session(session_id, require_principal(request))

    @router.post("/sessions/{session_id}/close", response_model=SessionView, operation_id="closeTerminalSession")
    def close(session_id: str, request: Request, body: EmptyInput):
        principal = require_principal(request)
        service.session(session_id, principal)
        service.close(session_id, "closed", "operator_closed")
        return service.session(session_id, principal)

    @router.get("/sessions/{session_id}/events", operation_id="listTerminalEvents")
    def events(session_id: str, request: Request, cursor: str = Query("0", pattern=r"^[0-9]{1,18}$"),
               limit: int = Query(50, ge=1, le=200)):
        return service.events(session_id, require_principal(request), int(cursor), limit)

    @router.post("/sessions/{session_id}/operations", response_model=OperationView,
                 operation_id="prepareTerminalCommand")
    def prepare(session_id: str, body: PrepareInput, request: Request):
        return service.prepare(session_id, require_principal(request), body.command_id, body.parameters)

    @router.get("/operations/{operation_id}", response_model=OperationView, operation_id="getTerminalOperation")
    def operation(operation_id: str, request: Request):
        return service.operation(operation_id, require_principal(request))

    @router.post("/operations/{operation_id}/confirm", operation_id="confirmTerminalCommand")
    def confirm(operation_id: str, body: ConfirmInput, request: Request):
        return service.confirm(operation_id, require_principal(request), body.first_confirmed, body.phrase)

    @router.post("/operations/{operation_id}/execute", response_model=OperationView,
                 operation_id="executeTerminalCommand")
    def execute(operation_id: str, body: ExecuteInput, request: Request):
        return service.execute(operation_id, require_principal(request), body.confirmation_token)

    app.include_router(router)
