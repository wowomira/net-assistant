"""Application factory. Business features are added in separate milestones."""

from fastapi import FastAPI
from pathlib import Path
import os

from app.discovery.api import install_discovery_api
from app.discovery.config import DEFAULT_DATABASE, ROOT
from app.assets.api import install_asset_api
from app.health import router as health_router
from app.scheduling.api import install_scheduler_api
from app.console import install_console
from app.monitoring.api import install_monitoring_api
from app.collectors.api import install_network_api
from app.switches.api import install_switch_api
from app.auth.api import install_auth
from app.auth.schema import install_security_schema
from app.terminal.api import install_terminal


def create_app(database_path: Path | None = None, schedule_config_path: Path | None = None,
               frontend_dist: Path | None = None, monitoring_config_path: Path | None = None,
               switch_config_path: Path | None = None, *,
               allow_anonymous_reads: bool = False,
               allow_insecure_local_http: bool = False,
               terminal_config_path: Path | None = None) -> FastAPI:
    configured_path = database_path or os.environ.get("INSPECT_DB") or DEFAULT_DATABASE
    path = Path(configured_path)
    if not path.is_absolute():
        raise ValueError("INSPECT_DB must be an absolute path.")
    schedule = schedule_config_path or os.environ.get("INSPECT_SCHEDULE_CONFIG")
    # Default project database gets the project plan; independent databases must opt in.
    if schedule is None and path.resolve() == DEFAULT_DATABASE.resolve():
        default_plan = ROOT / "configs/daily-scan.local.json"
        schedule = default_plan if default_plan.is_file() else None
    if schedule is not None and not Path(schedule).is_absolute():
        raise ValueError("INSPECT_SCHEDULE_CONFIG must be an absolute path.")
    app = FastAPI(title="网维助手巡检后端", version="0.10.0")
    app.include_router(health_router)
    install_discovery_api(app, path)
    install_asset_api(app, path)
    install_network_api(app, path)
    install_scheduler_api(app, path, Path(schedule) if schedule is not None else None)
    monitoring = monitoring_config_path or os.environ.get("INSPECT_MONITORING_CONFIG")
    if monitoring is None and path.resolve() == DEFAULT_DATABASE.resolve():
        default_monitoring = ROOT / "configs/monitoring.local.json"
        monitoring = default_monitoring if default_monitoring.is_file() else None
    if monitoring is not None and not Path(monitoring).is_absolute():
        raise ValueError("INSPECT_MONITORING_CONFIG must be an absolute path.")
    install_monitoring_api(app, Path(monitoring) if monitoring is not None else None)
    switches = switch_config_path or os.environ.get("INSPECT_SWITCH_CONFIG")
    if switches is None and path.resolve() == DEFAULT_DATABASE.resolve():
        default_switches = ROOT / "configs/switches.local.json"
        switches = default_switches if default_switches.is_file() else None
    if switches is not None and not Path(switches).is_absolute():
        raise ValueError("INSPECT_SWITCH_CONFIG must be an absolute path.")
    install_switch_api(app, path, Path(switches) if switches is not None else None)
    terminal = terminal_config_path or os.environ.get("INSPECT_TERMINAL_CONFIG")
    install_terminal(app, path, Path(terminal) if terminal is not None else None)
    install_auth(app, path, allow_anonymous_reads=allow_anonymous_reads,
                 allow_insecure_local_http=allow_insecure_local_http)
    install_console(app, frontend_dist if frontend_dist is not None else ROOT.parent / "frontend" / "dist")
    install_security_schema(app, allow_anonymous_reads=allow_anonymous_reads)
    return app
