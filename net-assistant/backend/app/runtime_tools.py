"""Explicit portable locations, while preserving legacy service invocations."""
import os
from pathlib import Path


def gatus_executable(legacy_root=None):
    if os.environ.get("NET_ASSISTANT_PORTABLE") == "1":
        value = os.environ.get("NET_ASSISTANT_GATUS")
        if not value or not Path(value).is_absolute() or not Path(value).is_file():
            raise FileNotFoundError("Portable Gatus is missing; run bootstrap.ps1.")
        return Path(value)
    root = Path(legacy_root) if legacy_root is not None else Path(__file__).resolve().parents[1]
    return root / "tools/gatus/bin/gatus.exe"


def browser_launch_options():
    # Portable mode uses Playwright's pinned Chromium in the project, never Edge.
    if os.environ.get("NET_ASSISTANT_PORTABLE") == "1":
        return {}  # Playwright's version-matched Chromium headless shell.
    return {"channel": "chromium" if os.name != "nt" else "msedge"}


def install_local_docs(app, directory):
    from fastapi.openapi.docs import get_swagger_ui_html
    from fastapi.staticfiles import StaticFiles
    directory = Path(directory)
    for filename in ("swagger-ui-bundle.js", "swagger-ui.css"):
        if not (directory / filename).is_file():
            raise FileNotFoundError("Local Swagger assets incomplete.")
    app.router.routes[:] = [route for route in app.router.routes
                           if getattr(route, "path", None) not in ("/docs", "/docs/oauth2-redirect", "/redoc")]
    app.mount("/docs-assets", StaticFiles(directory=directory), name="docs-assets")

    @app.get("/docs", include_in_schema=False)
    async def local_docs():
        return get_swagger_ui_html(
            openapi_url=app.openapi_url, title=app.title + " - Swagger",
            swagger_js_url="/docs-assets/swagger-ui-bundle.js",
            swagger_css_url="/docs-assets/swagger-ui.css",
            swagger_favicon_url="data:,",
            swagger_ui_parameters={"validatorUrl": None})
