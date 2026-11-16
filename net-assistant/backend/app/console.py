"""Serve only the compiled, read-only web console; never mount the project root."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.staticfiles import StaticFiles


class ConsoleFiles(StaticFiles):
    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        # Conditional revalidation avoids retaining an old entry point after a build.
        response.headers["Cache-Control"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response


def install_console(app: FastAPI, dist: Path):
    @app.get("/", include_in_schema=False)
    def console_entry():
        return RedirectResponse("/console/")

    if (dist / "index.html").is_file():
        app.mount("/console", ConsoleFiles(directory=dist, html=True), name="console")
    else:
        @app.get("/console/", include_in_schema=False)
        def console_not_built():
            return HTMLResponse(
                '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                "<title>前端尚未构建</title><h1>前端尚未构建</h1>"
                "<p>请在 frontend 目录执行 npm ci、npm run build，然后重启 API。</p>"
                "</html>",
                status_code=503, headers={"Cache-Control": "no-store"},
            )
