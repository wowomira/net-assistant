"""Same-origin cookie authentication. There is no public account-bootstrap endpoint."""
import hmac
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from uuid import uuid4

import anyio
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from app.auth.store import AuthStore
from app.discovery.api import ApiError, View

COOKIE = "na_session"
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class LoginInput(View):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class PasswordInput(View):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class UserView(View):
    id: str
    username: str
    role: str


class AuthSessionView(View):
    user: UserView
    csrf_token: str
    expires_at: str


def iso_time(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def require_principal(request: Request):
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise ApiError(401, "authentication_required", "请先登录平台。")
    return principal


def install_auth(app, path: Path, *, allow_anonymous_reads=False, allow_insecure_local_http=False):
    store = AuthStore(path)
    app.state.auth_store = store
    router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

    def check_origin(request):
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            raise ApiError(403, "origin_rejected", "拒绝跨站管理请求。")
        if request.headers.get("sec-fetch-site") == "cross-site":
            raise ApiError(403, "origin_rejected", "拒绝跨站管理请求。")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        request.state.request_id = str(uuid4())
        is_api = request.url.path.startswith("/api/v1/")
        try:
            if is_api:
                if request.method not in ("GET", "HEAD", "OPTIONS"):
                    check_origin(request)
                public_login = request.url.path == "/api/v1/auth/login" and request.method == "POST"
                token = request.cookies.get(COOKIE)
                principal = await anyio.to_thread.run_sync(store.authenticate, token) if token else None
                request.state.principal = principal
                terminal = request.url.path.startswith("/api/v1/terminal")
                legacy_read = allow_anonymous_reads and not terminal and request.method in ("GET", "HEAD")
                if not public_login and not legacy_read:
                    require_principal(request)
                if not public_login and request.method not in ("GET", "HEAD", "OPTIONS"):
                    principal = require_principal(request)
                    if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), principal.csrf):
                        raise ApiError(403, "csrf_rejected", "请求确认令牌无效，请重新读取登录会话。")
                if request.method not in ("GET", "HEAD", "OPTIONS"):
                    # Bound chunked requests as well as declared Content-Length.
                    body = bytearray()
                    async for chunk in request.stream():
                        if len(body) + len(chunk) > 32768:
                            raise ApiError(413, "request_too_large", "管理请求不得超过32KiB。")
                        body.extend(chunk)
                    request._body = bytes(body)
            response = await call_next(request)
        except (ApiError, sqlite3.Error) as error:
            if isinstance(error, sqlite3.Error):
                error = ApiError(503, "access_store_unavailable", "认证数据库不可用或尚未升级。")
            response = JSONResponse(status_code=error.status, content={
                "code": error.code, "message": error.message,
                "requestId": request.state.request_id, "fieldErrors": [],
            })
        if is_api:
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Request-ID"] = request.state.request_id
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(sqlite3.Error)
    async def access_error(request, error):
        return JSONResponse(status_code=503, content={
            "code": "access_store_unavailable", "message": "认证或终端存储暂不可用。",
            "requestId": request.state.request_id, "fieldErrors": [],
        })

    @router.post("/login", response_model=AuthSessionView, operation_id="login")
    def login(body: LoginInput, request: Request):
        # No reliance on untrusted Forwarded / X-Forwarded-For headers.
        secure = request.url.scheme == "https"
        if not secure and not (allow_insecure_local_http and request.url.hostname in LOOPBACK):
            raise ApiError(400, "https_required", "登录需要HTTPS；回环HTTP开发需显式启用。")
        result = store.login(body.username, body.password, request.client.host if request.client else "unknown")
        token = result.pop("token")
        result["expiresAt"] = iso_time(result["expiresAt"])
        response = JSONResponse(result)
        response.set_cookie(COOKIE, token, max_age=28800, httponly=True, secure=secure,
                            samesite="strict", path="/api")
        return response

    @router.get("/me", response_model=AuthSessionView, operation_id="getCurrentUser")
    def me(request: Request):
        principal = require_principal(request)
        return {"user": principal.view(), "csrfToken": principal.csrf, "expiresAt": iso_time(principal.expires_at)}

    @router.post("/logout", operation_id="logout")
    def logout(request: Request):
        principal = require_principal(request)
        store.logout(principal)
        if hasattr(app.state, "terminal"):
            app.state.terminal.revoke(principal.session_hash)
        response = JSONResponse({"status": "logged_out"})
        response.delete_cookie(COOKIE, path="/api")
        return response

    @router.post("/password", operation_id="changePassword")
    def change_password(body: PasswordInput, request: Request):
        principal = require_principal(request)
        store.change_password(principal, body.current_password, body.new_password)
        if hasattr(app.state, "terminal"):
            app.state.terminal.revoke(principal.session_hash)
        response = JSONResponse({"status": "password_changed", "reauthenticationRequired": True})
        response.delete_cookie(COOKIE, path="/api")
        return response

    app.include_router(router)
