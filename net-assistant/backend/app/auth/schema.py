"""Make middleware-enforced authentication and real error envelopes visible in OpenAPI."""


def install_security_schema(app, *, allow_anonymous_reads=False):
    original = app.openapi

    def openapi():
        schema = original()
        components = schema.setdefault("components", {})
        components.setdefault("securitySchemes", {}).update({
            "sessionCookie": {"type": "apiKey", "in": "cookie", "name": "na_session",
                              "description": "HttpOnly cookie obtained from same-origin platform login."},
            "csrfHeader": {"type": "apiKey", "in": "header", "name": "X-CSRF-Token",
                           "description": "csrfToken returned by login/me; required for authenticated writes."},
        })
        components.setdefault("schemas", {})["ApiErrorEnvelope"] = {
            "type": "object", "required": ["code", "message", "requestId", "fieldErrors"],
            "properties": {
                "code": {"type": "string"}, "message": {"type": "string"}, "requestId": {"type": "string"},
                "fieldErrors": {"type": "array", "items": {
                    "type": "object", "required": ["field", "message", "type"],
                    "properties": {name: {"type": "string"} for name in ("field", "message", "type")}}},
            },
        }
        for path, methods in schema["paths"].items():
            if not path.startswith("/api/v1/"):
                continue
            for method, operation in methods.items():
                if method not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue
                login = path == "/api/v1/auth/login" and method == "post"
                public_read = (allow_anonymous_reads and method in ("get", "head") and
                               not path.startswith("/api/v1/terminal") and path != "/api/v1/auth/me")
                operation["security"] = [] if login or public_read else [
                    {"sessionCookie": [], **({"csrfHeader": []} if method not in ("get", "head", "options") else {})}]
                statuses = (400, 401, 403, 413, 422, 429, 503) if login else (401, 403, 413, 422, 503)
                if path.startswith("/api/v1/terminal"):
                    statuses += (404, 409)
                if path == "/api/v1/terminal/configuration-runs":
                    statuses += (501,)
                for status in statuses:
                    operation.setdefault("responses", {})[str(status)] = {
                        "description": "Unified application error envelope",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiErrorEnvelope"}}},
                    }
        return schema

    app.openapi = openapi
