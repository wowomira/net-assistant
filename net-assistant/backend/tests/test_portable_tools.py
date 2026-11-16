"""Portable adapters must keep authentication and explicit failure behavior."""
import os
from pathlib import Path

import httpx
import pytest

from app.main import create_app
from app.runtime_tools import browser_launch_options, gatus_executable, install_local_docs


def test_portable_browser_does_not_depend_on_system_edge(monkeypatch):
    monkeypatch.setenv("NET_ASSISTANT_PORTABLE", "1")
    assert "channel" not in browser_launch_options()
    monkeypatch.delenv("NET_ASSISTANT_PORTABLE")
    assert browser_launch_options()["channel"] == ("msedge" if os.name == "nt" else "chromium")


def test_missing_portable_gatus_never_falls_back_to_authors_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("NET_ASSISTANT_PORTABLE", "1")
    monkeypatch.setenv("NET_ASSISTANT_GATUS", str(tmp_path / "missing.exe"))
    with pytest.raises(FileNotFoundError, match="Portable Gatus"):
        gatus_executable()


def test_local_swagger_uses_no_cdn_and_does_not_disable_auth(tmp_path):
    from fastapi.testclient import TestClient
    static = tmp_path / "swagger"
    static.mkdir()
    for name, content in (("swagger-ui-bundle.js", "/* actual test asset */"),
                          ("swagger-ui.css", "/* css fixture */")):
        (static / name).write_text(content, encoding="utf-8")
    app = create_app(database_path=tmp_path / "not-initialized.sqlite",
                     allow_insecure_local_http=True)
    install_local_docs(app, static)
    with TestClient(app) as client:
        response = client.get("/docs")
        assert response.status_code == 200
        assert "/docs-assets/swagger-ui-bundle.js" in response.text
        assert "cdn." not in response.text and "https://" not in response.text
        assert client.get("/docs-assets/swagger-ui-bundle.js").text == "/* actual test asset */"
        assert client.get("/api/v1/assets").status_code == 401
    assert not (tmp_path / "not-initialized.sqlite").exists()
