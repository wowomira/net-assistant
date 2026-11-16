"""Real HTTP, production JavaScript and authentication in a relocated temporary checkout."""
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from workspace import isolated_python_command
PYTHON = ROOT / ".runtime" / ("venv/Scripts/python.exe" if os.name == "nt" else "venv/bin/python")
if (ROOT / ".runtime/python/python.exe").is_file():
    PYTHON = ROOT / ".runtime/python/python.exe"


@unittest.skipUnless(PYTHON.is_file(), "Run workspace.py setup first (isolated runtime required)")
class RealHttpWorkspaceTests(unittest.TestCase):
    def test_relocated_checkout_login_console_data_and_logout(self):
        with tempfile.TemporaryDirectory(prefix="net-assistant-relocated-") as directory:
            root = Path(directory) / "朋友的项目 空格"
            scripts = root / "scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/workspace.py", scripts / "workspace.py")
            backend = root / "net-assistant/backend"
            for name in ("app", "migrations"):
                shutil.copytree(ROOT / "net-assistant/backend" / name, backend / name,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            shutil.copytree(ROOT / ".runtime/frontend/dist", root / ".runtime/frontend/dist")
            environment = {key: value for key, value in os.environ.items()
                           if not key.upper().startswith(("INSPECT_", "NET_ASSISTANT_"))
                           and key.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
            environment.update(PYTHONPATH=str(scripts), PYTHONUTF8="1")
            select_checkout = f"import sys;sys.path[:0]=[{str(scripts)!r},{str(backend)!r}];"
            password = secrets.token_urlsafe(30)
            seed = (
                "import sys,workspace; workspace.init_database(); "
                "from app.auth.store import AuthStore; "
                "AuthStore(workspace.layout()['database']).create_user("
                "'isolated-smoke',sys.stdin.read(),'admin')"
            )
            seeded = subprocess.run(isolated_python_command(PYTHON, select_checkout + seed), input=password,
                                    cwd=root, env=environment, text=True, encoding="utf-8",
                                    capture_output=True)
            self.assertEqual(seeded.returncode, 0, seeded.stdout + seeded.stderr)
            with socket.socket() as port_socket:
                port_socket.bind(("127.0.0.1", 0))
                port = port_socket.getsockname()[1]
            launch = (
                "import workspace,uvicorn; "
                f"uvicorn.run(workspace.build_app(),host='127.0.0.1',port={port},"
                "proxy_headers=False,log_level='warning')"
            )
            jar = http.cookiejar.CookieJar()
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPCookieProcessor(jar))
            base = f"http://127.0.0.1:{port}"

            def request(path, data=None, headers=None):
                body = json.dumps(data).encode() if data is not None else None
                req = urllib.request.Request(base + path, data=body, headers={
                    "Content-Type": "application/json", **(headers or {})
                })
                try:
                    response = client.open(req, timeout=5)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    return response.status, response.headers, response.read()

            with (root / ".runtime/http-smoke.log").open("wb") as log:
                process = subprocess.Popen(
                    isolated_python_command(PYTHON, select_checkout + launch), cwd=root, env=environment,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    creationflags=0x08000000 if os.name == "nt" else 0,
                )
                try:
                    deadline = time.monotonic() + 30
                    while True:
                        try:
                            self.assertEqual(request("/health/live")[0], 200)
                            break
                        except (OSError, AssertionError):
                            if process.poll() is not None or time.monotonic() > deadline:
                                self.fail("Owned HTTP process did not become ready.")
                            time.sleep(0.1)
                    self.assertEqual(request("/api/v1/assets")[0], 401)
                    code, _, document = request("/openapi.json")
                    self.assertEqual(code, 200)
                    self.assertEqual(json.loads(document)["info"]["version"], "0.10.0")
                    code, cookie_headers, payload = request("/api/v1/auth/login", {
                        "username": "isolated-smoke", "password": password
                    }, {"Origin": base})
                    self.assertEqual(code, 200, payload)
                    self.assertIn("HttpOnly", cookie_headers.get("Set-Cookie", ""))
                    csrf = json.loads(payload)["csrfToken"]
                    self.assertEqual(request("/api/v1/auth/me")[0], 200)
                    code, _, payload = request("/api/v1/assets")
                    self.assertEqual(code, 200)
                    self.assertEqual(json.loads(payload)["items"], [])
                    self.assertEqual(json.loads(request("/api/v1/terminal/targets")[2]), {"items": []})
                    code, _, page = request("/console/")
                    self.assertEqual(code, 200)
                    self.assertIn(b"/console/assets/", page)
                    # A real production bundle, not just an index.html placeholder.
                    import re
                    asset = re.search(rb'src="([^"]+\.js)"', page).group(1).decode()
                    code, _, bundle = request(asset)
                    self.assertEqual(code, 200)
                    self.assertGreater(len(bundle), 100_000)
                    self.assertEqual(request("/api/v1/auth/logout", {})[0], 403)
                    self.assertEqual(request("/api/v1/auth/logout", {},
                                             {"X-CSRF-Token": csrf, "Origin": base})[0], 200)
                    self.assertEqual(request("/api/v1/assets")[0], 401)
                    self.assertFalse((backend / "data/inspection.sqlite").exists())
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
