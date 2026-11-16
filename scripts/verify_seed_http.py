"""Verify private seed history over HTTP in an owned, relocated temporary checkout."""
import argparse
from contextlib import closing
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from data_seed import BUSINESS_TABLES, manifest_path, now, readonly, table_digest, validate_seed
from workspace import ROOT, layout


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(seed_path):
    seed_path = Path(seed_path).resolve()
    manifest = validate_seed(seed_path)
    paths = layout()
    require(paths["python"].is_file(), "Project runtime missing.")
    require((paths["frontend_dist"] / "index.html").is_file(), "Built console missing.")
    with closing(readonly(seed_path)) as database:
        database.row_factory = __import__("sqlite3").Row

        def expected(table):
            return {row["id"]: dict(row) for row in database.execute(f'SELECT * FROM "{table}"')}

        jobs, hosts, probes = (expected(table) for table in (
            "discovery_jobs", "discovery_hosts", "discovery_probes"))
        assets, devices, runs = (expected(table) for table in (
            "assets", "network_devices", "network_collection_runs"))
        links = {(row[0], row[1]) for row in database.execute(
            "SELECT asset_id,discovery_host_id FROM asset_discovery_links")}
        audits = {(row[0], row[1]) for row in database.execute(
            "SELECT asset_id,id FROM asset_audit_events")}
    checked = {}
    with tempfile.TemporaryDirectory(prefix="net-assistant-seed-http-") as temporary:
        root = Path(temporary) / "数据验证 中文 空格"
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        for name in ("workspace.py", "data_seed.py"):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        backend = root / "net-assistant/backend"
        for name in ("app", "migrations"):
            shutil.copytree(ROOT / "net-assistant/backend" / name, backend / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(paths["frontend_dist"], root / ".runtime/frontend/dist")
        local_seed = layout(root)["seed"]
        local_seed.parent.mkdir(parents=True)
        shutil.copyfile(seed_path, local_seed)
        shutil.copyfile(manifest_path(seed_path), manifest_path(local_seed))
        for artifact in manifest["screenshots"]:
            if artifact["status"] == "copied":
                directory = local_seed.parent / "artifacts/screenshots"
                directory.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(seed_path.parent / "artifacts/screenshots" / artifact["file"],
                                directory / artifact["file"])
        environment = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith(("INSPECT_", "NET_ASSISTANT_"))
                       and key.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
        environment.update(PYTHONPATH=str(scripts), PYTHONUTF8="1")
        # Embedded Python ignores PYTHONPATH. Explicit insertion must select the
        # relocated checkout, not the interpreter's original relative _pth entries.
        select_checkout = (f"import sys;sys.path[:0]=[{str(scripts)!r},{str(backend)!r}];")
        password = secrets.token_urlsafe(32)
        create_account = (
            "import sys,workspace; workspace.init_database(); workspace.backend_imports(); "
            "from app.auth.store import AuthStore; "
            "AuthStore(workspace.layout()['database']).create_user("
            "'seed-http-verification',sys.stdin.read(),'admin')"
        )
        result = subprocess.run(
            [str(paths["python"]), "-c", select_checkout + create_account], input=password,
            cwd=root, env=environment, text=True, encoding="utf-8", capture_output=True,
            timeout=60,
        )
        require(result.returncode == 0, "Temporary seed initialization/account setup failed.")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        client = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def request(path, data=None, headers=None):
            body = json.dumps(data).encode() if data is not None else None
            req = urllib.request.Request(base + path, data=body, headers={
                "Content-Type": "application/json", **(headers or {}),
            })
            try:
                response = client.open(req, timeout=30)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, response.headers, response.read()

        def get(path):
            status, _, payload = request(path)
            require(status == 200, f"HTTP query failed: {path.split('?')[0]} ({status})")
            return json.loads(payload)

        def page(path):
            rows = []
            cursor = None
            seen = set()
            while True:
                query = {"limit": 200}
                if cursor is not None:
                    require(cursor not in seen, "Repeated pagination cursor.")
                    seen.add(cursor)
                    query["cursor"] = cursor
                document = get(path + "?" + urllib.parse.urlencode(query))
                rows.extend(document["items"])
                cursor = document["nextCursor"]
                if cursor is None:
                    break
            return rows

        def same(rows, expected_rows, table, fields):
            require(len(rows) == len(expected_rows), f"HTTP row count mismatch: {table}")
            require({row["id"] for row in rows} == set(expected_rows),
                    f"HTTP identity mismatch: {table}")
            for row in rows:
                original = expected_rows[row["id"]]
                require(all(row[api] == original[column] for api, column in fields.items()),
                        f"HTTP history fields changed: {table}")
            checked[table] = len(rows)

        launch = (
            "import workspace,uvicorn; "
            f"uvicorn.run(workspace.build_app(),host='127.0.0.1',port={port},"
            "proxy_headers=False,log_level='warning')"
        )
        with (root / "http.log").open("wb") as log:
            process = subprocess.Popen(
                [str(paths["python"]), "-u", "-c", select_checkout + launch], cwd=root, env=environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            try:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        require(request("/health/live")[0] == 200, "HTTP health failed.")
                        break
                    except (OSError, ValueError):
                        require(process.poll() is None and time.monotonic() < deadline,
                                "Owned temporary HTTP process did not become ready.")
                        time.sleep(0.1)
                require(request("/api/v1/assets")[0] == 401, "Anonymous history was exposed.")
                status, headers, payload = request("/api/v1/auth/login", {
                    "username": "seed-http-verification", "password": password,
                }, {"Origin": base})
                require(status == 200 and "HttpOnly" in headers.get("Set-Cookie", ""),
                        "Cookie login failed.")
                csrf = json.loads(payload)["csrfToken"]
                require(get("/api/v1/auth/me")["user"]["role"] == "admin", "Session lookup failed.")
                same(page("/api/v1/discovery-jobs"), jobs, "discovery_jobs", {
                    "state": "state", "startedAt": "started_at", "finishedAt": "finished_at",
                    "errorCode": "error_code", "scheduleRunId": "schedule_run_id",
                })
                observed_hosts, observed_probes = [], []
                for job_id in jobs:
                    detail = get(f"/api/v1/discovery-jobs/{job_id}")
                    require(detail["id"] == job_id, "Job detail identity mismatch.")
                    observed_hosts.extend(page(f"/api/v1/discovery-jobs/{job_id}/hosts"))
                    observed_probes.extend(page(f"/api/v1/discovery-jobs/{job_id}/probes"))
                same(observed_hosts, hosts, "discovery_hosts", {
                    "jobId": "job_id", "address": "address", "observedAt": "observed_at",
                })
                same(observed_probes, probes, "discovery_probes", {
                    "jobId": "job_id", "status": "status", "observedAt": "observed_at",
                    "reasonCode": "reason_code",
                })
                same(page("/api/v1/assets"), assets, "assets", {
                    "createdAt": "created_at", "updatedAt": "updated_at",
                })
                observed_links, observed_audits = set(), set()
                for asset_id in assets:
                    require(get(f"/api/v1/assets/{asset_id}")["id"] == asset_id,
                            "Asset detail mismatch.")
                    observed_links.update((asset_id, row["discoveryHostId"])
                                          for row in page(f"/api/v1/assets/{asset_id}/observations"))
                    observed_audits.update((asset_id, row["id"])
                                           for row in page(f"/api/v1/assets/{asset_id}/audit"))
                require(observed_links == links, "Asset observation links mismatch.")
                require(observed_audits == audits, "Asset audit history mismatch.")
                checked.update(asset_discovery_links=len(links), asset_audit_events=len(audits))
                same(page("/api/v1/network-devices"), devices, "network_devices", {
                    "createdAt": "created_at", "assetId": "asset_id",
                })
                observed_runs = []
                for device_id in devices:
                    rows = page(f"/api/v1/network-devices/{device_id}/snapshots")
                    observed_runs.extend(rows)
                    if rows:
                        latest = get(f"/api/v1/network-devices/{device_id}/snapshots/latest")
                        require(latest["id"] == rows[-1]["id"], "Latest network attempt mismatch.")
                same(observed_runs, runs, "network_collection_runs", {
                    "deviceId": "device_id", "state": "state", "startedAt": "started_at",
                    "observedAt": "observed_at", "errorCode": "error_code",
                })
                if observed_runs:
                    run = observed_runs[0]
                    require(get(f"/api/v1/network-snapshots/{run['id']}")["id"] == run["id"],
                            "Network snapshot detail mismatch.")
                status, _, document = request("/console/")
                require(status == 200, "Console HTML was not served.")
                match = re.search(rb'src="([^"]+\.js)"', document)
                require(match is not None, "Console production script missing.")
                status, _, javascript = request(match.group(1).decode())
                require(status == 200 and len(javascript) > 100_000,
                        "Console production JavaScript was not served.")
                require(request("/api/v1/auth/logout", {})[0] == 403, "CSRF protection missing.")
                require(request("/api/v1/auth/logout", {}, {
                    "X-CSRF-Token": csrf, "Origin": base})[0] == 200, "Logout failed.")
                require(request("/api/v1/assets")[0] == 401, "Logout did not revoke the session.")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        with closing(readonly(layout(root)["database"])) as connection:
            for table in BUSINESS_TABLES:
                require(table_digest(connection, table) == manifest["tables"][table],
                        f"HTTP startup or reads modified business history: {table}")
        require(not (backend / "data/inspection.sqlite").exists(),
                "Temporary server unexpectedly created a working database.")
    return {
        "verified_at": now(), "seed_sha256": manifest["database_sha256"],
        "checked_counts": checked, "login_logout_verified": True,
        "business_rows_unchanged_after_http": True,
        "verification_account_location": "temporary_database_only",
        "console_html_and_production_js_served": True,
        "visual_browser_verification": False, "clean_windows_offline_verification": False,
        "owned_http_process_stopped": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=Path, default=layout()["seed"])
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = verify(args.seed)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
