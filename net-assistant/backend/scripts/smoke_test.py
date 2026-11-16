"""Start a temporary loopback-only server, verify HTTP, and stop our process."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-id", help="Also verify existing discovery records through real read-only HTTP.")
    parser.add_argument("--asset-id", help="Also verify an existing stable asset, linked history and audit.")
    parser.add_argument("--scheduler", action="store_true", help="Verify read-only scheduler status and history.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    base_url = f"http://127.0.0.1:{port}"
    opener = build_opener(ProxyHandler({}))
    # Explicit existing test/operator session, never a default account or password.
    # A token is not accepted through argv and is never printed to the logs.
    session = os.environ.get("INSPECT_SMOKE_SESSION")
    if session:
        if "\n" in session or "\r" in session:
            parser.error("Invalid session token.")
        opener.addheaders = [("Cookie", "na_session=" + session)]
    elif args.job_id or args.asset_id or args.scheduler:
        parser.error("Authenticated business smoke checks require INSPECT_SMOKE_SESSION.")
    command = [
        sys.executable, "-m", "uvicorn", "app.main:create_app",
        "--factory", "--host", "127.0.0.1", "--port", str(port),
        "--workers", "1", "--no-proxy-headers",
    ]
    with tempfile.TemporaryFile() as logs:
        process = subprocess.Popen(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=logs,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Uvicorn exited before startup.")
                try:
                    with opener.open(f"{base_url}/health/live", timeout=1) as response:
                        if response.status != 200:
                            raise RuntimeError("Unexpected liveness status.")
                        payload = json.load(response)
                        if payload != {"status": "alive"}:
                            raise RuntimeError(f"Unexpected liveness body: {payload!r}")
                        if response.headers.get("Cache-Control") != "no-store":
                            raise RuntimeError("Missing no-store response header.")
                    break
                except (URLError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Timed out waiting for the local server.")
                    time.sleep(0.1)

            with opener.open(f"{base_url}/openapi.json", timeout=2) as response:
                schema = json.load(response)
                if schema["paths"]["/health/live"]["get"]["operationId"] != "getLiveness":
                    raise RuntimeError("The HTTP OpenAPI contract did not match.")
            with opener.open(f"{base_url}/docs", timeout=2) as response:
                if response.status != 200:
                    raise RuntimeError("API documentation did not respond.")
            if args.job_id:
                with opener.open(f"{base_url}/api/v1/discovery-jobs/{args.job_id}", timeout=5) as response:
                    job = json.load(response)
                    if job["id"] != args.job_id or "configSnapshot" not in job:
                        raise RuntimeError("Stored job was not returned by the real HTTP API.")
                with opener.open(
                    f"{base_url}/api/v1/discovery-jobs/{args.job_id}/hosts?limit=200", timeout=5
                ) as response:
                    page = json.load(response)
                    if len(page["items"]) != job["coverage"]["discoveredCandidates"]:
                        raise RuntimeError("Stored host count did not match task coverage.")
                    for host in page["items"]:
                        if host["collectionAccess"] != "not_enrolled" or host["hostMetrics"] is not None:
                            raise RuntimeError("Discovery must not auto-grant or fabricate host metrics.")
                        registration = job["coverage"].get("assetRegistration", {})
                        if host["confidence"] == "direct_response" and registration and registration.get("status") != "failed":
                            with opener.open(
                                base_url + f"/api/v1/discovery-hosts/{host['id']}/asset-association",
                                timeout=5,
                            ) as linked_response:
                                association = json.load(linked_response)
                            decision = association["automaticDecision"]
                            if (not host["assetId"] or not decision
                                    or decision["assetId"] != host["assetId"]
                                    or not decision["decidedAt"].endswith("Z")):
                                raise RuntimeError("Automatic decision did not round-trip using the typed camelCase API.")
                with opener.open(
                    f"{base_url}/api/v1/discovery-jobs/{args.job_id}/probes?limit=1", timeout=5
                ) as response:
                    page = json.load(response)
                    if len(page["items"]) != 1 or not page["nextCursor"]:
                        raise RuntimeError("Real HTTP evidence pagination did not match.")
                print("PASS: stored discovery job, asset classification, missing host metrics, evidence pagination.")
            if args.asset_id:
                def read(path):
                    with opener.open(base_url + path, timeout=5) as response:
                        if response.headers.get("Cache-Control") != "no-store":
                            raise RuntimeError("Asset API must not cache potentially stale observations.")
                        return json.load(response)

                asset = read(f"/api/v1/assets/{args.asset_id}")
                if (asset["id"] != args.asset_id or asset["collectionAccess"] != "not_enrolled"
                        or asset["hostMetrics"] is not None):
                    raise RuntimeError("Asset identity or host collection boundary did not match.")
                history = read(f"/api/v1/assets/{args.asset_id}/observations?limit=200")
                if not history["items"]:
                    raise RuntimeError("This smoke fixture must have at least one linked observation.")
                first = history["items"][0]
                association = read(f"/api/v1/discovery-hosts/{first['discoveryHostId']}/asset-association")
                if association["assetId"] != args.asset_id or first["assetId"] != args.asset_id:
                    raise RuntimeError("Asset-to-discovery association did not round-trip.")
                audit = read(f"/api/v1/assets/{args.asset_id}/audit?limit=1")
                if not audit["items"] or audit["items"][0]["action"] != "registered":
                    raise RuntimeError("The initial registration audit was missing.")
                print("PASS: real HTTP asset registry, stable identity, observation history, association, audit.")
            if args.scheduler:
                with opener.open(base_url + "/api/v1/scheduler", timeout=5) as response:
                    if response.headers.get("Cache-Control") != "no-store":
                        raise RuntimeError("Scheduler response must not be cached.")
                    status = json.load(response)
                if not status["configured"] or status["capabilities"]["hostMetrics"] is not False:
                    raise RuntimeError("Schedule configuration or capability boundary did not match.")
                if status["capabilities"]["manualScanEntry"] != "local_cli":
                    raise RuntimeError("Manual scanning must not imply an unauthenticated HTTP write API.")
                with opener.open(base_url + "/api/v1/scheduler/runs?limit=1", timeout=5) as response:
                    runs = json.load(response)
                for run in runs["items"]:
                    if run["scheduleName"] != status["schedule"]["name"] or "configSnapshot" in run:
                        raise RuntimeError("Schedule history scope or privacy mismatch.")
                try:
                    opener.open(Request(base_url + "/api/v1/scheduler", method="POST"), timeout=5).close()
                except HTTPError as error:
                    if error.code != 403:
                        raise
                else:
                    raise RuntimeError("Scheduler observability must not accept HTTP writes.")
                print("PASS: real HTTP scheduler status, history, no-store, capability boundary, POST rejection.")
                print(json.dumps({"scheduler": status, "runs": runs}, ensure_ascii=True, indent=2))
            try:
                opener.open(f"{base_url}/health/ready", timeout=2).close()
            except HTTPError as error:
                if error.code != 404:
                    raise
            else:
                raise RuntimeError("Unimplemented readiness must not report success.")
            print(f"PASS: real HTTP liveness, OpenAPI, docs, readiness boundary ({base_url})")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            logs.seek(0)
            print(logs.read().decode("utf-8", errors="replace"))
            print("Temporary server stopped; no permanent service was installed.")


if __name__ == "__main__":
    main()
