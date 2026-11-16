"""Opt-in real processes and loopback only: RUN_LOCAL_TOOLS=1 python -m pytest ..."""
import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import threading
import time

import httpx
import pytest

from app.discovery.config import ROOT, ScanSettings
from app.discovery.execution import execute_scan
from app.discovery.store import initialize_database
from app.main import create_app
from app.monitoring.client import GatusClient, GatusError
from app.monitoring.config import MonitoringPlan, render_gatus, write_gatus_config


pytestmark = pytest.mark.skipif(os.environ.get("RUN_LOCAL_TOOLS") != "1",
                                reason="Explicit opt-in: real Nmap/Gatus, loopback only")


def test_real_mdns_name_on_approved_loopback_interface(tmp_path):
    from zeroconf import IPVersion
    from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf
    from app.collectors.mdns import collect_mdns

    async def execute(port):
        publisher = AsyncZeroconf(interfaces=["127.0.0.1"], ip_version=IPVersion.V4Only)
        service = AsyncServiceInfo(
            "_http._tcp.local.", "Codex loopback verification._http._tcp.local.",
            addresses=[socket.inet_aton("127.0.0.1")], port=port,
            server="codex-loopback-verification.local.",
        )
        try:
            await publisher.async_register_service(service)
            settings = ScanSettings(
                name="mdns-loopback-test", targets=["127.0.0.1"], ports=[port], http_ports=[port],
                allow_loopback=True, engine="nmap", mdns_enabled=True,
                mdns_interface_addresses=["127.0.0.1"], mdns_service_types=["_http._tcp.local."],
                timeout_ms=3000, arp_enabled=False, hostname_enabled=False,
            )
            names = await collect_mdns(settings)
            assert names["127.0.0.1"][0]["hostname"] == "codex-loopback-verification.local"
            assert list(names) == ["127.0.0.1"]
            db = initialize_database(tmp_path / "mdns.sqlite")
            output = await asyncio.to_thread(execute_scan, settings, db, tmp_path / "reports")
            assert db.get_job(output["jobId"])["coverage"]["mdnsStatus"] == "completed"
            with live_api(create_app(allow_anonymous_reads=True, database_path=db.path)) as api:
                response = httpx.get(f'{api}/api/v1/discovery-jobs/{output["jobId"]}/hosts',
                                     trust_env=False)
                assert response.status_code == 200
                candidates = response.json()["items"][0]["nameCandidates"]
                assert any(item["hostname"] == "codex-loopback-verification.local"
                           and item["source"] == "mdns_server" for item in candidates)
            print(json.dumps({"realTool": "python-zeroconf", "interface": "127.0.0.1",
                              "source": names["127.0.0.1"][0]["source"]}))
        finally:
            await publisher.async_unregister_service(service)
            await publisher.async_close()

    with server() as (port, _):
        asyncio.run(execute(port))


@pytest.mark.skipif(os.name != "nt", reason="Real Windows local snapshot collector")
def test_real_automation_gatus_windows_snapshot_database_and_http(tmp_path):
    from uuid import uuid4
    from app.collectors.store import NetworkStore
    from app.discovery.store import Database
    from app.monitoring.automation import load_automation, read_state, run_automation
    with server() as (port, _):
        monitor = MonitoringPlan(
            api_url=f"http://127.0.0.1:{unused_port()}", allowed_hosts=["127.0.0.1"],
            allow_loopback=True,
            endpoints=[{"id": "actual-automation-web", "url": f"http://127.0.0.1:{port}",
                        "interval_seconds": 5}])
        monitor_path = tmp_path / "monitoring.json"
        monitor_path.write_text(monitor.model_dump_json(), encoding="utf-8")
        config = tmp_path / "automation.json"
        config.write_text(json.dumps({
            "device_id": str(uuid4()), "device_label": "isolated real local collection",
            "database": str(tmp_path / "inspection.sqlite"), "monitoring_plan": str(monitor_path),
            "storage": str(tmp_path / "gatus.sqlite"), "collector_interval_seconds": 30,
        }), encoding="utf-8")
        plan = load_automation(config)
        stop, errors, result = threading.Event(), [], []

        def run():
            try:
                result.append(run_automation(config, stop_event=stop))
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 50
            before = None
            while time.monotonic() < deadline:
                assert not errors, errors
                state = read_state(plan)
                if state.get("lastCollection", {}).get("state") == "completed":
                    try:
                        current = asyncio.run(GatusClient(monitor).statuses())
                        if current["items"][0]["status"] == "up":
                            before = state["lastCollection"]["id"]
                            break
                    except GatusError:
                        pass
                time.sleep(.2)
            assert before is not None, read_state(plan)
            # Wait for a second real timer-driven sample; not two manual CLI invocations.
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                assert not errors, errors
                state = read_state(plan)
                if state.get("lastCollection", {}).get("id") != before:
                    break
                time.sleep(.2)
            assert state["lastCollection"]["id"] != before
            assert state["lastCollection"]["state"] == "completed"
            store = NetworkStore(Database(plan.database, readonly=True))
            sample = store.latest(str(plan.device_id))
            assert sample["snapshot"]["interfaces"]
            assert sample["snapshot"]["source"] == "windows_native"
            assert len(store.history(str(plan.device_id))["items"]) >= 2
            with live_api(create_app(allow_anonymous_reads=True, database_path=plan.database,
                                     monitoring_config_path=monitor_path)) as api:
                response = httpx.get(
                    f"{api}/api/v1/network-devices/{plan.device_id}/snapshots/latest",
                    trust_env=False)
                assert response.status_code == 200
                assert response.json() == sample
                monitoring = httpx.get(f"{api}/api/v1/monitoring", trust_env=False)
                assert monitoring.status_code == 200
                assert monitoring.json()["items"][0]["status"] == "up"
            print(json.dumps({"realTool": "integrated-automation", "timedSnapshots": 2,
                              "windowsInterfaces": len(sample["snapshot"]["interfaces"]),
                              "realHttpReadback": True}))
        finally:
            stop.set()
            thread.join(40)
            assert not thread.is_alive(), "Owned automation did not stop."
            assert not errors, errors
        assert result == [0]
        assert read_state(plan)["state"] == "stopped"


@contextmanager
def server(family=socket.AF_INET, context=None):
    state = {"code": 200, "forbidden_hits": 0}

    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            try:
                super().handle()
            except ConnectionResetError:
                # Nmap service detection intentionally closes probe connections.
                pass

        def do_GET(self):
            if self.path == "/must-not-follow":
                state["forbidden_hits"] += 1
            body = b"<html><title>Loopback actual service</title></html>"
            self.send_response(302 if self.path == "/redirect" else state["code"])
            if self.path == "/redirect":
                self.send_header("Location", "/must-not-follow")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def log_message(self, *_):
            pass

    class Server(ThreadingHTTPServer):
        address_family = family
        daemon_threads = True

    http = Server(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0), Handler)
    if context is not None:
        http.socket = context.wrap_socket(http.socket, server_side=True)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield http.server_address[1], state
    finally:
        http.shutdown()
        http.server_close()
        thread.join(3)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def live_api(app):
    """Actual HTTP transport, not an in-process ASGI client."""
    import uvicorn
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    api = uvicorn.Server(uvicorn.Config(app, log_level="critical", lifespan="off"))
    thread = threading.Thread(target=api.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not api.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert api.started, "Temporary loopback API did not start."
        yield f"http://127.0.0.1:{port}"
    finally:
        api.should_exit = True
        thread.join(10)
        sock.close()
        assert not thread.is_alive(), "Temporary API did not shut down."


@pytest.mark.parametrize("address,family", [("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)])
def test_real_nmap_scan_to_persisted_api_website_and_report(tmp_path, address, family):
    with server(family) as (port, _):
        settings = ScanSettings(
            name="actual-loopback-tools", targets=[address], ports=[port],
            http_ports=[port], engine="nmap", allow_loopback=True,
            arp_enabled=False, icmp_enabled=False, hostname_enabled=False,
            timeout_ms=2000, nmap_host_timeout_seconds=30, budget_seconds=60,
        )
        db = initialize_database(tmp_path / "discovery.sqlite")
        result = execute_scan(settings, db, tmp_path / "reports")
        job = db.get_job(result["jobId"])
        assert job["state"] == "completed", job
        hosts = db.list_hosts(result["jobId"])["items"]
        assert hosts[0]["address"] == address
        assert hosts[0]["open_ports"] == [port]
        assert hosts[0]["websites"][0]["title"] == "Loopback actual service"
        assert hosts[0]["websites"][0]["url"] == (
            f"http://[::1]:{port}/" if family == socket.AF_INET6 else f"http://127.0.0.1:{port}/")
        assert Path(result["reportDirectory"], "observations.json").is_file()
        assert len(job["coverage"]["toolVersions"]) == 1 and job["coverage"]["toolVersions"][0]
        with live_api(create_app(allow_anonymous_reads=True, database_path=db.path)) as api:
            response = httpx.get(f'{api}/api/v1/discovery-jobs/{result["jobId"]}/hosts',
                                 trust_env=False)
            assert response.status_code == 200
            received = response.json()["items"][0]
            assert received["address"] == address
            assert received["openPorts"] == [port]
            assert received["websites"][0]["title"] == "Loopback actual service"
            assert received["services"][0]["protocol"] == "http"
        print(json.dumps({"realTool": "nmap", "address": address, "port": port,
                          "jobState": job["state"], "websiteTitle": hosts[0]["websites"][0]["title"]}))


def test_real_os_attempt_is_stored_and_transmitted_without_inventing_windows_match(tmp_path):
    import platform
    with server() as (port, _):
        closed = unused_port()
        settings = ScanSettings(
            name="actual-os-attempt", targets=["127.0.0.1"], ports=[port, closed],
            allow_loopback=True, nmap_os_detection=True, arp_enabled=False,
            hostname_enabled=False, nmap_host_timeout_seconds=25, budget_seconds=40,
        )
        db = initialize_database(tmp_path / "os.sqlite")
        output = execute_scan(settings, db, tmp_path / "reports")
        job = db.get_job(output["jobId"])
        assert job["state"] == "completed", job
        with live_api(create_app(allow_anonymous_reads=True, database_path=db.path)) as api:
            response = httpx.get(f'{api}/api/v1/discovery-jobs/{output["jobId"]}/hosts',
                                 trust_env=False)
            assert response.status_code == 200
            host = response.json()["items"][0]
        assert host["osDetection"]["status"] in ("candidates", "limited", "no_match")
        assert host["osDetection"]["confirmed"] is False
        if host["osCandidates"]:
            assert host["osDetection"]["status"] == "candidates"
            assert all(not item["confirmed"] for item in host["osCandidates"])
        else:
            assert host["osDetection"]["reason_code"]
        print(json.dumps({"realTool": "nmap-os", "target": "127.0.0.1",
                          "localBaseline": platform.system() + " " + platform.release(),
                          "result": host["osDetection"], "candidates": host["osCandidates"]}))


def test_real_gatus_up_down_recovery_sqlite_restart_redirect_and_tls(tmp_path):
    from app.runtime_tools import gatus_executable
    executable = gatus_executable()
    assert executable.is_file(), "Build the pinned project-local Gatus first."
    # Generate the isolated test certificate with an already pinned dependency,
    # not an unrelated Git installation's openssl.exe.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(
                ipaddress.ip_address("127.0.0.1"))]), critical=False).sign(key, hashes.SHA256()))
    (tmp_path / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    with server() as (target_port, state), server(context=context) as (tls_port, _):
        web_port = unused_port()
        plan = MonitoringPlan(
            api_url=f"http://127.0.0.1:{web_port}",
            allowed_hosts=["127.0.0.1"], allow_loopback=True,
            endpoints=[
                {"id": "web", "url": f"http://127.0.0.1:{target_port}/",
                 "interval_seconds": 5, "timeout_seconds": 2},
                {"id": "tcp", "url": f"tcp://127.0.0.1:{target_port}",
                 "interval_seconds": 5, "timeout_seconds": 2},
                {"id": "redirect", "url": f"http://127.0.0.1:{target_port}/redirect",
                 "interval_seconds": 5, "timeout_seconds": 2},
                {"id": "self-signed", "url": f"https://127.0.0.1:{tls_port}/",
                 "interval_seconds": 5, "timeout_seconds": 2, "certificate_days": 7},
            ],
        )
        config = tmp_path / "gatus.yaml"
        storage = tmp_path / "gatus.sqlite"
        write_gatus_config(plan, config, storage, web_port)
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(plan.model_dump_json(), encoding="utf-8")
        env = {**os.environ, "GATUS_CONFIG_PATH": str(config)}
        # Do not inherit a workstation proxy for monitoring; target is loopback.
        for name in list(env):
            if name.lower() in ("http_proxy", "https_proxy", "all_proxy"):
                del env[name]
        log = (tmp_path / "gatus.log").open("wb")
        process = None

        def start():
            return subprocess.Popen([str(executable)], cwd=tmp_path, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, creationflags=0x08000000)

        def stop():
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

        def wait_state(expected):
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                assert process.poll() is None, (tmp_path / "gatus.log").read_text("utf-8", errors="replace")
                try:
                    result = asyncio.run(GatusClient(plan).statuses())
                    by_id = {item["id"]: item for item in result["items"]}
                    if all(by_id[key]["status"] == status for key, status in expected.items()):
                        return by_id
                except GatusError:
                    pass
                time.sleep(1)
            pytest.fail("Gatus transition timeout: " + (tmp_path / "gatus.log").read_text("utf-8", errors="replace"))

        try:
            process = start()
            up = wait_state({"web": "up", "tcp": "up", "redirect": "down", "self-signed": "down"})
            assert up["redirect"]["latest"]["statusCode"] == 302
            assert up["self-signed"]["latest"]["errors"], up["self-signed"]
            state["code"] = 503
            down = wait_state({"web": "down"})
            assert down["web"]["latest"]["statusCode"] == 503
            state["code"] = 200
            recovered = wait_state({"web": "up"})
            before = {entry["observedAt"] for entry in recovered["web"]["history"]}
            assert any(not row["success"] for row in recovered["web"]["history"])
            stop()  # Forced stop also tests persisted committed observations, not an in-memory cache.
            with sqlite3.connect(storage) as db:
                assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert render_gatus(plan, storage, web_port)["storage"]["type"] == "sqlite"
            process = start()
            restarted = wait_state({"web": "up"})
            assert before <= {entry["observedAt"] for entry in restarted["web"]["history"]}
            assert state["forbidden_hits"] == 0

            with live_api(create_app(allow_anonymous_reads=True, database_path=tmp_path / "not-created.sqlite",
                                     monitoring_config_path=plan_path)) as api:
                response = httpx.get(f"{api}/api/v1/monitoring/web", trust_env=False)
                assert response.status_code == 200
                assert response.json()["status"] == "up"
                assert len(response.json()["history"]) >= 3
            assert not (tmp_path / "not-created.sqlite").exists()
            print(json.dumps({"realTool": "gatus", "version": "v5.38.0",
                              "transitions": ["up", "down:503", "up"],
                              "sqliteRestartHistoryPreserved": True,
                              "redirectFollowed": False, "untrustedTlsAccepted": False}))
        finally:
            stop()
            log.close()
