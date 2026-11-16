"""Temporary databases and loopback servers only; never seed the working DB."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import shutil
import threading

import httpx
import pytest
from pydantic import ValidationError

from app.discovery.config import ScanSettings, load_settings
from app.discovery.execution import execute_scan
from app.discovery.report import write_report
from app.discovery.store import initialize_database
from app.discovery.types import ProbeResult
from app.main import create_app


@pytest.fixture
def anyio_backend():
    return "asyncio"


def settings_for(address="10.81.0.11", **changes):
    return ScanSettings(name="integrity", targets=[address], ports=[22, 80], **changes)


def recorded_job(db, settings, hosts, probes, state="completed", legacy=False):
    scope, revision = db.save_scope(settings)
    snapshot = settings.snapshot()
    if legacy:
        snapshot["vmware_context_files"] = ["Z:/private/machine.vmx"]
    job = db.begin_job(scope, revision, snapshot)
    for address, mac in hosts:
        db.record_discovery(job, address, [], {
            "mac": mac, "discovery_methods": ["icmp:reply"],
            "confidence": "direct_response",
            "context": {"displayName": "NOT_NETWORK_DATA", "sourceFile": "Z:/private/machine.vmx"}
            if legacy else {},
        })
    db.record_probes(job, probes)
    db.finish_job(job, state, {"responsiveHosts": len(hosts)})
    return job


def export_json(db, job, directory):
    result = write_report(db, job, directory)
    return json.loads((result / "observations.json").read_text(encoding="utf-8"))


def test_vm_configuration_is_rejected_instead_of_read_or_used(tmp_path):
    # A deprecated VM file option must fail validation, even when the file exists.
    vmx = tmp_path / "machine.vmx"
    vmx.write_text('displayName = "NOT_NETWORK_DATA"', encoding="utf-8")
    config = tmp_path / "scope.json"
    config.write_text(json.dumps({
        "name": "normal-network", "targets": ["10.81.0.11"], "ports": [80],
        "vmware_context_files": [str(vmx)],
    }), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_settings(config)


@pytest.mark.anyio
@pytest.mark.parametrize("address,port,status", [
    ("10.81.0.11", 22, "open"), ("10.92.0.22", 80, "timeout"),
])
async def test_api_returns_selected_database_rows_not_sample_devices(tmp_path, address, port, status):
    db = initialize_database(tmp_path / "isolated.sqlite")
    settings = settings_for(address)
    job = recorded_job(db, settings, [(address, "02:11:22:33:44:55")], [
        ProbeResult(address, "tcp", status, port=port, phase="inventory", duration_ms=7.25),
    ], legacy=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=db.path)), base_url="http://test",
    ) as client:
        hosts = (await client.get(f"/api/v1/discovery-jobs/{job}/hosts")).json()["items"]
        probes = (await client.get(f"/api/v1/discovery-jobs/{job}/probes")).json()["items"]
        detail = (await client.get(f"/api/v1/discovery-jobs/{job}")).json()
    assert len(hosts) == 1 and hosts[0]["address"] == address
    assert hosts[0]["openPorts"] == ([port] if status == "open" else [])
    assert [(row["address"], row["port"], row["status"], row["durationMs"]) for row in probes] == [
        (address, port, status, 7.25),
    ]
    assert "context" not in hosts[0]
    assert "vmwareContextFiles" not in detail["configSnapshot"]
    exported = export_json(db, job, tmp_path / "reports")
    assert "NOT_NETWORK_DATA" not in json.dumps(exported)
    assert "machine.vmx" not in json.dumps(exported)


def test_first_report_has_no_invented_baseline(tmp_path):
    db = initialize_database(tmp_path / "db.sqlite")
    job = recorded_job(db, settings_for(), [], [])
    exported = export_json(db, job, tmp_path / "reports")
    assert exported["comparison"]["status"] == "unavailable"
    assert exported["comparison"]["reason_code"] == "no_previous_job"
    assert exported["comparison"]["baseline_job_id"] is None


def test_report_compares_real_observations_and_never_calls_timeout_closed(tmp_path):
    db = initialize_database(tmp_path / "db.sqlite")
    settings = settings_for()
    previous = recorded_job(db, settings, [
        ("10.81.0.11", "02:11:22:33:44:55"),
        ("10.81.0.12", "02:11:22:33:44:66"),
    ], [
        ProbeResult("10.81.0.11", "tcp", "open", port=22, phase="inventory"),
        ProbeResult("10.81.0.11", "tcp", "refused", port=80, phase="inventory"),
    ])
    current = recorded_job(db, settings, [
        ("10.81.0.11", "02:11:22:33:44:55"),
        ("10.81.0.13", "02:11:22:33:44:77"),
    ], [
        ProbeResult("10.81.0.11", "tcp", "timeout", port=22, phase="inventory"),
        ProbeResult("10.81.0.11", "tcp", "open", port=80, phase="inventory"),
    ])
    exported = export_json(db, current, tmp_path / "reports")
    comparison = exported["comparison"]
    assert comparison["status"] == "available"
    assert comparison["baseline_job_id"] == previous
    assert comparison["added_addresses"] == ["10.81.0.13"]
    assert comparison["not_observed_addresses"] == ["10.81.0.12"]
    assert [(r["port"], r["before"]["status"], r["after"]["status"])
            for r in comparison["probe_changes"]] == [
                (22, "open", "timeout"), (80, "refused", "open"),
            ]
    markdown = (tmp_path / "reports" / current / "report.md").read_text(encoding="utf-8")
    assert previous in markdown and "timeout" in markdown
    assert "关闭" not in markdown and "离线" not in markdown


@pytest.mark.parametrize("change,previous_state,current_state,reason", [
    ({"ports": [22]}, "completed", "completed", "configuration_changed"),
    ({}, "partial", "completed", "incomplete_scan"),
    ({}, "completed", "partial", "incomplete_scan"),
])
def test_report_refuses_incomparable_scans(tmp_path, change, previous_state, current_state, reason):
    db = initialize_database(tmp_path / "db.sqlite")
    settings = settings_for()
    previous = recorded_job(db, settings, [], [], state=previous_state)
    current = recorded_job(db, settings.model_copy(update=change), [], [], state=current_state)
    comparison = export_json(db, current, tmp_path / "reports")["comparison"]
    assert comparison["status"] == "unavailable"
    assert comparison["reason_code"] == reason
    assert comparison["baseline_job_id"] == previous
    assert comparison["probe_changes"] == []


@pytest.mark.anyio
@pytest.mark.skipif(shutil.which("nmap") is None,
                    reason="Real Nmap required: import-nmap, then run test --local-tools; no mocked fallback.")
async def test_real_loopback_get_to_database_api_and_changed_report(tmp_path):
    # Both responses come from a real local socket; neither API nor report is mocked.
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(self.server.response_status)
            self.send_header("Content-Type", "application/x-integrity-check")
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.response_status = 200
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    settings = ScanSettings(
        name="real-loopback", targets=["127.0.0.1"], ports=[port],
        discovery_ports=[port], http_ports=[port], allow_loopback=True,
        icmp_enabled=False, arp_enabled=False, timeout_ms=2000,
    )
    db = initialize_database(tmp_path / "socket.sqlite")
    try:
        first = await asyncio.to_thread(execute_scan, settings, db, tmp_path / "reports")
        server.response_status = 503
        second = await asyncio.to_thread(execute_scan, settings, db, tmp_path / "reports")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=db.path)), base_url="http://test",
        ) as client:
            for result, expected in [(first, 200), (second, 503)]:
                response = await client.get(
                    f"/api/v1/discovery-jobs/{result['jobId']}/probes?method=http")
                assert response.status_code == 200
                rows = response.json()["items"]
                assert len(rows) == 1
                assert rows[0]["evidence"]["statusCode"] == expected
                assert rows[0]["evidence"]["requestMethod"] == "GET"
        exported = json.loads((tmp_path / "reports" / second["jobId"] / "observations.json")
                              .read_text(encoding="utf-8"))
        assert exported["comparison"]["baseline_job_id"] == first["jobId"]
        changes = [r for r in exported["comparison"]["probe_changes"] if r["method"] == "http"]
        assert len(changes) == 1
        assert changes[0]["before"]["evidence"]["statusCode"] == 200
        assert changes[0]["after"]["evidence"]["statusCode"] == 503
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=db.path)), base_url="http://test",
        ) as client:
            response = await client.get(f"/api/v1/discovery-jobs/{second['jobId']}/comparison")
            assert response.status_code == 200
            assert response.json()["baselineJobId"] == first["jobId"]
            http_change = next(r for r in response.json()["probeChanges"] if r["method"] == "http")
            assert http_change["after"]["evidence"]["statusCode"] == 503
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.anyio
async def test_empty_database_returns_empty_rows_without_fixed_examples(tmp_path):
    db = initialize_database(tmp_path / "empty.sqlite")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=db.path)), base_url="http://test",
    ) as client:
        for path in ("/assets", "/discovery-jobs"):
            response = await client.get("/api/v1" + path)
            assert response.status_code == 200
            assert response.json() == {"items": [], "nextCursor": None}
        missing = await client.get("/api/v1/discovery-jobs/absent/comparison")
        assert missing.status_code == 404


@pytest.mark.anyio
async def test_arp_output_contains_evidence_not_a_fixed_explanatory_paragraph(tmp_path):
    db = initialize_database(tmp_path / "legacy-arp.sqlite")
    settings = settings_for()
    job = recorded_job(db, settings, [("10.81.0.11", "02:11:22:33:44:55")], [
        ProbeResult("10.81.0.11", "arp", "resolved", evidence={
            "mac": "02:11:22:33:44:55", "cachePossible": True,
            "source": "windows_send_arp", "note": "OLD_FIXED_EXPLANATION",
        }),
    ])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(allow_anonymous_reads=True, database_path=db.path)), base_url="http://test",
    ) as client:
        response = await client.get(f"/api/v1/discovery-jobs/{job}/probes?method=arp")
    assert response.json()["items"][0]["evidence"] == {
        "mac": "02:11:22:33:44:55", "cachePossible": True, "source": "windows_send_arp",
    }
    exported = export_json(db, job, tmp_path / "reports")
    assert "OLD_FIXED_EXPLANATION" not in json.dumps(exported)
