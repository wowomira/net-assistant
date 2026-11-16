"""Live entry selects mature tools; archived native code is not a fallback."""
import pytest
from pydantic import ValidationError

from app.discovery.config import ScanSettings
from app.discovery.execution import execute_scan
from app.discovery.store import initialize_database


def test_default_entry_persists_nmap_results_without_native_probes(tmp_path, monkeypatch):
    from app.discovery import execution, nmap

    async def scan(settings, address):
        assert address == "10.0.0.10"
        return nmap.parse_nmap(
            b'<nmaprun version="7.92"><host><address addr="10.0.0.10" addrtype="ipv4"/>'
            b'<ports><port protocol="tcp" portid="22"><state state="open"/>'
            b'<service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"/>'
            b'</port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>',
            address, [22],
        )

    class NoNativeProbes:
        def __init__(self, *_):
            pass

        async def close(self):
            pass

    monkeypatch.setattr(nmap, "scan_host", scan)
    monkeypatch.setattr(execution, "SystemProbes", NoNativeProbes)
    settings = ScanSettings(
        name="upgraded-entry", targets=["10.0.0.10"], ports=[22],
        icmp_enabled=False, arp_enabled=False, hostname_enabled=False,
        passive_service_detection=False,
    )
    db = initialize_database(tmp_path / "isolated.sqlite")
    output = execute_scan(settings, db, tmp_path / "reports")
    job = db.get_job(output["jobId"])
    assert job["state"] == "completed"
    assert job["coverage"]["engine"] == "nmap"
    assert db.list_hosts(job["id"])["items"][0]["services"][0]["product"] == "OpenSSH"


def test_native_config_cannot_reactivate_archived_scanner():
    with pytest.raises(ValidationError):
        ScanSettings(name="no-old-engine", targets=["10.0.0.10"], ports=[22], engine="native")


def test_missing_default_tool_records_failure_not_native_success(tmp_path, monkeypatch):
    from app.discovery import nmap

    async def missing(*_):
        raise FileNotFoundError("No tool")

    monkeypatch.setattr(nmap, "scan_host", missing)
    settings = ScanSettings(name="no-fallback", targets=["127.0.0.1"], ports=[22],
                            allow_loopback=True, hostname_enabled=False, arp_enabled=False)
    db = initialize_database(tmp_path / "isolated.sqlite")
    output = execute_scan(settings, db, tmp_path / "reports")
    assert db.get_job(output["jobId"])["state"] == "failed"
    assert db.list_hosts(output["jobId"])["items"] == []
    assert db.list_probes(output["jobId"])["items"][0]["reason_code"] == "nmap_not_installed"
