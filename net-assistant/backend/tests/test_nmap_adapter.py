import pytest
from pydantic import ValidationError

from app.discovery.config import ScanSettings


XML = b"""<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.92">
 <scaninfo type="connect" protocol="tcp" numservices="3" services="22,80,443"/>
 <host><status state="up" reason="user-set"/>
  <address addr="10.0.0.10" addrtype="ipv4"/>
  <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example NIC"/>
  <hostnames><hostname name="server.local" type="PTR"/></hostnames>
  <ports><extraports state="filtered" count="1"/>
   <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
    <service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"/></port>
   <port protocol="tcp" portid="80"><state state="closed" reason="conn-refused"/></port>
  </ports>
  <os><osmatch name="Linux 5.x" accuracy="94">
   <osclass type="general purpose" vendor="Linux" osfamily="Linux" accuracy="94"/>
  </osmatch></os>
 </host><runstats><finished exit="success"/></runstats>
</nmaprun>"""


def test_nmap_xml_does_not_invent_health_brand_confidence_or_closed_filtered_ports():
    from app.discovery.nmap import parse_nmap
    result = parse_nmap(XML, "10.0.0.10", [22, 80, 443])
    assert result["version"] == "7.92"
    assert result["responsive"] is True  # Open TCP, not the forced host-up status.
    assert result["ports"][443]["status"] == "filtered"
    assert result["ports"][80]["status"] == "refused"
    assert result["ports"][22]["service"]["method"] == "probed"
    assert result["ports"][22]["service"]["confidence"] == 10
    assert result["os_candidates"][0]["accuracy"] == 94
    assert result["vendor_hint"] == {
        "name": "Example NIC", "source": "nmap_mac_prefix",
        "match_type": "prefix_match", "device_brand_confirmed": False,
    }
    assert result["names"] == [{"hostname": "server.local", "source": "nmap_PTR"}]


def test_nmap_table_guess_is_not_protocol_evidence_and_forced_up_is_not_online():
    from app.discovery.nmap import parse_nmap
    xml = XML.replace(b'state="open"', b'state="filtered"').replace(b'method="probed"', b'method="table"')
    assert parse_nmap(xml, "10.0.0.10", [22, 80, 443])["responsive"] is False


def test_nmap_port_table_cannot_populate_confirmed_protocol_product_or_version():
    from app.discovery.inventory import summarize_inventory
    rows = [
        {"method": "tcp", "phase": "inventory", "port": 22, "status": "open", "evidence": {}},
        {"method": "nmap_service", "phase": "enrichment", "port": 22, "status": "identified",
         "evidence": {"method": "table", "name": "ssh", "product": "Not verified",
                      "version": "Not verified", "confidence": 3}},
    ]
    service = summarize_inventory("10.0.0.10", rows, {"ports": [22]})["services"][0]
    assert service["identification"] == "port_table_hint"
    assert service["protocol"] is None and service["product"] is None and service["version"] is None
    assert service["port_hint"] == "ssh"


@pytest.mark.anyio
async def test_total_nmap_budget_does_not_claim_attempted_ports_or_leave_running_job(tmp_path, monkeypatch):
    import asyncio
    from app.discovery import nmap
    from app.discovery.nmap_runner import run_nmap_discovery
    from app.discovery.store import initialize_database
    async def slow(settings, address):
        await asyncio.sleep(10)
    monkeypatch.setattr(nmap, "scan_host", slow)
    settings = ScanSettings(name="budget", targets=["10.0.0.10"], ports=[22],
                            engine="nmap", budget_seconds=0.02)
    db = initialize_database(tmp_path / "test.sqlite")
    job = await run_nmap_discovery(settings, db, probes=None)
    record = db.get_job(job)
    assert record["state"] == "partial" and record["error_code"] == "budget_exceeded"
    assert record["coverage"]["completedTcpChecks"] == 0
    assert record["coverage"]["expectedTcpChecks"] == 1


@pytest.mark.parametrize("xml", [
    XML.replace(b'10.0.0.10', b'10.0.0.11'),
    XML.replace(b'exit="success"', b'exit="error"'),
    XML.replace(b'count="1"', b'count="2"'),
    XML.replace(b"<!DOCTYPE nmaprun>", b'<!DOCTYPE nmaprun [<!ENTITY x "bad">]>'),
    b"<nmaprun>",
])
def test_incomplete_wrong_target_or_entity_xml_is_rejected(xml):
    from app.discovery.nmap import parse_nmap
    with pytest.raises(ValueError):
        parse_nmap(xml, "10.0.0.10", [22, 80, 443])


def test_nmap_command_only_accepts_validated_scope_and_no_scripts():
    from app.discovery.nmap import command_for
    settings = ScanSettings(name="nmap", targets=["10.0.0.10"], ports=[22, 80],
                            engine="nmap", nmap_path="C:/tools/nmap.exe")
    args = command_for(settings, "10.0.0.10")
    assert args[-1] == "10.0.0.10"
    assert "-sT" in args and "-Pn" in args and "-sV" in args
    assert "-sC" not in args and "-A" not in args and "-O" not in args
    assert args[args.index("-p") + 1] == "22,80"
    with pytest.raises(ValueError, match="scope"):
        command_for(settings, "10.0.0.11")


def test_requested_os_scan_records_why_no_system_was_identified():
    from app.discovery.nmap import parse_nmap
    # A forced-up host and filtered ports cannot establish a reliable OS match.
    xml = XML.replace(b'state="open"', b'state="filtered"')
    start, end = xml.index(b"<os>"), xml.index(b"</os>") + len(b"</os>")
    xml = xml[:start] + xml[end:]
    result = parse_nmap(xml, "10.0.0.10", [22, 80, 443], os_requested=True)
    assert result["os_candidates"] == []
    assert result["os_detection"] == {
        "status": "limited",
        "reason_code": "open_and_closed_tcp_not_observed",
        "source": "nmap_os_fingerprint",
        "confirmed": False,
    }


def test_os_candidates_and_not_requested_are_not_conflated():
    from app.discovery.nmap import parse_nmap
    matched = parse_nmap(XML, "10.0.0.10", [22, 80, 443], os_requested=True)
    assert matched["os_detection"]["status"] == "candidates"
    start, end = XML.index(b"<os>"), XML.index(b"</os>") + len(b"</os>")
    no_os = XML[:start] + XML[end:]
    assert parse_nmap(no_os, "10.0.0.10", [22, 80, 443])["os_detection"]["status"] == "not_requested"
    assert parse_nmap(no_os, "10.0.0.10", [22, 80, 443], os_requested=True)["os_detection"]["status"] == "no_match"


def test_ipv6_explicit_scope_exclusion_zone_and_no_64_enumeration():
    settings = ScanSettings(name="ipv6", engine="nmap",
                            targets=["fd00::10", "10.0.0.10", "fe80::12%7"],
                            ports=[80], exclude=["fd00::11"])
    assert settings.addresses() == ["10.0.0.10", "fd00::10", "fe80::12%7"]
    assert settings.permits("fe80::12%7")
    assert not settings.permits("fe80::12%8")
    with pytest.raises((ValueError, ValidationError)):
        ScanSettings(name="huge", engine="nmap", targets=["fd00::/64"], ports=[80]).addresses()
    with pytest.raises((ValueError, ValidationError)):
        ScanSettings(name="zone", engine="nmap", targets=["fe80::12"], ports=[80]).addresses()
    with pytest.raises((ValueError, ValidationError)):
        ScanSettings(name="native", engine="native", targets=["fd00::10"], ports=[80]).addresses()


@pytest.mark.anyio
async def test_nmap_results_survive_database_api_and_keep_table_services_unconfirmed(tmp_path, monkeypatch):
    import httpx
    from app.discovery import nmap
    from app.discovery.nmap_runner import run_nmap_discovery
    from app.discovery.store import initialize_database
    from app.main import create_app

    async def scan(settings, address):
        return nmap.parse_nmap(XML, address, settings.ports)

    monkeypatch.setattr(nmap, "scan_host", scan)
    settings = ScanSettings(name="isolated", targets=["10.0.0.10"], ports=[22, 80, 443],
                            engine="nmap", hostname_enabled=False, arp_enabled=False)
    db = initialize_database(tmp_path / "test.sqlite")
    job = await run_nmap_discovery(settings, db, probes=None)
    assert db.get_job(job)["state"] == "completed"
    assert db.get_job(job)["coverage"]["completedTcpChecks"] == 3
    async with httpx.AsyncClient(transport=httpx.ASGITransport(
        app=create_app(allow_anonymous_reads=True, database_path=db.path)), base_url="http://test") as client:
        response = await client.get(f"/api/v1/discovery-jobs/{job}/hosts")
    assert response.status_code == 200
    host = response.json()["items"][0]
    assert host["hostname"] == "server.local"
    assert host["portScan"]["filtered"] == 1
    assert host["services"][0]["product"] == "OpenSSH"
    assert host["services"][0]["identification"] == "observed"
    assert host["osCandidates"][0]["accuracy"] == 94
    assert host["vendorHint"]["device_brand_confirmed"] is False
    assert host["nameCandidates"][0]["source"] == "nmap_PTR"


@pytest.mark.anyio
async def test_missing_nmap_fails_without_native_fallback_or_fake_coverage(tmp_path, monkeypatch):
    from app.discovery import nmap
    from app.discovery.nmap_runner import run_nmap_discovery
    from app.discovery.store import initialize_database

    async def missing(settings, address):
        raise FileNotFoundError("Nmap missing")

    monkeypatch.setattr(nmap, "scan_host", missing)
    settings = ScanSettings(name="missing", targets=["10.0.0.10"], ports=[22], engine="nmap")
    db = initialize_database(tmp_path / "test.sqlite")
    job = await run_nmap_discovery(settings, db, probes=None)
    assert db.get_job(job)["state"] == "failed"
    assert db.get_job(job)["coverage"]["completedTcpChecks"] == 0
    assert db.list_hosts(job)["items"] == []
    assert db.list_probes(job)["items"][0]["reason_code"] == "nmap_not_installed"


@pytest.fixture
def anyio_backend():
    return "asyncio"
