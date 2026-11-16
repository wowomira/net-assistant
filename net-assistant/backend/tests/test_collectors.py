import pytest
from pydantic import ValidationError


def test_windows_multiple_interfaces_addresses_and_neighbors_keep_sources():
    from app.collectors.windows import normalize_network
    snapshot = normalize_network({
        "adapters": [{"ifIndex": 7, "Name": "LAN", "MacAddress": "00-11-22-33-44-55",
                      "InterfaceDescription": "Ethernet", "Status": "Up"},
                     {"ifIndex": 9, "Name": "Other", "MacAddress": "02-11-22-33-44-55",
                      "Status": "Disconnected"}],
        "addresses": [{"InterfaceIndex": 7, "IPAddress": "10.0.0.2", "PrefixLength": 24},
                      {"InterfaceIndex": 7, "IPAddress": "fe80::2", "PrefixLength": 64},
                      {"InterfaceIndex": 9, "IPAddress": "fd00::2", "PrefixLength": 64}],
        "neighbors": [{"InterfaceIndex": 7, "IPAddress": "10.0.0.1",
                       "LinkLayerAddress": "00-11-22-33-44-66", "State": "Stale"}],
    })
    assert len(snapshot.interfaces) == 2
    assert [row.address for row in snapshot.interfaces[0].addresses] == ["10.0.0.2", "fe80::2%7"]
    assert snapshot.interfaces[0].mac == "00:11:22:33:44:55"
    assert snapshot.neighbors[0].state == "Stale"
    assert snapshot.neighbors[0].online_verified is False
    assert snapshot.source == "windows_native"
    assert snapshot.asset_id is None


def test_windows_keeps_ip_interfaces_without_a_netadapter_entry_including_loopback():
    from app.collectors.windows import normalize_network
    snapshot = normalize_network({
        "adapters": [],
        "addresses": [{"InterfaceIndex": 1, "InterfaceAlias": "Loopback Pseudo-Interface 1",
                       "IPAddress": "::1", "PrefixLength": 128},
                      {"InterfaceIndex": 1, "InterfaceAlias": "Loopback Pseudo-Interface 1",
                       "IPAddress": "127.0.0.1", "PrefixLength": 8}],
        "neighbors": [],
    })
    assert len(snapshot.interfaces) == 1
    assert snapshot.interfaces[0].interface_index == 1
    assert len(snapshot.interfaces[0].addresses) == 2
    assert snapshot.interfaces[0].mac is None


def test_switch_contract_is_typed_readonly_and_not_a_claim_of_real_device_support():
    from app.collectors.contracts import SwitchSnapshot
    snapshot = SwitchSnapshot.model_validate({
        "device_address": "10.0.0.1", "source": "snmpv3_readonly",
        "observed_at": "2026-11-15T12:00:00Z", "interfaces": [],
        "neighbors": [], "forwarding": [{"interface_index": 7, "vlan": 10,
                                       "mac": "00:11:22:33:44:55"}],
        "lldp": [],
    })
    assert snapshot.forwarding[0].vlan == 10
    assert snapshot.identity_verified is False
    with pytest.raises(ValidationError):
        SwitchSnapshot.model_validate({**snapshot.model_dump(),
                                       "forwarding": [{"interface_index": 7, "vlan": 5000, "mac": "bad"}]})


def test_mdns_names_only_for_approved_addresses_keep_service_instance_distinct():
    from app.collectors.mdns import names_for_scope
    result = names_for_scope([
        {"server": "workstation.local.", "name": "My App._http._tcp.local.",
         "addresses": ["10.0.0.10", "10.0.0.99"]},
        {"server": "outside.local.", "name": "Other", "addresses": ["10.0.0.99"]},
    ], {"10.0.0.10"})
    assert list(result) == ["10.0.0.10"]
    assert result["10.0.0.10"][0] == {
        "hostname": "workstation.local", "source": "mdns_server",
        "service_instance": "My App._http._tcp.local.",
    }


def test_vendor_database_is_local_existing_nmap_data_and_random_mac_is_not_a_brand(tmp_path):
    from app.discovery.nmap import lookup_mac_vendor
    binary = tmp_path / "nmap.exe"
    binary.touch()
    (tmp_path / "nmap-mac-prefixes").write_text(
        "# upstream database fixture\n001122\tExample NIC\n021122\tMust not use local MAC\n", encoding="utf-8")
    assert lookup_mac_vendor("00:11:22:33:44:55", str(binary))["name"] == "Example NIC"
    assert lookup_mac_vendor("00:11:22:33:44:55", str(binary))["device_brand_confirmed"] is False
    assert lookup_mac_vendor("02:11:22:33:44:55", str(binary)) is None
    assert lookup_mac_vendor("not-a-mac", str(binary)) is None
