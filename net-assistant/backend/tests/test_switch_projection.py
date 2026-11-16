"""MIB rows are synthetic protocol fixtures, never imported by production."""


def test_interfaces_use_real_ifindex_and_64bit_counters_without_fabricated_speed():
    from app.switches.projection import project_interfaces, IF
    columns = {name: {} for name in IF}
    columns["name"] = {"7": "Gi0/7"}
    columns["description"] = {"7": "GigabitEthernet 0/7"}
    columns["type"] = {"7": 6}
    columns["adminStatus"] = {"7": 1}
    columns["operStatus"] = {"7": 2}
    columns["mac"] = {"7": b"\x00\x11\x22\x33\x44\x55"}
    columns["inOctets"] = {"7": 2**54 + 1}
    columns["speedMbps"] = {"7": 1000}
    rows = project_interfaces(columns)
    assert rows[0]["ifIndex"] == 7
    assert rows[0]["operStatus"] == "down"
    assert rows[0]["inOctets"] == str(2**54 + 1)  # lossless JavaScript transfer
    assert rows[0]["outOctets"] is None
    assert rows[0]["speedMbps"] == 1000
    assert rows[0]["mac"] == "00:11:22:33:44:55"


def test_qbridge_fdb_id_is_not_assumed_to_be_vlan_and_bridge_port_is_mapped():
    from app.switches.projection import project_forwarding
    suffix = "400.0.17.34.51.68.85"
    rows = project_forwarding(
        {suffix: 3}, {suffix: 3}, {"3": 107},
        {"0.20": 400, "0.30": 400}, vlan_aware=True,
    )
    assert rows == [{
        "mac": "00:11:22:33:44:55", "bridgePort": 3, "ifIndex": 107,
        "fdbId": 400, "vlanIds": [20, 30], "status": "learned",
        "source": "Q-BRIDGE-MIB",
    }]
    unknown = project_forwarding({suffix: 3}, {}, {}, {}, vlan_aware=True)[0]
    assert unknown["vlanIds"] == []
    assert unknown["ifIndex"] is None


def test_lldp_preserves_remote_ids_and_local_port_mapping_is_not_guessed():
    from app.switches.projection import project_lldp
    rows = project_lldp({
        "chassisId": {"0.5.2": b"\x00\x11\x22\x33\x44\x55"},
        "chassisSubtype": {"0.5.2": 4}, "portId": {"0.5.2": "Gi0/1"},
        "portSubtype": {"0.5.2": 5}, "systemName": {"0.5.2": "test-peer"},
    })
    assert rows[0]["localPortNumber"] == 5
    assert rows[0]["localIfIndex"] is None
    assert rows[0]["remoteChassisId"] == "00:11:22:33:44:55"
    assert rows[0]["remoteSystemName"] == "test-peer"


def test_ruijie_identity_requires_numeric_enterprise_boundary():
    from app.switches.projection import is_ruijie
    assert is_ruijie("1.3.6.1.4.1.4881.1.1.10.1.1")
    assert not is_ruijie("1.3.6.1.4.1.48810.1")
    assert not is_ruijie("Ruijie")


def test_vendor_enterprise_alone_does_not_confirm_switch_product_family():
    from app.switches.projection import device_kind
    assert device_kind("1.3.6.1.4.1.4881.1.1.10.1.999") == "switch_product"
    assert device_kind("1.3.6.1.4.1.4881.1.999") == "unverified_network_device"
    assert device_kind("1.3.6.1.4.1.4881.1.1.10.10.1") == "unverified_network_device"
