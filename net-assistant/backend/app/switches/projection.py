"""Numeric standard MIBs, no runtime MIB downloads or inferred physical port order.

References: RFC 2863 (IF-MIB), RFC 4188 (BRIDGE-MIB), RFC 4363 (Q-BRIDGE-MIB),
IEEE 802.1AB LLDP-MIB. IANA enterprise registry assigns 4881 to Ruijie.
"""
from app.discovery.types import safe_text

SYSTEM = {
    "description": "1.3.6.1.2.1.1.1.0",
    "objectId": "1.3.6.1.2.1.1.2.0",
    "uptime": "1.3.6.1.2.1.1.3.0",
    "name": "1.3.6.1.2.1.1.5.0",
    "location": "1.3.6.1.2.1.1.6.0",
}
IF = {
    "description": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3",
    "mac": "1.3.6.1.2.1.2.2.1.6", "adminStatus": "1.3.6.1.2.1.2.2.1.7",
    "operStatus": "1.3.6.1.2.1.2.2.1.8", "name": "1.3.6.1.2.1.31.1.1.1.1",
    "inOctets": "1.3.6.1.2.1.31.1.1.1.6", "outOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "speedMbps": "1.3.6.1.2.1.31.1.1.1.15", "alias": "1.3.6.1.2.1.31.1.1.1.18",
}
BRIDGE_MAP = "1.3.6.1.2.1.17.1.4.1.2"
Q_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
Q_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
VLAN_FDB = "1.3.6.1.2.1.17.7.1.4.2.1.3"
DOT_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
LLDP = {
    "chassisSubtype": "1.0.8802.1.1.2.1.4.1.1.4",
    "chassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "portSubtype": "1.0.8802.1.1.2.1.4.1.1.6",
    "portId": "1.0.8802.1.1.2.1.4.1.1.7",
    "systemName": "1.0.8802.1.1.2.1.4.1.1.9",
}


def text(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return safe_text(str(value), 512)


def number(value):
    try:
        return int(value)
    except (ValueError, TypeError, OverflowError):
        return None


def mac(value):
    if isinstance(value, bytes) and len(value) == 6:
        return ":".join(f"{part:02X}" for part in value)
    return None


def is_ruijie(object_id):
    value = str(object_id).strip(".")
    return value == "1.3.6.1.4.1.4881" or value.startswith("1.3.6.1.4.1.4881.")


def device_kind(object_id):
    # Manufacturer RUIJIE-SMI assigns ruijieSwitchProducts to this subtree.
    # Enterprise 4881 alone also includes other device families; do not call them switches.
    value = str(object_id).strip(".")
    root = "1.3.6.1.4.1.4881.1.1.10.1"
    return "switch_product" if value.startswith(root + ".") else "unverified_network_device"


def project_interfaces(columns):
    indexes = {suffix for values in columns.values() for suffix in values if suffix.isdecimal()}
    result = []
    for index in sorted(indexes, key=int):
        row = {key: values.get(index) for key, values in columns.items()}
        result.append({
            "ifIndex": int(index), "name": text(row.get("name")),
            "description": text(row.get("description")), "alias": text(row.get("alias")),
            "ifType": number(row.get("type")), "mac": mac(row.get("mac")),
            "adminStatus": {1: "up", 2: "down", 3: "testing"}.get(number(row.get("adminStatus")), "unknown"),
            "operStatus": {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant",
                           6: "not_present", 7: "lower_layer_down"}.get(number(row.get("operStatus")), "unknown"),
            "speedMbps": number(row.get("speedMbps")),
            # Counter64 must be strings: JavaScript Number loses precision above 2**53.
            "inOctets": str(number(row["inOctets"])) if number(row.get("inOctets")) is not None else None,
            "outOctets": str(number(row["outOctets"])) if number(row.get("outOctets")) is not None else None,
        })
    return result


def project_forwarding(ports, statuses, bridge_map, vlan_fdb, *, vlan_aware):
    vlans = {}
    for suffix, value in vlan_fdb.items():
        parts = suffix.split(".")
        if len(parts) == 2 and all(part.isdecimal() for part in parts):
            vlan, fdb = int(parts[1]), number(value)
            if 1 <= vlan <= 4094 and fdb is not None:
                vlans.setdefault(fdb, set()).add(vlan)
    result = []
    for suffix, port_value in ports.items():
        parts = suffix.split(".")
        if len(parts) != (7 if vlan_aware else 6) or not all(part.isdecimal() for part in parts):
            continue
        octets = [int(part) for part in parts[-6:]]
        if any(part > 255 for part in octets):
            continue
        port = number(port_value)
        fdb = int(parts[0]) if vlan_aware else None
        result.append({
            "mac": ":".join(f"{part:02X}" for part in octets),
            "bridgePort": port, "ifIndex": number(bridge_map.get(str(port))),
            "fdbId": fdb, "vlanIds": sorted(vlans.get(fdb, set())),
            "status": {1: "other", 2: "invalid", 3: "learned", 4: "self", 5: "mgmt"}.get(
                number(statuses.get(suffix)), "unknown"),
            "source": "Q-BRIDGE-MIB" if vlan_aware else "BRIDGE-MIB",
        })
    return result


def project_lldp(columns):
    result = []
    for suffix, value in columns.get("chassisId", {}).items():
        parts = suffix.split(".")
        if len(parts) != 3 or not all(part.isdecimal() for part in parts):
            continue
        get = lambda key: columns.get(key, {}).get(suffix)
        result.append({
            "localPortNumber": int(parts[1]), "localIfIndex": None,
            "remoteIndex": int(parts[2]),
            "remoteChassisId": mac(value) if number(get("chassisSubtype")) == 4 else text(value),
            "remoteChassisSubtype": number(get("chassisSubtype")),
            "remotePortId": mac(get("portId")) if number(get("portSubtype")) == 3 else text(get("portId")),
            "remotePortSubtype": number(get("portSubtype")),
            "remoteSystemName": text(get("systemName")),
        })
    return result
