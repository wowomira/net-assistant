"""SNMPv3 authPriv only; bounded numeric GET/GETBULK, never SET."""
import asyncio
import ipaddress
import time

from app.discovery.types import utc_now
from app.switches import projection as mib


class SnmpFailure(RuntimeError):
    """Only fixed codes may leave the protocol boundary; never raw library errors."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _check(error, status):
    if error:
        from pysnmp.proto import errind
        if isinstance(error, errind.RequestTimedOut):
            raise SnmpFailure("snmp_timeout")
        if isinstance(error, (errind.UnknownUserName, errind.AuthenticationFailure,
                              errind.AuthenticationError, errind.DecryptionError)):
            raise SnmpFailure("snmp_authentication_failed")
        raise SnmpFailure("snmp_protocol_error")
    if status:
        raise SnmpFailure("snmp_access_denied" if int(status) in (6, 16) else "snmp_agent_error")


def _value(value):
    from pyasn1.type import univ
    from pysnmp.proto import rfc1905
    if isinstance(value, (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)):
        return None
    if isinstance(value, univ.ObjectIdentifier):
        return str(value)
    if isinstance(value, univ.OctetString):
        return bytes(value.asOctets())
    try:
        return int(value)
    except (TypeError, ValueError):
        raise SnmpFailure("snmp_invalid_value")


class Session:
    async def open(self, address, profile, secrets, plan):
        from pysnmp.hlapi.v3arch import asyncio as snmp
        self.snmp = snmp
        self.engine = snmp.SnmpEngine()
        self.auth = snmp.UsmUserData(
            profile.username,
            secrets.auth_key.get_secret_value(), secrets.priv_key.get_secret_value(),
            authProtocol={"SHA": snmp.USM_AUTH_HMAC96_SHA,
                          "SHA256": snmp.USM_AUTH_HMAC192_SHA256,
                          "SHA512": snmp.USM_AUTH_HMAC384_SHA512}[profile.auth_protocol],
            privProtocol=snmp.USM_PRIV_CFB128_AES,
        )
        transport = snmp.Udp6TransportTarget if ipaddress.ip_address(address).version == 6 else snmp.UdpTransportTarget
        try:
            self.target = await transport.create((address, plan.port), timeout=plan.timeout_seconds, retries=0)
            self.context = snmp.ContextData(contextName=profile.context_name)
            self.max_rows = plan.max_rows
        except BaseException:
            self.close()
            raise
        return self

    async def get(self, oids):
        s = self.snmp
        error, status, _, rows = await s.get_cmd(
            self.engine, self.auth, self.target, self.context,
            *(s.ObjectType(s.ObjectIdentity(oid)) for oid in oids), lookupMib=False)
        _check(error, status)
        return {str(oid): _value(value) for oid, value in rows}

    async def walk(self, root):
        s = self.snmp
        prefix, current, result = tuple(map(int, root.split("."))), root, {}
        while True:
            error, status, _, rows = await s.bulk_cmd(
                self.engine, self.auth, self.target, self.context, 0, 25,
                s.ObjectType(s.ObjectIdentity(current)), lookupMib=False)
            _check(error, status)
            if not rows:
                return result, False
            previous = tuple(map(int, current.split(".")))
            for oid, value in rows:
                index = tuple(oid)
                normalized = _value(value)
                if index[:len(prefix)] != prefix or normalized is None:
                    return result, False
                if index <= previous:
                    raise SnmpFailure("snmp_oid_not_increasing")
                previous, current = index, str(oid)
                if len(result) >= self.max_rows:
                    return result, True
                result[".".join(map(str, index[len(prefix):]))] = normalized

    def close(self):
        if getattr(self, "engine", None) is not None:
            self.engine.close_dispatcher()


async def collect_switch(address, profile, secrets, plan, *, session_factory=Session):
    session = session_factory()
    try:
        await session.open(address, profile, secrets, plan)
        raw = await session.get(list(mib.SYSTEM.values()))
        object_id = raw.get(mib.SYSTEM["objectId"])
        if not mib.is_ruijie(object_id):
            raise SnmpFailure("not_ruijie_device")
        # sysObjectID is evidence of reported enterprise, not authenticated asset identity.
        snapshot = {
            "source": "snmpv3_readonly", "observedAt": utc_now(),
            "identityVerified": False, "vendor": "Ruijie",
            "vendorEvidence": {"source": "sysObjectID", "enterprise": 4881},
            "system": {key: mib.text(raw.get(oid)) for key, oid in mib.SYSTEM.items() if key != "uptime"},
            "interfaces": [], "forwarding": [], "lldp": [], "capabilities": {},
        }
        uptime = mib.number(raw.get(mib.SYSTEM["uptime"]))
        snapshot["system"]["uptimeSeconds"] = uptime / 100 if uptime is not None else None
        deadline = time.monotonic() + plan.target_budget_seconds

        async def column(oid):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {}, {"state": "not_collected", "reasonCode": "collection_budget_exceeded"}
            try:
                values, limited = await asyncio.wait_for(session.walk(oid), timeout=remaining)
                return values, {
                    "state": "limited" if limited else "available" if values else "no_data",
                    "reasonCode": "row_limit" if limited else None if values else "empty_or_not_exposed",
                }
            except TimeoutError:
                return {}, {"state": "failed", "reasonCode": "collection_budget_exceeded"}
            except SnmpFailure as error:
                return {}, {"state": "failed", "reasonCode": error.code}

        async def table(name, oids):
            values, states = {}, {}
            for key, oid in oids.items():
                values[key], states[key] = await column(oid)
            states_list = [row["state"] for row in states.values()]
            state = ("partial" if any(value in ("failed", "limited", "not_collected") for value in states_list)
                     else "available" if any(values.values()) else "no_data")
            snapshot["capabilities"][name] = {"state": state, "columns": states}
            return values

        interfaces = await table("interfaces", mib.IF)
        snapshot["interfaces"] = mib.project_interfaces(interfaces)
        forwarding = await table("forwarding", {
            "ports": mib.Q_PORT, "statuses": mib.Q_STATUS,
            "bridgeMap": mib.BRIDGE_MAP, "vlanFdb": mib.VLAN_FDB})
        vlan_aware = bool(forwarding["ports"])
        if not vlan_aware:
            # A standard bridge table can still be useful; no guessed VLAN 1.
            fallback = await table("bridgeForwarding", {"ports": mib.DOT_PORT, "statuses": mib.DOT_STATUS})
            forwarding.update(ports=fallback["ports"], statuses=fallback["statuses"])
        snapshot["forwarding"] = mib.project_forwarding(
            forwarding["ports"], forwarding["statuses"], forwarding["bridgeMap"],
            forwarding["vlanFdb"], vlan_aware=vlan_aware)
        snapshot["lldp"] = mib.project_lldp(await table("lldp", mib.LLDP))
        snapshot["observedAt"] = utc_now()
        return snapshot
    except (SnmpFailure, asyncio.CancelledError):
        raise
    except Exception:
        raise SnmpFailure("snmp_collection_failed") from None
    finally:
        session.close()
