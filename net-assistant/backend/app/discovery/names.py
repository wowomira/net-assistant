"""Bounded reverse lookup / unicast NBSTAT; no host configuration file access."""
import asyncio
import ipaddress
import os
import socket
import struct
import time

from app.discovery.types import ProbeResult, safe_text


def _skip_name(data, offset):
    for _ in range(128):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise ValueError("Short NBNS pointer")
            return offset + 2
        if length > 63:
            raise ValueError("Invalid NBNS label")
        offset += 1
        if length == 0:
            return offset
        offset += length
        if offset > len(data):
            raise ValueError("Short NBNS label")
    raise ValueError("Long NBNS name")


def parse_nbstat(data: bytes, transaction: int) -> str | None:
    """Accept only a matching, positive NBSTAT response and a unique host name."""
    if len(data) < 12:
        return None
    identifier, flags, questions, answers, _, _ = struct.unpack_from("!6H", data)
    if identifier != transaction or flags & 0xF80F != 0x8000 or questions > 16 or answers > 16:
        return None
    try:
        offset = 12
        for _ in range(questions):
            offset = _skip_name(data, offset) + 4
        for _ in range(answers):
            offset = _skip_name(data, offset)
            kind, cls, _, size = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            end = offset + size
            if end > len(data):
                return None
            if kind == 0x21 and cls == 1 and size:
                count = data[offset]
                if 1 + count * 18 > size:
                    return None
                for index in range(count):
                    start = offset + 1 + index * 18
                    raw, suffix, name_flags = struct.unpack_from("!15sBH", data, start)
                    if suffix in (0, 0x20) and not name_flags & 0x8000:
                        name = raw.decode("ascii", errors="replace").strip(" \0")
                        if name and name != "*":
                            return safe_text(name, 63)
            offset = end
    except (IndexError, struct.error, ValueError):
        return None
    return None


async def _nbstat(address, timeout, source):
    transaction = int.from_bytes(os.urandom(2), "big")
    wildcard = b"*" + b"\0" * 15
    encoded = bytes(value for byte in wildcard for value in (65 + (byte >> 4), 65 + (byte & 15)))
    packet = struct.pack("!6H", transaction, 0, 1, 0, 0, 0) + b"\x20" + encoded + b"\0\x00\x21\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        sock.bind((source or "0.0.0.0", 0))
        sock.connect((address, 137))  # Connected UDP rejects other response endpoints.
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(timeout):
            await loop.sock_sendall(sock, packet)
            return parse_nbstat(await loop.sock_recv(sock, 2048), transaction)


async def resolve_name(address, timeout, source=None, netbios=True):
    started = time.perf_counter()
    attempts = []
    try:
        hostname, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, address), timeout=timeout)
        hostname = safe_text(hostname.rstrip("."), 253)
        try:
            ipaddress.ip_address(hostname)
            hostname = ""
        except ValueError:
            pass
        if hostname:
            return ProbeResult(address, "name", "resolved",
                               (time.perf_counter() - started) * 1000,
                               evidence={"hostname": hostname, "source": "system_reverse_lookup"})
    except (OSError, TimeoutError):
        attempts.append("system_reverse_lookup_unavailable")
    if netbios:
        try:
            hostname = await _nbstat(address, timeout, source)
            if hostname:
                return ProbeResult(address, "name", "resolved",
                                   (time.perf_counter() - started) * 1000,
                                   evidence={"hostname": hostname, "source": "netbios_node_status"})
            attempts.append("netbios_no_name")
        except (OSError, TimeoutError):
            attempts.append("netbios_unavailable")
    return ProbeResult(address, "name", "no_response",
                       (time.perf_counter() - started) * 1000,
                       reason_code="hostname_unavailable", evidence={"attempts": attempts})
