"""Archived custom scanner probes. Not imported by live entry points.

Kept for historical regression tests and recovery only; do not select at runtime.
The shared base still owns scoped HTTP/TLS/name/ARP enrichment.
"""
import asyncio
import ctypes
from ctypes import wintypes
import errno
import os
import re
import socket
import struct
import time

from app.discovery.probes import SystemProbes
from app.discovery.types import ProbeResult, safe_text


class LegacySystemProbes(SystemProbes):
    async def icmp(self, address):
        self._guard(address)
        if not self.settings.icmp_enabled or os.name != "nt":
            return ProbeResult(address, "icmp", "not_supported", reason_code="icmp_not_enabled_or_supported")
        return await asyncio.to_thread(self._icmp_windows, address)


    def _icmp_windows(self, address):
        started = time.perf_counter()
        api = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        api.IcmpCreateFile.restype = wintypes.HANDLE
        api.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        api.IcmpCloseHandle.restype = wintypes.BOOL
        if self.settings.source_address:
            send = api.IcmpSendEcho2Ex
            send.argtypes = [
                wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ]
        else:
            send = api.IcmpSendEcho
            send.argtypes = [
                wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
                ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ]
        send.restype = wintypes.DWORD
        handle = api.IcmpCreateFile()
        if handle in (None, ctypes.c_void_p(-1).value):
            return ProbeResult(address, "icmp", "error", reason_code="icmp_handle_error",
                               evidence={"windowsError": ctypes.get_last_error()})
        try:
            data = ctypes.create_string_buffer(b"net-assistant")
            replies = ctypes.create_string_buffer(2048)
            destination = struct.unpack("=I", socket.inet_aton(address))[0]
            if self.settings.source_address:
                source_address = struct.unpack("=I", socket.inet_aton(self.settings.source_address))[0]
                count = send(handle, None, None, None, source_address, destination,
                             data, len(data) - 1, None, replies, len(replies),
                             self.settings.timeout_ms)
            else:
                count = send(handle, destination, data, len(data) - 1, None,
                             replies, len(replies), self.settings.timeout_ms)
            elapsed = (time.perf_counter() - started) * 1000
            if count:
                # The address/status/RTT prefix is identical in native and 32-bit echo replies.
                reply_address, status, rtt = struct.unpack_from("=III", replies.raw)
                source = socket.inet_ntoa(struct.pack("=I", reply_address))
                valid_reply = status == 0 and source == address
                return ProbeResult(
                    address, "icmp", "reply" if valid_reply else "no_response", elapsed,
                    reason_code=None if valid_reply else f"ip_status_{status}",
                    evidence={"replyAddress": source, "ipStatus": status, "roundTripMs": rtt},
                )
            error = ctypes.get_last_error()
            return ProbeResult(address, "icmp", "timeout" if error == 11010 else "no_response",
                               elapsed, reason_code=f"windows_{error}", evidence={"windowsError": error})
        finally:
            api.IcmpCloseHandle(handle)


    async def tcp(self, address, port):
        self._guard(address, port)
        started = time.perf_counter()
        try:
            _, writer = await self._open(address, port)
            await self._close(writer)
            return ProbeResult(address, "tcp", "open", (time.perf_counter() - started) * 1000, port)
        except TimeoutError:
            return ProbeResult(address, "tcp", "timeout", (time.perf_counter() - started) * 1000,
                               port, "connect_timeout")
        except OSError as error:
            code = getattr(error, "winerror", None) or error.errno
            status = "refused" if code in (10061, errno.ECONNREFUSED) else "unreachable" if code in (
                10051, 10065, errno.ENETUNREACH, errno.EHOSTUNREACH,
            ) else "error"
            return ProbeResult(address, "tcp", status, (time.perf_counter() - started) * 1000,
                               port, f"socket_{code}", {"socketError": code})


    async def banner(self, address, port):
        self._guard(address, port)
        started = time.perf_counter()
        writer = None
        try:
            reader, writer = await self._open(address, port)
            data = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
            evidence = {"banner": safe_text(data.decode("utf-8", errors="replace")),
                        "sentApplicationData": False, "maximumBytes": 512}
            # MySQL's initial protocol-v10 packet is server-initiated. Do not retain
            # its per-connection authentication challenge or mistake a port for proof.
            if (len(data) >= 20 and data[3:5] == b"\x00\x0a"
                    and 16 <= int.from_bytes(data[:3], "little") <= len(data) - 4):
                raw_version = data[5:].split(b"\x00", 1)[0]
                if re.fullmatch(rb"[0-9][\x20-\x7e]{0,79}", raw_version):
                    version = raw_version.decode("ascii")
                    evidence.update(protocol="mysql", product="MariaDB" if "MariaDB" in version else "MySQL-compatible",
                                    version=version, banner=f"MySQL protocol 10; server version {version}")
            return ProbeResult(address, "banner", "received" if data else "empty",
                               (time.perf_counter() - started) * 1000, port,
                               evidence=evidence)
        except TimeoutError:
            return ProbeResult(address, "banner", "timeout", (time.perf_counter() - started) * 1000,
                               port, "banner_timeout")
        except OSError:
            return ProbeResult(address, "banner", "error", (time.perf_counter() - started) * 1000,
                               port, "banner_connection_error")
        finally:
            if writer is not None:
                await self._close(writer)


