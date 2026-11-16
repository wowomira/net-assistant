"""Scoped enrichment only: names, MAC resolution, HTTP/TLS and screenshots.

Nmap owns live port/service/OS scanning. The duplicate TCP/ICMP/banner scanner
is preserved in legacy_native and is never selected by this module.
"""

import asyncio
import ctypes
from ctypes import wintypes
import ipaddress
import os
import re
import socket
import ssl
import struct
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.discovery.config import ScanSettings, url_host
from app.discovery.types import ProbeResult, safe_text


class _Title(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inside, self.done, self.parts = False, False, []

    def handle_starttag(self, tag, attrs):
        if tag == "title" and not self.done:
            self.inside = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.inside, self.done = False, True

    def handle_data(self, data):
        if self.inside and not self.done:
            self.parts.append(data)


def _bounded_text(value, maximum_bytes):
    return safe_text(value, maximum_bytes).encode("utf-8")[:maximum_bytes].decode("utf-8", errors="ignore")


def redirect_summary(value):
    # Preserve the destination identity/path, never credentials/query tokens.
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        if parts.port:
            host += f":{parts.port}"
        if parts.netloc and not host:
            return None
        return _bounded_text(urlunsplit((parts.scheme, host, parts.path, "", "")), 256)
    except ValueError:
        return None


class SystemProbes:
    def __init__(self, settings: ScanSettings, source_network: str | None = None):
        self.settings = settings
        self.allowed = frozenset(settings.addresses())
        self.allowed_ports = frozenset(settings.effective_ports())
        self.local_network = ipaddress.ip_network(source_network) if source_network else None
        self.timeout = settings.timeout_ms / 1000
        self.local_addr = (settings.source_address, 0) if settings.source_address else None
        self.screenshot_collector = None
        transport = httpx.AsyncHTTPTransport(local_address=settings.source_address, verify=True, retries=0)
        self.client = httpx.AsyncClient(
            transport=transport, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(self.timeout), headers={"User-Agent": "NetAssistant-Inventory/0.2"},
        )

    def _guard(self, address, port=None):
        if address not in self.allowed or (port is not None and port not in self.allowed_ports):
            raise ValueError("Probe target is outside the configured authorized scope.")

    async def close(self):
        try:
            await self.client.aclose()
        finally:
            if self.screenshot_collector:
                await self.screenshot_collector.close()

    async def screenshot(self, address, port, https=False, artifact_directory=None):
        self._guard(address, port)
        if artifact_directory is None:
            return ProbeResult(address, "screenshot", "not_supported", port=port,
                               reason_code="screenshot_directory_missing")
        if self.screenshot_collector is None:
            from app.discovery.screenshots import ScreenshotCollector
            self.screenshot_collector = ScreenshotCollector(self.settings, artifact_directory)
        return await self.screenshot_collector.capture(address, port, https)

    async def name(self, address):
        self._guard(address)
        from app.discovery.names import resolve_name
        return await resolve_name(address, self.timeout, self.settings.source_address,
                                  self.settings.netbios_enabled and ipaddress.ip_address(address).version == 4)



    async def arp(self, address):
        self._guard(address)
        if (not self.settings.arp_enabled or os.name != "nt" or not self.local_network
                or ipaddress.IPv4Address(address) not in self.local_network):
            return ProbeResult(address, "arp", "not_applicable", reason_code="not_on_verified_local_link")
        return await asyncio.to_thread(self._arp_windows, address)

    def _arp_windows(self, address):
        started = time.perf_counter()
        api = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        api.SendARP.argtypes = [wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p,
                                ctypes.POINTER(wintypes.ULONG)]
        api.SendARP.restype = wintypes.DWORD
        buffer = (wintypes.ULONG * 2)()
        size = wintypes.ULONG(ctypes.sizeof(buffer))
        destination = struct.unpack("=I", socket.inet_aton(address))[0]
        source = struct.unpack("=I", socket.inet_aton(self.settings.source_address or "0.0.0.0"))[0]
        code = api.SendARP(destination, source, buffer, ctypes.byref(size))
        elapsed = (time.perf_counter() - started) * 1000
        if code == 0 and 0 < size.value <= ctypes.sizeof(buffer):
            mac = ":".join(f"{byte:02X}" for byte in bytes(buffer)[:size.value])
            # SendARP 可能命中缓存，只保存解析事实；在线判断另需直接响应。
            return ProbeResult(address, "arp", "resolved", elapsed,
                               evidence={"mac": mac, "cachePossible": True,
                                         "source": "windows_send_arp"})
        status = "no_response" if code in (31, 67) else "error"
        return ProbeResult(address, "arp", status, elapsed, reason_code=f"windows_{code}",
                           evidence={"windowsError": code})

    async def _open(self, address, port, **kwargs):
        return await asyncio.wait_for(
            asyncio.open_connection(address, port, local_addr=self.local_addr, **kwargs),
            timeout=self.timeout,
        )

    @staticmethod
    async def _close(writer):
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except (OSError, TimeoutError):
            pass


    async def http(self, address, port, https=False):
        self._guard(address, port)
        started = time.perf_counter()
        url = f"{'https' if https else 'http'}://{url_host(address)}:{port}/"
        try:
            async with asyncio.timeout(self.timeout + 0.25):
                # Read only a bounded HTML prefix; never execute scripts or reuse cookies.
                async with self.client.stream("GET", url, headers={"Cookie": "", "Accept-Encoding": "identity"}) as response:
                    headers = {key: _bounded_text(response.headers[key], 100) for key in
                               ("server", "content-type", "content-length", "allow")
                               if key in response.headers}
                    body = bytearray()
                    truncated = False
                    is_html = "html" in response.headers.get("content-type", "").lower()
                    supported_encoding = response.headers.get("content-encoding", "identity").lower() in ("", "identity")
                    if is_html and not response.is_redirect and supported_encoding:
                        async for chunk in response.aiter_bytes(4096):
                            remaining = self.settings.http_body_limit - len(body)
                            body.extend(chunk[:remaining])
                            if len(chunk) > remaining or len(body) >= self.settings.http_body_limit:
                                truncated = True
                                break
                    parser = _Title()
                    parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))
                    title_text = " ".join("".join(parser.parts).split())
                    title = _bounded_text(title_text, 320) or None
                    return ProbeResult(
                        address, "http", "response", (time.perf_counter() - started) * 1000,
                        port, evidence={"scheme": "https" if https else "http",
                                        "url": url, "path": "/", "requestMethod": "GET",
                                        "statusCode": response.status_code, "headers": headers,
                                        "title": title, "redirectLocation": redirect_summary(
                                            response.headers.get("location", "")) or None,
                                        "titleTruncated": bool(title_text and title != title_text),
                                        "followedRedirect": False, "bodyCollected": bool(body),
                                        "bodyBytesRead": len(body), "bodyTruncated": truncated,
                                        "bodySkippedReason": None if supported_encoding else "unsupported_content_encoding",
                                        "bodyStored": False},
                    )
        except (httpx.TimeoutException, TimeoutError):
            status, reason = "timeout", "http_timeout"
        except httpx.ConnectError as error:
            status = "certificate_error" if "CERTIFICATE_VERIFY_FAILED" in str(error) else "error"
            reason = "tls_verification_failed" if status == "certificate_error" else "http_connect_error"
        except httpx.HTTPError:
            status, reason = "error", "http_protocol_error"
        return ProbeResult(address, "http", status, (time.perf_counter() - started) * 1000,
                           port, reason, {"scheme": "https" if https else "http", "url": url})

    async def tls(self, address, port):
        self._guard(address, port)
        started = time.perf_counter()
        writer = None
        try:
            _, writer = await self._open(
                address, port, ssl=ssl.create_default_context(), server_hostname=address,
                ssl_handshake_timeout=self.timeout,
            )
            connection = writer.get_extra_info("ssl_object")
            certificate = connection.getpeercert()
            return ProbeResult(address, "tls", "verified", (time.perf_counter() - started) * 1000,
                               port, evidence={"tlsVersion": connection.version(),
                                               "cipher": connection.cipher(),
                                               "subject": certificate.get("subject"),
                                               "issuer": certificate.get("issuer"),
                                               "notBefore": certificate.get("notBefore"),
                                               "notAfter": certificate.get("notAfter"),
                                               "subjectAltName": certificate.get("subjectAltName"),
                                               "verification": "passed"})
        except ssl.SSLCertVerificationError as error:
            return ProbeResult(address, "tls", "certificate_error",
                               (time.perf_counter() - started) * 1000, port,
                               "tls_verification_failed",
                               {"verifyCode": error.verify_code, "verification": "failed"})
        except TimeoutError:
            return ProbeResult(address, "tls", "timeout", (time.perf_counter() - started) * 1000,
                               port, "tls_timeout")
        except (OSError, ssl.SSLError):
            return ProbeResult(address, "tls", "error", (time.perf_counter() - started) * 1000,
                               port, "tls_handshake_error")
        finally:
            if writer is not None:
                await self._close(writer)

