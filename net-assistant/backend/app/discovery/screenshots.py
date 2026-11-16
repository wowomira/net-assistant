"""Optional, noninteractive static previews; all browser network I/O is mediated.

Only GETs for the exact scanned origin are fetched, using httpx with TLS checks
and no cookies/proxy inheritance. Scripts, workers, frames, redirects and
cross-origin requests are blocked. A preview is not a functional browser test.
"""
import asyncio
import ipaddress
import os
from pathlib import Path
import time
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from app.discovery.types import ProbeResult


class ScreenshotCollector:
    def __init__(self, settings, directory):
        self.settings = settings
        self.directory = Path(directory)
        self.allowed = frozenset(settings.addresses())
        self.ports = frozenset(settings.effective_ports())
        self._driver = None
        self._browser = None

    @staticmethod
    def _playwright():
        try:
            from playwright.async_api import async_playwright
            return async_playwright
        except ImportError:
            return None

    def permits_resource(self, url, origin):
        def endpoint(value):
            parts = urlsplit(value)
            if parts.scheme not in ("http", "https") or parts.username or parts.password:
                return None
            address = str(ipaddress.IPv4Address(parts.hostname))
            port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
            if address not in self.allowed or port not in self.ports:
                return None
            return parts.scheme, address, port
        try:
            expected = endpoint(origin)
            return expected is not None and endpoint(url) == expected
        except (ValueError, TypeError):
            return False

    async def close(self):
        try:
            if self._browser is not None:
                await self._browser.close()
        finally:
            self._browser = None
            if self._driver is not None:
                await self._driver.stop()
                self._driver = None

    async def capture(self, address, port, https=False):
        scheme = "https" if https else "http"
        url = f"{scheme}://{address}:{port}/"
        if not self.permits_resource(url, url):
            raise ValueError("Screenshot target is outside the configured authorized scope.")
        started = time.perf_counter()
        evidence = {"scheme": scheme, "url": url, "javascriptEnabled": False,
                    "renderMode": "static_no_javascript", "blockedRequests": 0,
                    "renderIncomplete": True}

        def result(status, reason=None):
            return ProbeResult(address, "screenshot", status,
                               (time.perf_counter() - started) * 1000, port, reason, dict(evidence))

        factory = self._playwright()
        if factory is None:
            return result("not_supported", "screenshot_dependency_missing")
        context = None
        root_failure = None
        resource_failures = 0
        total_bytes = 0
        request_count = 0
        transport = httpx.AsyncHTTPTransport(local_address=self.settings.source_address, verify=True, retries=0)
        try:
            async with asyncio.timeout(self.settings.screenshot_timeout_ms / 1000):
                if self._browser is None:
                    from app.runtime_tools import browser_launch_options
                    self._driver = await factory().start()
                    self._browser = await self._driver.chromium.launch(
                        **browser_launch_options(),
                        headless=True,
                        # Browser never connects to targets directly, including background I/O.
                        args=["--disable-background-networking", "--disable-component-update",
                              "--proxy-server=http://127.0.0.1:9", "--proxy-bypass-list=<-loopback>"],
                    )
                context = await self._browser.new_context(
                    java_script_enabled=False, service_workers="block", accept_downloads=False,
                    viewport={"width": 1280, "height": 800}, device_scale_factor=1,
                )
                async with httpx.AsyncClient(transport=transport, trust_env=False,
                                             follow_redirects=False, timeout=self.settings.timeout_ms / 1000,
                                             headers={"User-Agent": "NetAssistant-Preview/0.6",
                                                      "Cookie": "", "Accept-Encoding": "identity"}) as client:
                    async def route_request(route):
                        nonlocal total_bytes, request_count, root_failure, resource_failures
                        request = route.request
                        root = request.is_navigation_request()
                        request_count += 1
                        permitted = (request.method == "GET" and self.permits_resource(request.url, url)
                                     and request.resource_type in ("document", "stylesheet", "image", "font")
                                     and (not root or request.url == url)
                                     and request_count <= 32)
                        if not permitted:
                            evidence["blockedRequests"] += 1
                            await route.abort()
                            return
                        try:
                            async with client.stream("GET", request.url) as response:
                                if response.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
                                    if root:
                                        root_failure = "screenshot_compressed_response_unsupported"
                                    resource_failures += 1
                                    await route.abort()
                                    return
                                if response.is_redirect:
                                    if root:
                                        root_failure = "screenshot_redirect_not_followed"
                                    evidence["blockedRequests"] += 1
                                    await route.abort()
                                    return
                                if root and "html" not in response.headers.get("content-type", "").lower():
                                    root_failure = "screenshot_non_html_response"
                                    await route.abort()
                                    return
                                body = bytearray()
                                async for chunk in response.aiter_bytes(16384):
                                    total_bytes += len(chunk)
                                    if len(body) + len(chunk) > 1024 * 1024 or total_bytes > 4 * 1024 * 1024:
                                        if root:
                                            root_failure = "screenshot_resource_limit"
                                        resource_failures += 1
                                        await route.abort()
                                        return
                                    body.extend(chunk)
                                headers = {"content-type": response.headers.get("content-type", "application/octet-stream"),
                                           "content-security-policy": "sandbox allow-same-origin; script-src 'none'; "
                                           "connect-src 'none'; frame-src 'none'; form-action 'none'; "
                                           "object-src 'none'; base-uri 'none'"}
                                await route.fulfill(status=response.status_code, headers=headers, body=bytes(body))
                        except (httpx.HTTPError, TimeoutError):
                            if root:
                                root_failure = "screenshot_http_fetch_failed"
                            resource_failures += 1
                            await route.abort()

                    await context.route("**/*", route_request)
                    page = await context.new_page()
                    await page.goto(url, wait_until="load",
                                    timeout=self.settings.screenshot_timeout_ms)
                    # Only the first viewport: no scrolling, clicks, logins or DOM scripts.
                    png = await page.screenshot(type="png", full_page=False, animations="disabled",
                                                timeout=self.settings.screenshot_timeout_ms)
                if not png.startswith(b"\x89PNG\r\n\x1a\n"):
                    return result("error", "screenshot_invalid_png")
                filename = uuid4().hex + ".png"
                self.directory.mkdir(parents=True, exist_ok=True)
                with (self.directory / filename).open("xb") as output:
                    output.write(png)
                evidence.update(file=filename, width=1280, height=800,
                                bytesCollected=total_bytes, failedResources=resource_failures)
                # Scripts are intentionally disabled even when no resources were blocked.
                return result("captured")
        except TimeoutError:
            return result("timeout", "screenshot_timeout")
        except Exception as error:
            evidence["exceptionType"] = type(error).__name__
            if root_failure:
                return result("blocked", root_failure)
            if self._browser is None:
                return result("not_supported", "screenshot_browser_unavailable")
            return result("error", "screenshot_capture_failed")
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
