"""Archived native scanner, retained only for historical regression/recovery."""
import asyncio
from dataclasses import replace
from typing import Callable

from app.discovery.concurrency import _pool
from app.discovery.config import ScanSettings
from app.discovery.store import Database
from app.discovery.types import ProbeResult




async def run_discovery(
    settings: ScanSettings, db: Database, probes,
    progress: Callable | None = None,
    *, trigger="manual", schedule_run_id=None,
) -> str:
    addresses = settings.addresses()
    ports = settings.effective_ports()
    scope_id, revision = db.save_scope(settings)
    job_id = db.begin_job(scope_id, revision, settings.snapshot(), trigger, schedule_run_id)
    coverage = {
        "candidateAddresses": len(addresses), "completedDiscoveryAddresses": 0,
        "discoveredCandidates": 0, "responsiveHosts": 0, "configuredTcpPorts": len(ports),
        "expectedTcpChecks": len(addresses) * len(ports), "completedTcpChecks": 0,
        "serviceEvidenceChecks": 0, "probeErrors": 0,
        "expectedServiceEvidenceChecks": 0,
        "nameChecks": 0, "screenshotChecks": 0, "inventoryPolicy": "all_authorized_addresses",
    }
    hosts = {}
    confirmed = set()
    discovery_tcp = {}
    checked_names = set()
    screenshot_lock = asyncio.Lock()
    web_ports = set(settings.http_ports + settings.https_ports)
    non_banner_ports = web_ports | set(settings.tls_ports) | {515, 9100}

    def service_methods(port):
        methods = []
        if port in web_ports:
            methods.append("http")
        if port in settings.tls_ports:
            methods.append("tls")
        if port in settings.banner_ports or (settings.passive_service_detection and port not in non_banner_ports):
            methods.append("banner")
        return methods

    def notify(stage):
        db.finish_job(job_id, "running", coverage)
        if progress:
            progress(stage, dict(coverage))

    async def guarded(method, address, port=None, **kwargs):
        try:
            function = getattr(probes, method, None)
            if function is None:
                return ProbeResult(address, method, "not_supported", port=port,
                                   reason_code=f"{method}_probe_unavailable")
            return await function(address, **kwargs) if port is None else await function(address, port, **kwargs)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            return ProbeResult(
                address, method, "error", port=port, reason_code="probe_internal_error",
                evidence={"exceptionType": type(error).__name__},
            )

    def count_errors(results):
        coverage["probeErrors"] += sum(result.status == "error" for result in results)

    async def discover(address):
        results = []
        if settings.icmp_enabled:
            results.append(await guarded("icmp", address))
        if settings.arp_enabled:
            results.append(await guarded("arp", address))
        direct = any(result.status == "reply" for result in results)
        if not direct:
            # Neither a ping failure nor an ARP cache entry gates TCP discovery.
            for port in settings.discovery_ports:
                result = await guarded("tcp", address, port)
                discovery_tcp[address, port] = result
                results.append(result)
                if result.status in ("open", "refused"):
                    break
        direct = direct or any(result.method == "tcp" and result.status == "open" for result in results)
        candidate = direct or any(
            (result.method == "arp" and result.status == "resolved")
            or (result.method == "tcp" and result.status == "refused") for result in results
        )
        host = None
        if candidate:
            mac = next((result.evidence.get("mac") for result in results
                        if result.method == "arp" and result.status in ("reply", "resolved")), None)
            methods = [f"{result.method}:{result.status}" for result in results
                       if result.status in ("reply", "resolved", "open", "refused")]
            host = {
                "mac": mac, "discovery_methods": methods,
                "confidence": "direct_response" if direct else "candidate_only",
                # 旧表列暂保留以兼容原库；新观测不接收任何本机虚拟机提示。
                "context": {},
            }
            hosts[address] = host
            if direct:
                confirmed.add(address)
        db.record_discovery(job_id, address, results, host)
        count_errors(results)
        coverage["completedDiscoveryAddresses"] += 1
        coverage["discoveredCandidates"] = len(hosts)
        coverage["responsiveHosts"] = len(confirmed)
        if coverage["completedDiscoveryAddresses"] % 10 == 0:
            notify("discovery")

    async def inventory(item):
        address, port = item
        cached = discovery_tcp.pop((address, port), None)
        result = replace(cached if cached is not None else await guarded("tcp", address, port),
                         phase="inventory")
        db.record_probes(job_id, [result])
        count_errors([result])
        coverage["completedTcpChecks"] += 1
        if result.status in ("open", "refused") and address not in hosts:
            host = {"mac": None, "discovery_methods": [f"tcp:{result.status}"],
                    "confidence": "direct_response" if result.status == "open" else "candidate_only",
                    "context": {}}
            hosts[address] = host
            db.record_discovery(job_id, address, [], host)
            coverage["discoveredCandidates"] = len(hosts)
        if result.status == "open":
            if address not in confirmed:
                confirmed.add(address)
                db.confirm_host(job_id, address)
                coverage["responsiveHosts"] = len(confirmed)
            if settings.hostname_enabled and address not in checked_names:
                await identify(address)
            methods = service_methods(port)
            coverage["expectedServiceEvidenceChecks"] += len(methods)
            # Preserve evidence from early responsive hosts even if later targets
            # consume the scan budget. No second successful full-scan prerequisite.
            for method in methods:
                await enrich((address, port, method))
        if coverage["completedTcpChecks"] % 20 == 0:
            notify("inventory")

    async def identify(address):
        checked_names.add(address)
        if not hasattr(probes, "name"):
            result = ProbeResult(address, "name", "not_supported",
                                 reason_code="name_probe_unavailable")
        else:
            result = await guarded("name", address)
        db.record_probes(job_id, [replace(result, phase="enrichment")])
        count_errors([result])
        coverage["nameChecks"] += 1

    async def enrich(item):
        address, port, method = item
        kwargs = {"https": port in settings.https_ports} if method == "http" else {}
        result = replace(await guarded(method, address, port, **kwargs), phase="enrichment")
        if method == "http":
            result = replace(result, evidence={**result.evidence,
                             "scheme": "https" if kwargs["https"] else "http"})
        db.record_probes(job_id, [result])
        count_errors([result])
        coverage["serviceEvidenceChecks"] += 1
        if method == "http":
            if settings.screenshots_enabled:
                async with screenshot_lock:
                    await capture(result)

    async def capture(website):
        address, port = website.address, website.port
        scheme = website.evidence.get("scheme", "http")
        if website.status != "response":
            result = ProbeResult(address, "screenshot", "not_applicable", port=port,
                                 reason_code="http_probe_not_successful", evidence={"scheme": scheme})
        elif not hasattr(probes, "screenshot"):
            result = ProbeResult(address, "screenshot", "not_supported", port=port,
                                 reason_code="screenshot_probe_unavailable", evidence={"scheme": scheme})
        else:
            result = await guarded("screenshot", address, port, https=scheme == "https",
                                   artifact_directory=db.path.parent / "artifacts" / "screenshots")
        result = replace(result, evidence={**result.evidence, "scheme": scheme})
        db.record_probes(job_id, [replace(result, phase="enrichment")])
        coverage["screenshotChecks"] += 1
        coverage["screenshotFailures"] = coverage.get("screenshotFailures", 0) + (result.status != "captured")

    state, error_code = "completed", None
    try:
        async with asyncio.timeout(settings.budget_seconds):
            await _pool(addresses, discover, settings.concurrency)
            notify("discovery_finished")
            if settings.hostname_enabled:
                await _pool(list(hosts), identify, settings.concurrency)
            # Confirmed/candidate addresses first; unknown addresses are still
            # inventoried, never silently dropped by the discovery prefilter.
            ordered = [address for address in addresses if address in hosts]
            ordered.extend(address for address in addresses if address not in hosts)
            await _pool(((address, port) for address in ordered for port in ports),
                        inventory, settings.concurrency)
            notify("inventory_finished")
        if coverage["probeErrors"]:
            state, error_code = "partial", "probe_errors"
    except TimeoutError:
        state, error_code = "partial", "budget_exceeded"
    except asyncio.CancelledError:
        db.finish_job(job_id, "interrupted", coverage, "scan_interrupted")
        raise
    except Exception:
        db.finish_job(job_id, "failed", coverage, "scan_internal_error")
        raise
    db.finish_job(job_id, state, coverage, error_code)
    from app.assets.automatic import reconcile_job
    try:
        coverage["assetRegistration"] = reconcile_job(db, job_id)
    except Exception as error:
        # Raw discoveries stay available even if a separate asset write fails.
        coverage["assetRegistration"] = {"status": "failed", "errorType": type(error).__name__}
        state, error_code = "partial", "asset_registration_failed"
    db.finish_job(job_id, state, coverage, error_code)
    if progress:
        progress(state, dict(coverage))
    return job_id
