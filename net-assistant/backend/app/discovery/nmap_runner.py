"""Persist Nmap evidence through the existing snapshot/asset/report pipeline."""
import asyncio
from dataclasses import replace
import ipaddress

from app.discovery import nmap
from app.discovery.concurrency import _pool
from app.discovery.types import ProbeResult


async def run_nmap_discovery(settings, db, probes, progress=None, *, trigger="manual", schedule_run_id=None):
    addresses = settings.addresses()
    scope, revision = db.save_scope(settings)
    job = db.begin_job(scope, revision, settings.snapshot(), trigger, schedule_run_id)
    coverage = {
        "engine": "nmap", "candidateAddresses": len(addresses),
        "completedDiscoveryAddresses": 0, "configuredTcpPorts": len(settings.effective_ports()),
        "expectedTcpChecks": len(addresses) * len(settings.effective_ports()),
        "completedTcpChecks": 0, "responsiveHosts": 0, "discoveredCandidates": 0,
        "probeErrors": 0, "serviceEvidenceChecks": 0, "nameChecks": 0,
        "inventoryPolicy": "all_authorized_addresses", "toolVersions": [],
        "mdnsStatus": "not_requested",
    }
    names = {}
    screenshot_lock = asyncio.Lock()

    def notify(stage):
        db.finish_job(job, "running", coverage)
        if progress:
            progress(stage, dict(coverage))

    async def enrich(method, address, port=None, **kwargs):
        try:
            result = await getattr(probes, method)(address, **kwargs) if port is None else (
                await getattr(probes, method)(address, port, **kwargs))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            result = ProbeResult(address, method, "error", port=port,
                                 reason_code="probe_internal_error",
                                 evidence={"exceptionType": type(error).__name__})
        coverage["probeErrors"] += result.status == "error"
        db.record_probes(job, [replace(result, phase="enrichment")])
        return result

    async def inspect(address):
        try:
            result = await nmap.scan_host(settings, address)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            code = ("nmap_not_installed" if isinstance(error, FileNotFoundError) else
                    "nmap_timeout" if isinstance(error, TimeoutError) else "nmap_scan_failed")
            db.record_probes(job, [ProbeResult(address, "nmap", "error", reason_code=code,
                                              evidence={"exceptionType": type(error).__name__})])
            coverage["probeErrors"] += 1
            notify("nmap_target_failed")
            return
        if result["version"] not in coverage["toolVersions"]:
            coverage["toolVersions"].append(result["version"])
        port_results = [ProbeResult(address, "tcp", item["status"], port=port, phase="inventory",
                                    evidence={"engine": "nmap", "rawState": item["raw_state"],
                                              "reason": item["reason"]})
                        for port, item in sorted(result["ports"].items())]
        candidate = result["responsive"] or result["mac"] or any(
            item["status"] == "refused" for item in result["ports"].values())
        host = None
        if candidate:
            host = {"mac": result["mac"], "context": {},
                    "discovery_methods": ["nmap:tcp_open" if result["responsive"] else "nmap:candidate"],
                    "confidence": "direct_response" if result["responsive"] else "candidate_only"}
        db.record_discovery(job, address, port_results, host)
        coverage["completedDiscoveryAddresses"] += 1
        coverage["completedTcpChecks"] += len(port_results)
        coverage["responsiveHosts"] += bool(result["responsive"])
        coverage["discoveredCandidates"] += bool(candidate)
        evidence = []
        if result["mac"]:
            evidence.append(ProbeResult(address, "arp", "resolved",
                                        evidence={"mac": result["mac"], "source": "nmap"}))
        for name in result["names"] + names.get(address, []):
            evidence.append(ProbeResult(address, "name", "resolved", phase="enrichment", evidence=name))
        for os_candidate in result["os_candidates"]:
            evidence.append(ProbeResult(address, "os", "candidate", phase="enrichment", evidence=os_candidate))
        os_detection = result.get("os_detection", {"status": "not_collected"})
        evidence.append(ProbeResult(address, "nmap_os", os_detection["status"], phase="enrichment",
                                    reason_code=os_detection.get("reason_code"), evidence=os_detection))
        if result["vendor_hint"]:
            evidence.append(ProbeResult(address, "vendor", "hint", phase="enrichment",
                                        evidence=result["vendor_hint"]))
        db.record_probes(job, evidence)
        for port, item in result["ports"].items():
            if item["status"] == "open" and item["service"]:
                db.record_probes(job, [ProbeResult(address, "nmap_service", "identified", port=port,
                                                   phase="enrichment", evidence=item["service"])])
        if probes is not None and candidate:
            if settings.arp_enabled and ipaddress.ip_address(address).version == 4 and not result["mac"]:
                arp = await enrich("arp", address)
                if arp.evidence.get("mac"):
                    db.set_host_mac(job, address, arp.evidence["mac"])
                    hint = nmap.lookup_mac_vendor(arp.evidence["mac"], settings.nmap_path)
                    if hint and not result["vendor_hint"]:
                        db.record_probes(job, [ProbeResult(address, "vendor", "hint", phase="enrichment",
                                                           evidence=hint)])
            if settings.hostname_enabled:
                await enrich("name", address)
                coverage["nameChecks"] += 1
        if probes is not None:
            for port, item in result["ports"].items():
                if item["status"] != "open":
                    continue
                service = item["service"] or {}
                # Protocol-probed HTTP on a nonstandard port is still HTTP.
                is_web = service.get("method") == "probed" and service.get("name") in ("http", "https")
                https = port in settings.https_ports or service.get("tunnel") == "ssl" or service.get("name") == "https"
                if is_web or port in settings.http_ports + settings.https_ports:
                    web = await enrich("http", address, port, https=https)
                    coverage["serviceEvidenceChecks"] += 1
                    if settings.screenshots_enabled and web.status == "response":
                        async with screenshot_lock:
                            await enrich("screenshot", address, port, https=https,
                                         artifact_directory=db.path.parent / "artifacts" / "screenshots")
        notify("nmap_target_finished")

    state, error_code = "completed", None
    try:
        async with asyncio.timeout(settings.budget_seconds):
            if settings.mdns_enabled:
                from app.collectors.mdns import collect_mdns
                try:
                    names = await collect_mdns(settings)
                    coverage["mdnsStatus"] = "completed"
                except (ImportError, OSError, ValueError, RuntimeError) as error:
                    coverage["mdnsStatus"] = "failed"
                    coverage["mdnsErrorType"] = type(error).__name__
                    coverage["probeErrors"] += 1
            await _pool(addresses, inspect, settings.concurrency)
        if coverage["probeErrors"]:
            state = "partial" if coverage["completedTcpChecks"] else "failed"
            error_code = "collector_errors"
    except TimeoutError:
        state, error_code = "partial", "budget_exceeded"
    except asyncio.CancelledError:
        db.finish_job(job, "interrupted", coverage, "scan_interrupted")
        raise
    except Exception:
        db.finish_job(job, "failed", coverage, "scan_internal_error")
        raise
    db.finish_job(job, state, coverage, error_code)
    if state in ("completed", "partial"):
        from app.assets.automatic import reconcile_job
        try:
            coverage["assetRegistration"] = reconcile_job(db, job)
        except Exception as error:
            coverage["assetRegistration"] = {"status": "failed", "errorType": type(error).__name__}
            state, error_code = "partial", "asset_registration_failed"
    db.finish_job(job, state, coverage, error_code)
    if progress:
        progress(state, dict(coverage))
    return job
