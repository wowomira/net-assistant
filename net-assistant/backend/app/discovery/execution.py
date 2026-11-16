"""Shared real execution path for explicit manual and scheduled invocations."""
import asyncio

from app.discovery.context import verified_source_network
from app.discovery.probes import SystemProbes
from app.discovery.report import write_report
from app.discovery.nmap_runner import run_nmap_discovery


def execute_scan(settings, db, report_directory, *, trigger="manual", schedule_run_id=None, progress=None):
    source_network = verified_source_network(settings.source_address)
    db.interrupt_stale_jobs()  # Caller has acquired the shared process lock.

    async def execute():
        probes = SystemProbes(settings, source_network)
        try:
            return await run_nmap_discovery(
                settings, db, probes, progress=progress, trigger=trigger, schedule_run_id=schedule_run_id,
            )
        finally:
            await probes.close()

    job_id = asyncio.run(execute())
    directory = write_report(db, job_id, report_directory)
    return {"jobId": job_id, "reportDirectory": str(directory), "database": str(db.path)}
