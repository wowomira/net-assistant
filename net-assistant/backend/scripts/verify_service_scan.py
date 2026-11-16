"""Opt-in live acceptance: install a temporary service, scan one authorized target.

This is an acceptance tool, not daily product logic. No asset records are seeded.
Production plan/database and the legacy task are not modified.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIRECTORY))

from sqlalchemy.exc import SQLAlchemyError

from app.assets.service import AssetRegistry
from app.discovery.config import ROOT, load_settings
from app.discovery.store import Database
from app.scheduling.config import DailyPlan
from app.scheduling.runtime import read_runtime
from app.scheduling.status import recent_runs


SERVICE = "NetAssistant-Discovery-LiveCheck"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--allow-network", action="store_true", required=True)
    args = parser.parse_args()
    settings = load_settings(args.config)
    if not settings.permits(args.target):
        raise ValueError("Target must be inside the explicitly authorized scope.")
    directory = args.output_directory.resolve()
    if not directory.is_relative_to(ROOT / "reports"):
        raise ValueError("Acceptance data must stay inside this project's reports directory.")
    directory.mkdir(parents=True, exist_ok=False)
    values = settings.snapshot()
    values.update(name="service-live-acceptance", targets=[args.target])
    scan_path = directory / "single-authorized-target.json"
    scan_path.write_text(json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8")
    plan = DailyPlan(name="service-live-acceptance", at="00:00", scan_config=scan_path,
                     database=directory / "acceptance.sqlite", report_directory=directory / "jobs")
    plan_path = directory / "daily.json"
    plan_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    manager = ROOT / "scripts/manage-discovery-service.ps1"

    def manage(action):
        output = subprocess.run([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(manager), "-Action", action, "-ServiceName", SERVICE,
            "-ConfigPath", str(plan_path),
        ], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        (directory / f"{action.lower()}.log").write_text(output.stdout + output.stderr, encoding="utf-8")
        if output.returncode:
            raise RuntimeError(f"Service {action} failed; see saved log.")
        return json.loads(output.stdout)

    proof = {
        "acceptanceOnly": True, "target": args.target, "sourceConfig": str(args.config.resolve()),
        "dailyTimeOverriddenForIndependentAcceptance": "00:00",
        "productionScheduleChanged": False, "assetSeeded": False, "hostMetricsCollected": False,
        "realRebootTested": False, "realLogoutTested": False,
    }
    installed = False
    try:
        assert not plan.database.exists()
        proof["installed"] = manage("Install")
        installed = True
        deadline = time.monotonic() + settings.budget_seconds + 180
        run = None
        while time.monotonic() < deadline:
            if plan.database.is_file():
                try:
                    items = recent_runs(plan)["items"]
                    if items and items[0]["state"] != "running":
                        run = items[0]
                        break
                except (SQLAlchemyError, ValueError):
                    pass  # schema may still be initializing; no writes or migrations here
            time.sleep(.5)
        assert run and run["state"] == "completed", run
        db = Database(plan.database, readonly=True)
        job = db.get_job(run["job_id"])
        assets = AssetRegistry(db).list_assets()["items"]
        assert len(assets) == 1, "Target may be offline: do not seed or invent an asset."
        assert assets[0]["registration_source"] == "automatic"
        assert assets[0]["management_status"] == "discovered"
        assert assets[0]["collection_access"] == "not_enrolled"
        assert job["trigger"] == "scheduled"
        assert job["coverage"]["assetRegistration"]["registered"] == 1
        proof.update(run=run, job=job, assets=assets, runtime=read_runtime(plan))
        proof["stopped"] = manage("Stop")
        proof["restarted"] = manage("Start")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            runtime = read_runtime(plan)
            if runtime.get("lastInvocation") and runtime["lastInvocation"]["status"] == "already_attempted":
                break
            time.sleep(.5)
        assert runtime.get("lastInvocation", {}).get("status") == "already_attempted", runtime
        assert len(db.list_jobs()["items"]) == 1
        assert len(recent_runs(plan)["items"]) == 1
        assert len(AssetRegistry(db).list_assets()["items"]) == 1
        proof["afterServiceRestart"] = runtime
        proof["dailyDuplicatePrevented"] = True
        proof["passed"] = True
    finally:
        if installed:
            proof["finalStop"] = manage("Stop")
            proof["removed"] = manage("Remove")
        (directory / "proof.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2),
                                              encoding="utf-8")
    print(json.dumps(proof, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
