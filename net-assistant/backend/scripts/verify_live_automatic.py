"""Explicit live check: one authorized target, fresh DB, real scheduled CLI.

No SQL inserts, register/link calls, names or OS labels are supplied. The project
must discover, register and correlate all output itself. Not a daily daemon.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from app.assets.service import AssetRegistry
from app.discovery.config import DEFAULT_DATABASE, ROOT, load_settings
from app.discovery.store import Database
from app.scheduling.config import DailyPlan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--source-job-id", required=True)
    parser.add_argument("--source-database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    settings = load_settings(args.config)
    source = Database(args.source_database, readonly=True)
    selected = next((host for host in source.list_hosts(args.source_job_id, limit=200)["items"]
                     if host["confidence"] == "direct_response" and settings.permits(host["address"])), None)
    if not selected:
        raise ValueError("No directly responsive target within the explicitly authorized scope.")
    directory = args.output_directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    config = directory / "single-authorized-target.json"
    # 测试仅缩小授权范围；设备信息只能由探测取得。
    values = settings.snapshot()
    values.update(name="task04-empty-db-live", targets=[selected["address"]])
    config.write_text(json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8")
    plan = DailyPlan(name="task04-independent-live", at="00:00", scan_config=config,
                     database=directory / "empty-before-run.sqlite", report_directory=directory / "jobs")
    plan_path = directory / "daily-check.json"
    plan_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    assert not plan.database.exists()
    command = [sys.executable, "-m", "app.scheduling.cli", "run-due", "--config", str(plan_path)]
    first = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                           timeout=settings.budget_seconds + 180)
    (directory / "first-cli.log").write_text(first.stdout + first.stderr, encoding="utf-8")
    assert first.returncode == 0, first.stderr + first.stdout
    result = json.loads(first.stdout)
    assert result["status"] == "completed"
    db = Database(plan.database, readonly=True)
    job = db.get_job(result["jobId"])
    assets = AssetRegistry(db).list_assets()["items"]
    assert job["trigger"] == "scheduled"
    assert job["coverage"]["assetRegistration"]["registered"] == 1
    assert len(assets) == 1 and assets[0]["registration_source"] == "automatic"
    assert assets[0]["management_status"] == "discovered"
    assert assets[0]["collection_access"] == "not_enrolled"
    audit = AssetRegistry(db).list_audit(assets[0]["id"])["items"]
    assert len(audit) == 1 and audit[0]["actor"] == "automatic_discovery"
    second = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert second.returncode == 0 and json.loads(second.stdout)["status"] == "already_attempted"
    assert len(db.list_jobs()["items"]) == 1
    proof = {
        "sourceJobId": args.source_job_id, "singleAddressValidationOnly": True,
        "target": selected["address"], "databaseWasAbsent": True,
        "manualRegistrationUsed": False, "firstInvocation": result,
        "secondInvocation": json.loads(second.stdout), "job": job, "assets": assets, "audit": audit,
    }
    (directory / "proof.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(proof, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
