"""Run one due daily scan, or read history. No persistent terminal is required."""
import argparse
import json
from pathlib import Path
import sys

from app.discovery.store import Database
from app.discovery.types import utc_now
from app.scheduling.config import load_plan
from app.scheduling.service import history, run_due


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "run-due", "status"])
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        plan = load_plan(args.config)
        if args.command == "validate":
            from app.discovery.config import load_settings
            settings = load_settings(plan.scan_config)
            result = {"plan": plan.model_dump(mode="json"), "budgetSeconds": settings.budget_seconds}
        elif args.command == "status":
            initialized = plan.database.is_file()
            result = {
                "enabled": plan.enabled, "at": plan.at, "utcOffsetMinutes": plan.utc_offset_minutes,
                "localNow": plan.local_now().isoformat(), "database": str(plan.database),
                "databaseInitialized": initialized,
                "runs": history(Database(plan.database, readonly=True), schedule_name=plan.name)
                        if initialized else {"items": [], "next_cursor": None},
            }
        else:
            result = {"checkedAt": utc_now(), **run_due(plan)}
            logs = plan.report_directory / "schedule-logs"
            logs.mkdir(parents=True, exist_ok=True)
            with (logs / f"{plan.local_now().date().isoformat()}.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(result, ensure_ascii=False) + "\n")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result.get("status") == "busy":
            return 2
        return 1 if result.get("status") in ("failed", "partial", "interrupted") else 0
    except Exception as error:
        print(json.dumps({"code": "schedule_command_failed", "errorType": type(error).__name__},
                         ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
