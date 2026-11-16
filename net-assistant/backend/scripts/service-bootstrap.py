"""SCM must launch the base Python process, not a venv redirector.

Use only the dependency environment adjacent to this project. Installation
validates this same entry point; no global site-package fallback is intended.
"""
from pathlib import Path
import os
import site
import sys

ROOT = Path(__file__).resolve().parents[1]
if os.environ.get("NET_ASSISTANT_PORTABLE") == "1":
    portable = ROOT.parents[1] / ".runtime/python"
    if Path(sys.executable).resolve() != (portable / "python.exe").resolve():
        raise SystemExit("Portable worker must use this checkout's embedded Python.")
    packages = portable / "Lib/site-packages"
else:
    packages = ROOT / ".venv" / ("Lib/site-packages" if sys.platform == "win32"
                               else f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")
if not packages.is_dir():
    raise SystemExit("Project dependency environment is missing. Recreate .venv first.")
sys.path.insert(0, str(ROOT))
site.addsitedir(str(packages))
# Project packages take precedence over globally installed third-party packages.
sys.path.remove(str(packages))
sys.path.insert(1, str(packages))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("service", "worker", "due", "validate", "monitoring-service"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--name", default="NetAssistant-Discovery")
    args = parser.parse_args()
    if args.mode == "monitoring-service":
        from app.scheduling.windows_service import serve
        from app.monitoring.automation import run_automation
        serve(args.name, args.config, runner=run_automation)
        return 0
    if args.mode == "service":
        from app.scheduling.windows_service import serve
        serve(args.name, args.config)
        return 0
    if args.mode == "worker":
        from app.scheduling.worker import main as worker
        return worker(["--config", str(args.config)])
    from app.scheduling.cli import main as schedule
    return schedule(["validate" if args.mode == "validate" else "run-due", "--config", str(args.config)])


if __name__ == "__main__":
    raise SystemExit(main())
