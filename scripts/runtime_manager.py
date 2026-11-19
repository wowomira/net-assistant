"""Owned foreground workers. Never installs services, opens firewall rules or kills borrowed PIDs."""
from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import tempfile
import threading
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
NMAP_REQUIRED = ("nmap.exe", "nmap-services", "nmap-service-probes", "nmap-os-db",
                 "nmap-mac-prefixes", "nmap-protocols", "LICENSE")


def import_nmap(source, root=ROOT):
    """User-provided licensed installation only; never included in GitHub assets."""
    source, root = Path(source).resolve(), Path(root).resolve()
    if any(not (source / name).is_file() for name in NMAP_REQUIRED):
        raise ValueError("Nmap installation incomplete: executable + databases + LICENSE required.")
    destination = root / ".runtime/tools/nmap"
    if destination.exists():
        raise ValueError("Project-local Nmap already exists; it was not replaced.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.resolve() != root / ".runtime/tools":
        raise ValueError("Redirected tool directory refused.")
    from runtime_support import sha256
    with tempfile.TemporaryDirectory(prefix="nmap-import-", dir=destination.parent) as directory:
        stage = Path(directory) / "complete"
        stage.mkdir()
        # File allowlist, no keys, configs, user profiles, uninstallers or packet drivers.
        allowed = set(NMAP_REQUIRED) | {
            "nmap-rpc", "nmap-payloads", "nse_main.lua", "nmap.xsl", "ca-bundle.crt",
            "3rd-party-licenses.txt", "COPYING_HIGWIDGETS", "README-WIN32", "CHANGELOG"}
        for file in source.iterdir():
            if file.is_file() and (file.name in allowed or file.suffix.lower() == ".dll"):
                if file.is_symlink():
                    raise ValueError("Redirected Nmap resource refused.")
                shutil.copy2(file, stage / file.name)
        for name in ("licenses", "scripts", "nselib"):
            directory = source / name
            if directory.is_dir():
                for file in directory.rglob("*"):
                    if file.is_symlink() or getattr(file, "is_junction", lambda: False)():
                        raise ValueError("Redirected Nmap resource refused.")
                shutil.copytree(directory, stage / name)
        manifest = {str(file.relative_to(stage)).replace("\\", "/"): sha256(file)
                    for file in stage.rglob("*") if file.is_file()}
        (stage / "import-manifest.json").write_text(json.dumps(
            {"files": manifest, "redistribution": "user-supplied; excluded from GitHub resources"},
            indent=2), encoding="utf-8")
        stage.rename(destination)
    print("Licensed Nmap copied into this project. Npcap was not installed or redistributed.")


def worker_selection(configs):
    result = []
    for name, file, enabled in (
        ("schedule", "daily-scan.local.json", "enabled"),
        ("switches", "switches.local.json", "enabled"),
        ("collection", "collection.local.json", "enabled"),
        ("monitoring", "monitoring.local.json", "endpoints"),
    ):
        path = Path(configs) / file
        if not path.is_file():
            continue
        config = json.loads(path.read_text("utf-8-sig"))
        if not isinstance(config, dict):
            raise ValueError(f"{file} must contain a JSON object.")
        if enabled == "endpoints":
            selected = config.get(enabled, [])
            if not isinstance(selected, list):
                raise ValueError(f"{file}: endpoints must be a JSON array.")
        else:
            selected = config.get(enabled, False)
            if not isinstance(selected, bool):
                raise ValueError(f"{file}: enabled must be a JSON boolean.")
        if selected:
            result.append(name)
    return result


def collection_plan(configs):
    from uuid import UUID
    value = json.loads((Path(configs) / "collection.local.json").read_text("utf-8-sig"))
    interval = value.get("interval_seconds", 300)
    if isinstance(interval, bool) or not isinstance(interval, int) or not 30 <= interval <= 86400:
        raise ValueError("Collection interval must be in 30..86400 seconds.")
    identity = UUID(value["device_id"])
    label = value.get("label")
    if not isinstance(label, str) or not label.strip() or len(label) > 120:
        raise ValueError("Collection label must contain 1..120 characters.")
    return identity, label, interval


def start(port=8001):
    import workspace
    from runtime_support import verify_installed
    workspace.backend_imports()
    from app.discovery.store import scan_writer_lock
    import uvicorn
    if not 1 <= port <= 65535:
        raise ValueError("Port must be in 1..65535.")
    verify_installed()
    paths = workspace.layout()
    app = workspace.build_app()
    with closing(sqlite3.connect(paths["database"])) as db:
        if not db.execute("SELECT count(*) FROM auth_users WHERE enabled=1").fetchone()[0]:
            raise ValueError("No enabled accounts. Run create-user first; no default password exists.")
    # Fail before starting any worker if someone else already owns the API port.
    with socket.socket() as check:
        if os.name == "nt":
            check.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        check.bind(("127.0.0.1", port))
    selected = worker_selection(paths["configs"])
    collection_settings = collection_plan(paths["configs"]) if "collection" in selected else None
    stop, errors, threads = threading.Event(), [], []
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                         proxy_headers=False, workers=1))

    def guarded(name, function):
        try:
            code = function()
            if not stop.is_set():
                errors.append(f"{name} worker exited unexpectedly (code={code})")
                server.should_exit = True
        except Exception as error:
            errors.append(f"{name} worker failed ({type(error).__name__})")
            server.should_exit = True

    def collection():
        from app.collectors.store import NetworkStore
        from app.discovery.store import initialize_database
        identity, label, interval = collection_settings
        database = initialize_database(paths["database"])
        try:
            store = NetworkStore(database)
            while not stop.is_set():
                result = store.collect(identity, label)
                if result["state"] not in ("completed", "partial"):
                    raise RuntimeError("Local collection failed; inspect the stored run.")
                stop.wait(interval)
        finally:
            database.engine.dispose()
        return 0

    with scan_writer_lock(paths["runtime"] / "data/launcher.owner.sqlite"):
        # All selected plans are validated before any thread is started.
        tasks = []
        if "schedule" in selected:
            from app.scheduling.config import load_plan
            from app.scheduling.worker import run_worker
            plan = load_plan(paths["configs"] / "daily-scan.local.json")
            if plan.database != paths["database"]:
                raise ValueError("Scheduler must use the independent runtime database.")
            if not (paths["runtime"] / "tools/nmap/nmap.exe").is_file():
                raise ValueError("Enabled scanning requires import-nmap and the correct driver/permissions.")
            tasks.append(("schedule", lambda: run_worker(
                paths["configs"] / "daily-scan.local.json", stop_event=stop)))
        if "switches" in selected:
            from app.switches.config import load_switch_plan, readiness
            from app.switches.worker import run_worker as run_switches
            plan = load_switch_plan(paths["configs"] / "switches.local.json")
            if plan.database != paths["database"] or readiness(plan)["state"] != "ready":
                raise ValueError("Switch collection configuration/authorization is not ready.")
            tasks.append(("switches", lambda: run_switches(
                paths["configs"] / "switches.local.json", stop_event=stop, database=paths["database"])))
        if "monitoring" in selected:
            from app.monitoring.config import load_plan as load_monitor
            from app.monitoring.runtime import run_gatus
            from app.runtime_tools import gatus_executable
            monitor = load_monitor(paths["configs"] / "monitoring.local.json")
            # Never take over an already running Gatus on the configured port.
            from urllib.parse import urlsplit
            address = urlsplit(monitor.api_url)
            family = socket.AF_INET6 if address.hostname == "::1" else socket.AF_INET
            with socket.socket(family) as probe:
                probe.bind((address.hostname, address.port))
            tasks.append(("monitoring", lambda: run_gatus(
                monitor, gatus_executable(), paths["runtime"] / "data/gatus.sqlite", stop_event=stop)))
        if "collection" in selected:
            tasks.append(("collection", collection))
        try:
            for name, function in tasks:
                thread = threading.Thread(target=guarded, args=(name, function),
                                          name=f"managed-{name}", daemon=True)
                threads.append(thread)
                thread.start()
            print(f"Owned local API: http://127.0.0.1:{port}/docs", flush=True)
            print("Workers enabled: " + (", ".join(selected) or "none (no scan/collection configured)"),
                  flush=True)
            print("Ctrl+C stops this launcher's workers only. No Windows service is installed.", flush=True)
            server.run()
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=45)
            if any(thread.is_alive() for thread in threads):
                errors.append("Worker shutdown timed out; inspect this launcher's log.")
        if errors:
            raise ValueError("; ".join(errors))
