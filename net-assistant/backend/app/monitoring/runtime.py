"""Owned Gatus process; usable from CLI and SCM, never kills a borrowed PID."""
from contextlib import nullcontext
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

from app.discovery.store import scan_writer_lock
from app.monitoring.config import render_gatus, write_gatus_config


def run_gatus(plan, executable: Path, storage: Path, *, stop_event=None, tick=None):
    executable = Path(executable).resolve()
    if not executable.is_file():
        raise FileNotFoundError("Build the pinned project-local Gatus executable first.")
    storage = Path(storage)
    port = urlsplit(plan.api_url).port
    render_gatus(plan, storage, port)  # Validate before creating directories or launching.
    storage.parent.mkdir(parents=True, exist_ok=True)
    stop = stop_event if stop_event is not None else threading.Event()
    with scan_writer_lock(storage):
        from app.scheduling.windows_service import ChildJob
        job_context = ChildJob() if os.name == "nt" else nullcontext()
        with job_context as job, tempfile.TemporaryDirectory(
                prefix="gatus-config-", dir=storage.parent) as directory:
            config = Path(directory) / "config.yaml"
            write_gatus_config(plan, config, storage, port)
            environment = {key: value for key, value in os.environ.items()
                           if key.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
            environment.update(GATUS_CONFIG_PATH=str(config), ENVIRONMENT="production", GATUS_LOG_LEVEL="INFO")
            log_path = storage.parent / "gatus.log"
            if log_path.exists() and log_path.stat().st_size > 5 * 1024 * 1024:
                log_path.replace(log_path.with_suffix(".previous.log"))
            with log_path.open("ab") as log:
                process = subprocess.Popen(
                    [str(executable)], cwd=storage.parent, env=environment,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    creationflags=0x08000000 if os.name == "nt" else 0)
                try:
                    if job:
                        job.assign(process.pid)
                    while process.poll() is None and not stop.is_set():
                        if tick:
                            tick(process)
                        stop.wait(1)
                    return process.returncode if process.returncode is not None else 0
                except KeyboardInterrupt:
                    return 130
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            if job:
                                job.terminate()
                            else:
                                process.kill()
                            process.wait(timeout=5)
