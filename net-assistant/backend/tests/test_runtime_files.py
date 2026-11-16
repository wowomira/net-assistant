"""Real Windows read-sharing conflict, no global permissions or ACL changes."""
import json
import os
import threading
import time
from types import SimpleNamespace
import pytest


@pytest.mark.skipif(os.name != "nt", reason="Windows replacement/read-sharing semantics")
@pytest.mark.parametrize("writer", ["automation", "switch"])
def test_transient_reader_does_not_crash_heartbeat_writer(tmp_path, writer):
    if writer == "automation":
        from app.monitoring.automation import write_state
        path = tmp_path / "automation-state.json"
        plan = SimpleNamespace(storage=tmp_path / "gatus.sqlite")
    else:
        from app.switches.worker import write_runtime as write_state
        path = tmp_path / "switch-state.json"
        plan = SimpleNamespace(storage=tmp_path)
    path.write_text('{"old":true}', encoding="utf-8")
    handle = path.open("rb")
    release = threading.Thread(target=lambda: (time.sleep(.15), handle.close()))
    release.start()
    try:
        write_state(plan, {"heartbeat": "new"})
    finally:
        handle.close()
        release.join(timeout=2)
    assert json.loads(path.read_text(encoding="utf-8")) == {"heartbeat": "new"}


@pytest.mark.skipif(os.name != "nt", reason="Windows replacement/read-sharing semantics")
def test_persistent_reader_reports_failure_and_preserves_old_state(tmp_path):
    from app.runtime_files import write_atomic_json
    path = tmp_path / "state.json"
    path.write_text('{"old":true}', encoding="utf-8")
    started = time.monotonic()
    with path.open("rb"):
        with pytest.raises(PermissionError):
            write_atomic_json(path, {"heartbeat": "new"})
    assert time.monotonic() - started < 3
    assert json.loads(path.read_text(encoding="utf-8")) == {"old": True}
