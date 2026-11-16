"""Restart reconciliation and mutual exclusion use the actual SQLite store and OS lock."""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.terminal.config import TerminalPlan
from app.terminal.service import TerminalService
from app.discovery.store import ScanBusyError
from test_auth import login, setup
from test_terminal_transport import target


def test_restart_marks_inflight_unknown_without_sending_any_commands(tmp_path):
    db, auth = setup(tmp_path)
    principal = auth.authenticate(auth.login("administrator", "isolated-test-password-729!", "127.0.0.1")["token"])
    item = target(tmp_path, compatibility_confirmed=True, allowed_users=["administrator"],
                  allowed_commands=["version"])
    plan = TerminalPlan(targets=[item])
    with auth.transaction() as conn:
        conn.execute("INSERT INTO terminal_sessions VALUES(?,?,?,?,?,?,?,?)",
                     ("old-session", principal.id, principal.session_hash, item.id, "ready", 1, 1, None))
        conn.execute("""INSERT INTO terminal_operations
          (id,session_id,user_id,command_id,commands,risk,state,expires_at,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?)""", ("old-operation", "old-session", principal.id, "version",
          '["show version"]', "low", "executing", 9999999999, 1, 1))
    first = TerminalService(db.path, plan)
    first.start()
    try:
        with auth.transaction() as conn:
            row = conn.execute("SELECT state,error_code FROM terminal_operations WHERE id='old-operation'").fetchone()
            assert tuple(row) == ("interrupted", "process_interrupted")
            assert conn.execute("SELECT state FROM terminal_sessions").fetchone()[0] == "interrupted"
        second = TerminalService(db.path, plan)
        with pytest.raises(ScanBusyError):
            second.start()
        assert first.channels == {}
        result = first.execute("old-operation", principal)
        assert result["state"] == "interrupted"
    finally:
        first.stop()
    third = TerminalService(db.path, plan)
    third.start()
    third.stop()
