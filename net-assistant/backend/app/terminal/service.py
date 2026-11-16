"""Durable command state machine. Transport resources are single-process and never replayed."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from uuid import uuid4

from app.auth.store import AuthStore, digest
from app.discovery.api import ApiError
from app.discovery.store import scan_writer_lock
from app.terminal.catalog import render
from app.terminal import transport

TERMINAL_STATES = {"completed", "failed", "partial", "result_unknown", "interrupted"}
CLI_ERROR = re.compile(r"(?:^|[\r\n])\s*(?:%\s*(?:Invalid|Error|Incomplete|Ambiguous|Unknown)|"
                       r"Error:|Unrecognized command|Unknown command|Incomplete command|"
                       r"Ambiguous command)", re.I)


def stamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Channel:
    target: object
    principal: object
    transport: object
    last_used: float = field(default_factory=time.monotonic)
    lock: object = field(default_factory=threading.Lock)


class TerminalService:
    def __init__(self, path, plan):
        self.store = AuthStore(path)
        self.plan = plan
        self.channels = {}
        self.guard = threading.RLock()
        self.stop_event = threading.Event()
        self.thread = None
        self.lease = None

    def target(self, target_id, principal):
        target = next((t for t in self.plan.targets
                       if t.id == target_id and principal.username in t.allowed_users), None)
        if target is None:
            raise ApiError(404, "terminal_target_not_found", "目标不存在或没有设备授权。")
        return target

    @staticmethod
    def operator(principal):
        if principal.role not in ("admin", "operator"):
            raise ApiError(403, "terminal_permission_denied", "当前角色不能操作设备终端。")

    def start(self):
        if not self.plan.targets:
            return
        # Explicitly one API worker: never mark another live worker's operations interrupted.
        self.lease = scan_writer_lock(self.store.path.with_suffix(".terminal"))
        self.lease.__enter__()
        try:
            with self.store.transaction() as conn:
                rows = conn.execute("SELECT id,user_id FROM terminal_operations WHERE state='executing'").fetchall()
                for row in rows:
                    conn.execute("""UPDATE terminal_operations SET state='interrupted',
                         error_code='process_interrupted',updated_at=? WHERE id=?""",
                                 (self.store.clock(), row["id"]))
                    self.store.audit(conn, row["user_id"], "command_interrupted", row["id"])
                conn.execute("""UPDATE terminal_sessions SET state='interrupted',
                    error_code='process_interrupted',updated_at=? WHERE state IN ('connecting','ready')""",
                             (self.store.clock(),))
            self.thread = threading.Thread(target=self._reap, name="terminal-session-reaper", daemon=True)
            self.thread.start()
        except BaseException:
            self.lease.__exit__(None, None, None)
            self.lease = None
            raise

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)
        with self.guard:
            ids = list(self.channels)
        for sid in ids:
            try:
                self.close(sid, "closed", "server_shutdown")
            except sqlite3.Error:
                pass  # Channel already closed; next startup reconciles durable state.
        if self.lease:
            self.lease.__exit__(None, None, None)
            self.lease = None

    def _reap(self):
        while not self.stop_event.wait(1):
            with self.guard:
                items = list(self.channels.items())
            for sid, channel in items:
                try:
                    active = self.store.principal_active(channel.principal)
                    if not active or time.monotonic() - channel.last_used >= 300:
                        self.close(sid, "closed", "authentication_expired" if not active else "terminal_idle_timeout")
                except sqlite3.Error:
                    # Audit unavailable: close the device channel, never leave it usable.
                    with self.guard:
                        dead = self.channels.pop(sid, None)
                    if dead:
                        dead.transport.close()

    def revoke(self, session_hash):
        with self.guard:
            ids = [sid for sid, channel in self.channels.items()
                   if channel.principal.session_hash == session_hash]
        for sid in ids:
            self.close(sid, "closed", "platform_logout")

    def open(self, principal, target_id):
        self.operator(principal)
        target = self.target(target_id, principal)
        if not target.compatibility_confirmed:
            raise ApiError(409, "compatibility_not_confirmed", "设备平台／版本尚未由操作者确认。")
        sid, now = str(uuid4()), self.store.clock()
        # Reserve a slot before slow network I/O, avoiding parallel limit bypass.
        with self.guard:
            if len(self.channels) >= 16 or sum(c.principal.id == principal.id for c in self.channels.values()) >= 4:
                raise ApiError(409, "terminal_session_limit", "终端并发会话达到上限。")
            channel = Channel(target, principal, transport.OpenSSHTransport(target))
            self.channels[sid] = channel
        try:
            with self.store.transaction() as conn:
                conn.execute("INSERT INTO terminal_sessions VALUES(?,?,?,?,?,?,?,?)",
                             (sid, principal.id, principal.session_hash, target.id, "connecting", now, now, None))
        except sqlite3.Error:
            with self.guard:
                self.channels.pop(sid, None)
            channel.transport.close()
            raise
        try:
            with self.store.transaction() as conn:
                self.store.audit(conn, principal.id, "terminal_connecting", sid, {"targetId": target.id})
            channel.transport.connect()
            with self.guard:
                still_open = self.channels.get(sid) is channel
            if not still_open or not self.store.principal_active(principal):
                raise transport.TransportFailure("authentication_expired")
            with self.store.transaction() as conn:
                conn.execute("UPDATE terminal_sessions SET state='ready',updated_at=? WHERE id=?", (self.store.clock(), sid))
                self.store.audit(conn, principal.id, "terminal_connected", sid)
        except (transport.TransportFailure, OSError) as error:
            code = error.code if isinstance(error, transport.TransportFailure) else "ssh_connect_failed"
            self.close(sid, "failed", code)
        except sqlite3.Error:
            channel.transport.close()
            with self.guard:
                self.channels.pop(sid, None)
            raise
        return self.session(sid, principal)

    def _session_row(self, conn, sid, principal):
        row = conn.execute("""SELECT * FROM terminal_sessions
             WHERE id=? AND user_id=? AND auth_session_hash=?""",
                           (sid, principal.id, principal.session_hash)).fetchone()
        if row is None:
            raise ApiError(404, "terminal_session_not_found", "会话不存在或不属于本次平台登录。")
        self.target(row["target_id"], principal)
        with self.guard:
            channel_exists = sid in self.channels
        if row["state"] == "ready" and not channel_exists:
            conn.execute("""UPDATE terminal_sessions SET state='interrupted',
                error_code='runtime_channel_lost',updated_at=? WHERE id=?""", (self.store.clock(), sid))
            self.store.audit(conn, principal.id, "terminal_interrupted", sid)
            row = conn.execute("SELECT * FROM terminal_sessions WHERE id=?", (sid,)).fetchone()
        return row

    @staticmethod
    def _session_view(row):
        return {"id": row["id"], "targetId": row["target_id"], "state": row["state"],
                "createdAt": stamp(row["created_at"]), "updatedAt": stamp(row["updated_at"]),
                "errorCode": row["error_code"], "mode": "controlled_commands"}

    def session(self, sid, principal):
        with self.store.transaction() as conn:
            return self._session_view(self._session_row(conn, sid, principal))

    def close(self, sid, state="closed", code=None):
        with self.guard:
            channel = self.channels.pop(sid, None)
        if channel:
            channel.transport.close()
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM terminal_sessions WHERE id=?", (sid,)).fetchone()
            if row and row["state"] in ("connecting", "ready"):
                conn.execute("UPDATE terminal_sessions SET state=?,updated_at=?,error_code=? WHERE id=?",
                             (state, self.store.clock(), code, sid))
                self.store.audit(conn, row["user_id"], "terminal_closed", sid, {"reasonCode": code})

    def _operation_row(self, conn, oid, principal):
        row = conn.execute("SELECT * FROM terminal_operations WHERE id=? AND user_id=?", (oid, principal.id)).fetchone()
        if not row:
            raise ApiError(404, "terminal_operation_not_found", "操作不存在或无权读取。")
        self._session_row(conn, row["session_id"], principal)
        return row

    @staticmethod
    def _operation_view(row):
        result = json.loads(row["output"]) if row["output"] else {}
        return {"id": row["id"], "sessionId": row["session_id"], "commandId": row["command_id"],
                "commands": json.loads(row["commands"]), "risk": row["risk"], "state": row["state"],
                "requiresDoubleConfirmation": row["risk"] == "high",
                "expiresAt": stamp(row["expires_at"]), "createdAt": stamp(row["created_at"]),
                "updatedAt": stamp(row["updated_at"]), "output": result.get("text"),
                "steps": result.get("steps", []), "errorCode": row["error_code"],
                "businessVerified": False, "automaticSave": False}

    def operation(self, oid, principal):
        with self.store.transaction() as conn:
            row = self._operation_row(conn, oid, principal)
            with self.guard:
                channel_exists = row["session_id"] in self.channels
            if row["state"] == "executing" and not channel_exists:
                conn.execute("""UPDATE terminal_operations SET state='result_unknown',
                    error_code='runtime_channel_lost',updated_at=? WHERE id=?""", (self.store.clock(), oid))
                self.store.audit(conn, principal.id, "command_result_unknown", oid)
                row = self._operation_row(conn, oid, principal)
            return self._operation_view(row)

    def prepare(self, sid, principal, command_id, parameters):
        self.operator(principal)
        with self.store.transaction() as conn:
            session = self._session_row(conn, sid, principal)
            if session["state"] != "ready":
                raise ApiError(409, "terminal_not_ready", "该会话不可提交命令，请重新连接。")
            target = self.target(session["target_id"], principal)
            commands, risk = render(target, command_id, parameters)
            now, oid = self.store.clock(), str(uuid4())
            conn.execute("""INSERT INTO terminal_operations
                (id,session_id,user_id,command_id,commands,risk,state,expires_at,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)""", (oid, sid, principal.id, command_id,
                json.dumps(commands, ensure_ascii=False), risk, "prepared", now + 120, now, now))
            self.store.audit(conn, principal.id, "command_prepared", oid,
                             {"commandId": command_id, "targetId": target.id, "risk": risk})
        return self.operation(oid, principal)

    def confirm(self, oid, principal, first, phrase):
        self.operator(principal)
        if not first or phrase != "我确认执行该操作":
            raise ApiError(422, "confirmation_phrase_invalid", "请完成首次确认并准确输入确认文字。")
        with self.store.transaction() as conn:
            row = self._operation_row(conn, oid, principal)
            if row["state"] != "prepared" or row["risk"] != "high" or row["expires_at"] <= self.store.clock():
                raise ApiError(409, "confirmation_unavailable", "该操作不可确认或已过期。")
            token = secrets.token_urlsafe(32)
            conn.execute("UPDATE terminal_operations SET state='confirmed',confirmation_hash=?,updated_at=? WHERE id=?",
                         (digest(token), self.store.clock(), oid))
            self.store.audit(conn, principal.id, "command_confirmed", oid)
        return {"id": oid, "confirmationToken": token, "expiresAt": stamp(row["expires_at"])}

    def execute(self, oid, principal, confirmation_token=None):
        self.operator(principal)
        with self.store.transaction() as conn:
            row = self._operation_row(conn, oid, principal)
            if row["state"] in TERMINAL_OR_RUNNING:
                return self._operation_view(row)
            sid = row["session_id"]
        with self.guard:
            channel = self.channels.get(sid)
        if not channel:
            raise ApiError(409, "terminal_not_ready", "会话已断开，禁止自动重连或重放。")
        if not channel.lock.acquire(blocking=False):
            raise ApiError(409, "terminal_busy", "该终端正在执行另一操作。")
        try:
            with self.store.transaction() as conn:
                row = self._operation_row(conn, oid, principal)
                session = self._session_row(conn, sid, principal)
                if row["state"] in TERMINAL_OR_RUNNING:
                    return self._operation_view(row)
                if row["expires_at"] <= self.store.clock():
                    raise ApiError(409, "operation_expired", "命令预览已过期，请重新生成。")
                if session["state"] != "ready":
                    raise ApiError(409, "terminal_not_ready", "终端不可执行命令。")
                if row["risk"] == "high" and (row["state"] != "confirmed" or not confirmation_token or
                        not hmac.compare_digest(digest(confirmation_token), row["confirmation_hash"] or "")):
                    raise ApiError(409, "double_confirmation_required", "该操作必须完成有效的双重确认。")
                commands = json.loads(row["commands"])
                # Freeze server-rendered content; never accept replacement commands at execution.
                conn.execute("""UPDATE terminal_operations SET state='executing',confirmation_hash=NULL,
                    updated_at=? WHERE id=?""", (self.store.clock(), oid))
                self.store.audit(conn, principal.id, "command_started", oid)
            output, steps, state, code = "", [], "completed", None
            try:
                for command in commands:
                    if not self.store.principal_active(principal):
                        raise transport.TransportFailure("authentication_expired", sent=bool(steps))
                    text = transport.clean_output(channel.transport.run(command))
                    output = (output + text + "\n")
                    if len(output.encode()) > transport.MAX_OUTPUT:
                        raise transport.TransportFailure("output_limit_exceeded", sent=True)
                    accepted = not bool(CLI_ERROR.search(text))
                    steps.append({"command": command, "status": "prompt_returned" if accepted else "rejected"})
                    # Save each completed step immediately. No periodic transcript buffer to lose.
                    with self.store.transaction() as conn:
                        conn.execute("UPDATE terminal_operations SET output=?,updated_at=? WHERE id=?",
                                     (json.dumps({"text": output, "steps": steps}, ensure_ascii=False),
                                      self.store.clock(), oid))
                        self.store.audit(conn, principal.id, "command_step", oid,
                                         {"step": len(steps), "status": steps[-1]["status"]})
                    if not accepted:
                        state, code = ("partial" if len(steps) > 1 else "failed"), "device_command_rejected"
                        break
            except transport.TransportFailure as error:
                state = "result_unknown" if error.sent or steps else "failed"
                code = error.code
            except (OSError, sqlite3.Error):
                # A storage failure after send is not permission to re-execute.
                self.close(sid, "disconnected", "audit_or_transport_unavailable")
                raise
            if state != "completed":
                self.close(sid, "disconnected", code)
            with self.store.transaction() as conn:
                bounded_output = output.encode("utf-8")[:transport.MAX_OUTPUT].decode("utf-8", errors="ignore")
                conn.execute("UPDATE terminal_operations SET state=?,output=?,error_code=?,updated_at=? WHERE id=?",
                             (state, json.dumps({"text": bounded_output, "steps": steps},
                                                ensure_ascii=False), code, self.store.clock(), oid))
                self.store.audit(conn, principal.id, "command_" + state, oid)
            channel.last_used = time.monotonic()
            return self.operation(oid, principal)
        except sqlite3.Error:
            # Includes the final result/audit commit: a delivered command must never
            # leave an unaudited live channel available for another operation.
            try:
                self.close(sid, "disconnected", "audit_store_unavailable")
            except sqlite3.Error:
                pass
            raise
        finally:
            channel.lock.release()

    def events(self, sid, principal, after=0, limit=50):
        with self.store.transaction() as conn:
            self._session_row(conn, sid, principal)
            rows = conn.execute("""SELECT * FROM access_audit WHERE sequence>? AND
                (object_id=? OR object_id IN (SELECT id FROM terminal_operations WHERE session_id=?))
                ORDER BY sequence LIMIT ?""", (after, sid, sid, limit + 1)).fetchall()
        return {"items": [{"id": str(r["sequence"]), "action": r["action"], "objectId": r["object_id"],
                           "occurredAt": stamp(r["occurred_at"]), "details": json.loads(r["details"])}
                          for r in rows[:limit]],
                "nextCursor": str(rows[limit - 1]["sequence"]) if len(rows) > limit else None}


TERMINAL_OR_RUNNING = TERMINAL_STATES | {"executing"}
