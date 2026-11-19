"""SQLite transactions are durable before any success response or network mutation."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from uuid import uuid4

from app.discovery.api import ApiError


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str) -> str:
    if not 12 <= len(password) <= 128:
        raise ValueError("Password must contain 12 to 128 characters.")
    salt = secrets.token_bytes(16)
    # OWASP scrypt option N=2^15, r=8, p=3; no external package or system changes.
    value = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=3, maxmem=64 * 1024**2)
    return f"scrypt${salt.hex()}${value.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        method, salt, expected = stored.split("$")
        if method != "scrypt" or len(password) > 128:
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=3,
                                maxmem=64 * 1024**2).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Principal:
    id: str
    username: str
    role: str
    session_hash: str
    csrf: str
    expires_at: float

    def view(self):
        return {"id": self.id, "username": self.username, "role": self.role}


class AuthStore:
    def __init__(self, path: Path, clock=time.time):
        self.path = Path(path).resolve()
        self.clock = clock

    @contextmanager
    def transaction(self, *, readonly=False):
        # Neither connection mode creates a database when setup is incomplete.
        mode = "ro" if readonly else "rw"
        conn = sqlite3.connect(self.path.as_uri() + f"?mode={mode}", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("BEGIN" if readonly else "BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def audit(self, conn, user_id, action, object_id=None, details=None):
        conn.execute("INSERT INTO access_audit(occurred_at,user_id,action,object_id,details) VALUES(?,?,?,?,?)",
                     (self.clock(), user_id, action, object_id,
                      json.dumps(details or {}, ensure_ascii=False, separators=(",", ":"))))

    def create_user(self, username, password, role="viewer"):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,64}", username) or role not in ("admin", "operator", "viewer"):
            raise ValueError("Invalid username or role.")
        encoded = password_hash(password)
        user_id = str(uuid4())
        with self.transaction() as conn:
            conn.execute("INSERT INTO auth_users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                         (user_id, username.lower(), encoded, role, self.clock()))
            self.audit(conn, user_id, "user_created")
        return user_id

    def disable_user(self, username):
        with self.transaction() as conn:
            user = conn.execute("SELECT id FROM auth_users WHERE username=?", (username.lower(),)).fetchone()
            if not user:
                raise ValueError("Unknown user.")
            conn.execute("UPDATE auth_users SET enabled=0 WHERE id=?", (user["id"],))
            conn.execute("UPDATE auth_sessions SET revoked=1 WHERE user_id=?", (user["id"],))
            self.audit(conn, user["id"], "user_disabled")

    def reset_password(self, username, password):
        encoded = password_hash(password)
        with self.transaction() as conn:
            user = conn.execute("SELECT id FROM auth_users WHERE username=?", (username.lower(),)).fetchone()
            if not user:
                raise ValueError("Unknown user.")
            self._replace_password(conn, user["id"], encoded)

    def _replace_password(self, conn, user_id, encoded):
        conn.execute("UPDATE auth_users SET password_hash=? WHERE id=?", (encoded, user_id))
        conn.execute("UPDATE auth_sessions SET revoked=1 WHERE user_id=?", (user_id,))
        self.audit(conn, user_id, "password_reset")

    def login(self, username, password, address):
        now = self.clock()
        username = username.lower()
        keys = (digest("user:" + username), digest("ip:" + address))
        # Hashing happens outside the write transaction; failed attempts still atomically counted.
        with self.transaction(readonly=True) as conn:
            for key, maximum in zip(keys, (5, 25)):
                row = conn.execute("SELECT * FROM auth_throttles WHERE key=?", (key,)).fetchone()
                if row and now - row["window_start"] < 300 and row["failures"] >= maximum:
                    raise ApiError(429, "login_rate_limited", "登录尝试过多，请稍后重试。")
            user = conn.execute("SELECT * FROM auth_users WHERE username=?", (username,)).fetchone()
        # A constant dummy hash gives unknown accounts the same expensive password check.
        stored = user["password_hash"] if user else ("scrypt$" + "00" * 16 + "$" + "00" * 64)
        valid = verify_password(password, stored)
        error = None
        with self.transaction() as conn:
            # Re-check under the same lock that increments failures / creates a session.
            for key, maximum in zip(keys, (5, 25)):
                row = conn.execute("SELECT * FROM auth_throttles WHERE key=?", (key,)).fetchone()
                if row and now - row["window_start"] < 300 and row["failures"] >= maximum:
                    raise ApiError(429, "login_rate_limited", "登录尝试过多，请稍后重试。")
            fresh = conn.execute("SELECT * FROM auth_users WHERE username=?", (username,)).fetchone()
            if not valid or not fresh or not fresh["enabled"] or fresh["password_hash"] != stored:
                for key in keys:
                    conn.execute("""INSERT INTO auth_throttles VALUES(?,1,?)
                        ON CONFLICT(key) DO UPDATE SET
                        failures=CASE WHEN ?-window_start>=300 THEN 1 ELSE failures+1 END,
                        window_start=CASE WHEN ?-window_start>=300 THEN ? ELSE window_start END""",
                                 (key, now, now, now, now))
                self.audit(conn, None, "login_failed")
                error = ApiError(401, "invalid_credentials", "用户名或密码错误。")
            else:
                conn.execute("DELETE FROM auth_throttles WHERE key=?", (keys[0],))
                token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                conn.execute("INSERT INTO auth_sessions VALUES(?,?,?,?,?,?,0)",
                             (digest(token), fresh["id"], csrf, now, now, now + 28800))
                self.audit(conn, fresh["id"], "login_succeeded")
                result = {"token": token, "csrfToken": csrf, "expiresAt": now + 28800,
                          "user": {"id": fresh["id"], "username": fresh["username"], "role": fresh["role"]}}
        if error:
            raise error
        return result

    def authenticate(self, token) -> Principal | None:
        if not token or len(token) > 256:
            return None
        token_hash = digest(token)
        with self.transaction() as conn:
            now = self.clock()
            row = conn.execute("""SELECT u.id,u.username,u.role,u.enabled,s.* FROM auth_sessions s
                JOIN auth_users u ON u.id=s.user_id WHERE token_hash=?""", (token_hash,)).fetchone()
            if not row or row["revoked"] or not row["enabled"]:
                return None
            if row["expires_at"] <= now or now - row["last_seen_at"] >= 1800:
                conn.execute("UPDATE auth_sessions SET revoked=1 WHERE token_hash=?", (token_hash,))
                return None
            conn.execute("UPDATE auth_sessions SET last_seen_at=? WHERE token_hash=?", (now, token_hash))
            return Principal(row["id"], row["username"], row["role"], token_hash, row["csrf"],
                             row["expires_at"])

    def _active_user(self, conn, principal):
        now = self.clock()
        return conn.execute("""SELECT u.password_hash FROM auth_sessions s
            JOIN auth_users u ON u.id=s.user_id
            WHERE s.token_hash=? AND u.id=? AND u.enabled=1 AND s.revoked=0
              AND s.expires_at>? AND s.last_seen_at>?""",
            (principal.session_hash, principal.id, now, now - 1800)).fetchone()

    def principal_active(self, principal):
        with self.transaction(readonly=True) as conn:
            return self._active_user(conn, principal) is not None

    def logout(self, principal):
        with self.transaction() as conn:
            conn.execute("UPDATE auth_sessions SET revoked=1 WHERE token_hash=?", (principal.session_hash,))
            self.audit(conn, principal.id, "logout")

    def change_password(self, principal, current_password, new_password):
        with self.transaction(readonly=True) as conn:
            user = self._active_user(conn, principal)
        if not user:
            raise ApiError(401, "authentication_required", "请先登录平台。")
        if not verify_password(current_password, user["password_hash"]):
            raise ApiError(401, "invalid_credentials", "当前密码错误。")
        encoded = password_hash(new_password)
        # scrypt runs outside the write lock. Recheck both the authorizing session
        # and the verified password under the lock before the credential update.
        with self.transaction() as conn:
            fresh = self._active_user(conn, principal)
            if not fresh or fresh["password_hash"] != user["password_hash"]:
                raise ApiError(401, "authentication_required", "请先登录平台。")
            self._replace_password(conn, principal.id, encoded)
