"""Schema metadata for the explicit SQLite access migration (no runtime create_all)."""
from sqlalchemy import CheckConstraint, Column, ForeignKey, Index, Integer, REAL, Table, Text, text
from app.discovery.models import Base

users = Table("auth_users", Base.metadata,
    Column("id", Text, primary_key=True), Column("username", Text, nullable=False, unique=True),
    Column("password_hash", Text, nullable=False), Column("role", Text, nullable=False),
    Column("enabled", Integer, nullable=False, server_default=text("1")),
    Column("created_at", REAL, nullable=False),
    CheckConstraint("role IN ('admin','operator','viewer')"))
sessions = Table("auth_sessions", Base.metadata,
    Column("token_hash", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("auth_users.id"), nullable=False),
    Column("csrf", Text, nullable=False), Column("created_at", REAL, nullable=False),
    Column("last_seen_at", REAL, nullable=False), Column("expires_at", REAL, nullable=False),
    Column("revoked", Integer, nullable=False, server_default=text("0")))
throttles = Table("auth_throttles", Base.metadata,
    Column("key", Text, primary_key=True), Column("failures", Integer, nullable=False),
    Column("window_start", REAL, nullable=False))
audit = Table("access_audit", Base.metadata,
    Column("sequence", Integer, primary_key=True, autoincrement=True),
    Column("occurred_at", REAL, nullable=False), Column("user_id", Text),
    Column("action", Text, nullable=False), Column("object_id", Text),
    Column("details", Text, nullable=False),
    Index("ix_access_audit_object", "object_id", "sequence"))
terminal_sessions = Table("terminal_sessions", Base.metadata,
    Column("id", Text, primary_key=True),
    Column("user_id", Text, ForeignKey("auth_users.id"), nullable=False),
    Column("auth_session_hash", Text, nullable=False), Column("target_id", Text, nullable=False),
    Column("state", Text, nullable=False), Column("created_at", REAL, nullable=False),
    Column("updated_at", REAL, nullable=False), Column("error_code", Text))
operations = Table("terminal_operations", Base.metadata,
    Column("id", Text, primary_key=True),
    Column("session_id", Text, ForeignKey("terminal_sessions.id"), nullable=False),
    Column("user_id", Text, nullable=False), Column("command_id", Text, nullable=False),
    Column("commands", Text, nullable=False), Column("risk", Text, nullable=False),
    Column("state", Text, nullable=False), Column("confirmation_hash", Text),
    Column("expires_at", REAL, nullable=False), Column("created_at", REAL, nullable=False),
    Column("updated_at", REAL, nullable=False), Column("output", Text), Column("error_code", Text),
    Index("ix_terminal_operations_session", "session_id", "created_at"))
