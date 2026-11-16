"""Platform identities, revocable sessions and durable controlled-terminal intentions."""
from alembic import op

revision = "0006_access_terminal"
down_revision = "0005_switch_collection"
branch_labels = None
depends_on = None


def upgrade():
    # Raw SQL is deliberately shared with the sqlite-only operational store.
    for statement in (
        """CREATE TABLE auth_users (
          id TEXT NOT NULL PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),
          enabled INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL)""",
        """CREATE TABLE auth_sessions (
          token_hash TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL REFERENCES auth_users(id),
          csrf TEXT NOT NULL, created_at REAL NOT NULL, last_seen_at REAL NOT NULL,
          expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)""",
        """CREATE TABLE auth_throttles (
          key TEXT NOT NULL PRIMARY KEY, failures INTEGER NOT NULL, window_start REAL NOT NULL)""",
        """CREATE TABLE access_audit (
          sequence INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, occurred_at REAL NOT NULL,
          user_id TEXT, action TEXT NOT NULL, object_id TEXT, details TEXT NOT NULL)""",
        """CREATE TABLE terminal_sessions (
          id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL REFERENCES auth_users(id),
          auth_session_hash TEXT NOT NULL, target_id TEXT NOT NULL, state TEXT NOT NULL,
          created_at REAL NOT NULL, updated_at REAL NOT NULL, error_code TEXT)""",
        """CREATE TABLE terminal_operations (
          id TEXT NOT NULL PRIMARY KEY, session_id TEXT NOT NULL REFERENCES terminal_sessions(id),
          user_id TEXT NOT NULL, command_id TEXT NOT NULL, commands TEXT NOT NULL,
          risk TEXT NOT NULL, state TEXT NOT NULL, confirmation_hash TEXT,
          expires_at REAL NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
          output TEXT, error_code TEXT)""",
        "CREATE INDEX ix_terminal_operations_session ON terminal_operations(session_id, created_at)",
        "CREATE INDEX ix_access_audit_object ON access_audit(object_id, sequence)",
    ):
        op.execute(statement)


def downgrade():
    for name in ("terminal_operations", "terminal_sessions", "access_audit",
                 "auth_throttles", "auth_sessions", "auth_users"):
        op.execute(f"DROP TABLE {name}")
