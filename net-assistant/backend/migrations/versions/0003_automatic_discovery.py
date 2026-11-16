"""Automatic asset decisions and durable daily scan execution history."""
from alembic import op
import sqlalchemy as sa

revision = "0003_automatic_discovery"
down_revision = "0002_asset_registry"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("assets", sa.Column("registration_source", sa.String(16),
                                     nullable=False, server_default="manual"))
    op.add_column("assets", sa.Column("identity_status", sa.String(24),
                                     nullable=False, server_default="manual_confirmed"))
    op.create_table(
        "asset_identity_decisions",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("discovery_host_id", sa.String(36), sa.ForeignKey("discovery_hosts.id"),
                  nullable=False, unique=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id")),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("rule", sa.String(64), nullable=False),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("decided_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "scheduled_scan_runs",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("schedule_name", sa.String(120), nullable=False),
        sa.Column("local_date", sa.String(10), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("finished_at", sa.String(40)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("config_snapshot", sa.JSON, nullable=False),
        sa.UniqueConstraint("schedule_name", "local_date"),
        sa.CheckConstraint("state IN ('running','completed','partial','failed','interrupted')"),
    )
    op.add_column("discovery_jobs", sa.Column("trigger", sa.String(16),
                                             nullable=False, server_default="manual"))
    # SQLite ADD COLUMN permits a nullable FK with a NULL default.
    op.execute("ALTER TABLE discovery_jobs ADD COLUMN schedule_run_id VARCHAR(36) "
               "REFERENCES scheduled_scan_runs(id)")


def downgrade():
    # Downgrade can discard identity/schedule history; backup before an explicit downgrade.
    with op.batch_alter_table("discovery_jobs") as batch:
        batch.drop_column("schedule_run_id")
        batch.drop_column("trigger")
    op.drop_table("scheduled_scan_runs")
    op.drop_table("asset_identity_decisions")
    with op.batch_alter_table("assets") as batch:
        batch.drop_column("identity_status")
        batch.drop_column("registration_source")
