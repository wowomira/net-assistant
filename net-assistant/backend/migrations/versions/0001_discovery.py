"""Independent discovery records, not the Node shared progress database."""
from alembic import op
import sqlalchemy as sa

revision = "0001_discovery"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "discovery_scopes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False, unique=True),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("config", sa.JSON, nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "discovery_jobs",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("scope_id", sa.String(36), sa.ForeignKey("discovery_scopes.id"), nullable=False),
        sa.Column("scope_revision", sa.Integer, nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("finished_at", sa.String(40)),
        sa.Column("config_snapshot", sa.JSON, nullable=False),
        sa.Column("coverage", sa.JSON, nullable=False),
        sa.Column("error_code", sa.String(80)),
        sa.CheckConstraint("state IN ('running','completed','partial','failed','interrupted')"),
    )
    op.create_table(
        "discovery_hosts",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("discovery_jobs.id"), nullable=False),
        sa.Column("address", sa.String(15), nullable=False),
        sa.Column("mac", sa.String(32)),
        sa.Column("discovery_methods", sa.JSON, nullable=False),
        sa.Column("context", sa.JSON, nullable=False),
        sa.Column("confidence", sa.String(40), nullable=False),
        sa.Column("management_status", sa.String(24), nullable=False),
        sa.Column("collection_access", sa.String(24), nullable=False),
        sa.Column("asset_kind", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.String(40), nullable=False),
        sa.UniqueConstraint("job_id", "address"),
    )
    op.create_table(
        "discovery_probes",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("discovery_jobs.id"), nullable=False),
        sa.Column("address", sa.String(15), nullable=False),
        sa.Column("phase", sa.String(20), nullable=False),
        sa.Column("method", sa.String(20), nullable=False),
        sa.Column("port", sa.Integer),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("duration_ms", sa.Float, nullable=False),
        sa.Column("reason_code", sa.String(80)),
        sa.Column("evidence", sa.JSON, nullable=False),
        sa.Column("observed_at", sa.String(40), nullable=False),
        sa.CheckConstraint("port IS NULL OR (port >= 1 AND port <= 65535)"),
        sa.CheckConstraint("duration_ms >= 0"),
    )
    op.create_index("ix_discovery_probes_job_address", "discovery_probes",
                    ["job_id", "address", "sequence"])


def downgrade():
    op.drop_index("ix_discovery_probes_job_address", table_name="discovery_probes")
    for name in ("discovery_probes", "discovery_hosts", "discovery_jobs", "discovery_scopes"):
        op.drop_table(name)
