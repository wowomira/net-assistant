"""Read-only switch endpoint registration and immutable collection attempts."""
from alembic import op
import sqlalchemy as sa

revision = "0005_switch_collection"
down_revision = "0004_network_snapshots"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "switch_devices",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), unique=True, nullable=False),
        sa.Column("scope_key", sa.String(64), nullable=False),
        sa.Column("address", sa.String(128), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("object_id", sa.String(512), nullable=False),
        sa.Column("first_seen_at", sa.String(40), nullable=False),
        sa.Column("last_seen_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "switch_collection_runs",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), unique=True, nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("switch_devices.id")),
        sa.Column("scope_key", sa.String(64), nullable=False),
        sa.Column("address", sa.String(128), nullable=False),
        sa.Column("profile_id", sa.String(64), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("finished_at", sa.String(40)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("snapshot", sa.JSON),
        sa.CheckConstraint("state IN ('running','completed','partial','failed','ignored','interrupted')"),
        sa.CheckConstraint("(state IN ('completed','partial') AND snapshot IS NOT NULL AND device_id IS NOT NULL) "
                           "OR (state NOT IN ('completed','partial') AND snapshot IS NULL)"),
    )
    op.create_index("ix_switch_runs_device_sequence", "switch_collection_runs", ["device_id", "sequence"])


def downgrade():
    op.drop_index("ix_switch_runs_device_sequence", table_name="switch_collection_runs")
    op.drop_table("switch_collection_runs")
    op.drop_table("switch_devices")
