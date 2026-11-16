"""Local collector identity and complete network snapshots, including failures."""
from alembic import op
import sqlalchemy as sa

revision = "0004_network_snapshots"
down_revision = "0003_automatic_discovery"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "network_devices",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), unique=True, nullable=False),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id")),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "network_collection_runs",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), unique=True, nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("network_devices.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id")),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("finished_at", sa.String(40)),
        sa.Column("observed_at", sa.String(40)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("snapshot", sa.JSON),
        sa.CheckConstraint("state IN ('running','completed','failed','interrupted')"),
        sa.CheckConstraint("(state = 'completed' AND snapshot IS NOT NULL AND observed_at IS NOT NULL) "
                           "OR (state != 'completed' AND snapshot IS NULL AND observed_at IS NULL)"),
    )
    op.create_index("ix_network_runs_device_sequence", "network_collection_runs",
                    ["device_id", "sequence"])


def downgrade():
    op.drop_index("ix_network_runs_device_sequence", table_name="network_collection_runs")
    op.drop_table("network_collection_runs")
    op.drop_table("network_devices")
