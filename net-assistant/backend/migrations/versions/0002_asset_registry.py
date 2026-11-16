"""Stable assets and explicit, retractable links; leave discovery evidence unchanged."""
from alembic import op
import sqlalchemy as sa

revision = "0002_asset_registry"
down_revision = "0001_discovery"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "assets",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("scope_id", sa.String(36), sa.ForeignKey("discovery_scopes.id"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("asset_kind", sa.String(32), nullable=False),
        sa.Column("owner", sa.String(120)),
        sa.Column("notes", sa.String(2000), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint("revision >= 1"),
    )
    op.create_table(
        "asset_discovery_links",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("discovery_host_id", sa.String(36), sa.ForeignKey("discovery_hosts.id"),
                  nullable=False, unique=True),
        sa.Column("confirmed_at", sa.String(40), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("actor", sa.String(32), nullable=False),
    )
    op.create_index("ix_asset_links_asset_sequence", "asset_discovery_links", ["asset_id", "sequence"])
    op.create_table(
        "asset_audit_events",
        sa.Column("sequence", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("id", sa.String(36), nullable=False, unique=True),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("discovery_host_id", sa.String(36), sa.ForeignKey("discovery_hosts.id")),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("actor", sa.String(32), nullable=False),
        sa.Column("asset_revision", sa.Integer, nullable=False),
        sa.Column("occurred_at", sa.String(40), nullable=False),
        sa.Column("details", sa.JSON, nullable=False),
        sa.CheckConstraint("action IN ('registered','linked','unlinked','updated')"),
    )
    op.create_index("ix_asset_audit_asset_sequence", "asset_audit_events", ["asset_id", "sequence"])


def downgrade():
    op.drop_index("ix_asset_audit_asset_sequence", table_name="asset_audit_events")
    op.drop_table("asset_audit_events")
    op.drop_index("ix_asset_links_asset_sequence", table_name="asset_discovery_links")
    op.drop_table("asset_discovery_links")
    op.drop_table("assets")
