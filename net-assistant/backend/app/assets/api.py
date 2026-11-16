from pathlib import Path
from typing import Literal

from fastapi import APIRouter, FastAPI, Query

from app.assets.service import AssetRegistry, RegistryError
from app.discovery.api import ApiError, Page, View
from app.discovery.store import Database


class AssetView(View):
    id: str
    scope_id: str
    name: str
    asset_kind: str
    owner: str | None
    notes: str
    revision: int
    created_at: str
    updated_at: str
    management_status: Literal["managed", "discovered"]
    registration_source: Literal["manual", "automatic"]
    identity_status: Literal["manual_confirmed", "observed_mac", "mac_correlated", "needs_review"]
    identity_verified: Literal[False]
    collection_access: Literal["not_enrolled"]
    host_metrics: None
    host_metrics_status: Literal["not_collected"]
    linked_observation_count: int
    last_observed_at: str | None


class LinkedObservationView(View):
    id: str
    asset_id: str
    discovery_host_id: str
    job_id: str
    scope_id: str
    address: str
    mac: str | None
    observed_at: str
    confidence: str
    confirmed_at: str
    reason: str
    actor: Literal["local_cli", "automatic_discovery"]


class AssetAuditView(View):
    id: str
    asset_id: str
    discovery_host_id: str | None
    action: Literal["registered", "linked", "unlinked", "updated"]
    reason: str
    actor: Literal["local_cli", "automatic_discovery"]
    asset_revision: int
    occurred_at: str
    details: dict


class CandidateView(View):
    asset_id: str
    name: str
    evidence: Literal["same_scope_mac_history"]
    identity_verified: Literal[False]


class AutomaticDecisionView(View):
    outcome: Literal["existing", "registered", "linked", "skipped"]
    rule: Literal[
        "preserve_explicit_link", "no_direct_response", "missing_or_invalid_mac",
        "duplicate_mac_in_scan", "ambiguous_mac_history", "unique_mac_same_scope", "new_mac",
    ]
    asset_id: str | None
    evidence: dict
    decided_at: str


class AssociationView(View):
    discovery_host_id: str
    asset_id: str | None
    association_status: Literal["unlinked", "linked"]
    requires_confirmation: bool
    candidates: list[CandidateView]
    ambiguous: bool
    candidates_truncated: bool
    address_conflict: bool
    confirmable: bool
    collection_access: Literal["not_enrolled"]
    automatic_decision: AutomaticDecisionView | None = None


def install_asset_api(app: FastAPI, database_path: Path):
    registry = AssetRegistry(Database(database_path, readonly=True))
    router = APIRouter(prefix="/api/v1", tags=["asset registry (read only)"])

    @app.exception_handler(RegistryError)
    async def asset_error(request, error):
        # Reuse the already installed error envelope and request-id policy.
        return await app.exception_handlers[ApiError](
            request, ApiError(error.status, error.code, error.message))

    @router.get("/assets", response_model=Page[AssetView], operation_id="listAssets")
    def list_assets(limit: int = Query(50, ge=1, le=200),
                    cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        return registry.list_assets(limit, cursor)

    @router.get("/assets/{asset_id}", response_model=AssetView, operation_id="getAsset")
    def get_asset(asset_id: str):
        return registry.get_asset(asset_id)

    @router.get("/assets/{asset_id}/observations", response_model=Page[LinkedObservationView],
                operation_id="listAssetObservations")
    def observations(asset_id: str, limit: int = Query(50, ge=1, le=200),
                     cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        return registry.list_observations(asset_id, limit, cursor)

    @router.get("/assets/{asset_id}/audit", response_model=Page[AssetAuditView],
                operation_id="listAssetAuditEvents")
    def audit(asset_id: str, limit: int = Query(50, ge=1, le=200),
              cursor: str | None = Query(None, pattern=r"^[0-9]{1,18}$")):
        return registry.list_audit(asset_id, limit, cursor)

    @router.get("/discovery-hosts/{host_id}/asset-association", response_model=AssociationView,
                operation_id="getDiscoveryAssetAssociation")
    def association(host_id: str):
        return registry.association(host_id)

    app.include_router(router)
