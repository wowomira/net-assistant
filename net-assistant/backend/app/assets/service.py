"""Local confirmed identity associations; no probing or collection authorization."""
from contextlib import contextmanager
import re
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.assets.inputs import Create, Revision, Update
from app.assets.models import AssetAuditRow, AssetDecisionRow, AssetLinkRow, AssetRow
from app.discovery.models import HostRow, JobRow
from app.discovery.store import Database
from app.discovery.types import utc_now


class RegistryError(Exception):
    def __init__(self, code: str, message: str, status: int = 409):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def canonical_mac(value: str | None) -> str | None:
    if not value or not re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", value):
        return None
    raw = bytes.fromhex(value.replace(":", "").replace("-", ""))
    if not any(raw) or raw[0] & 1:
        return None
    return ":".join(f"{byte:02X}" for byte in raw)


class AssetRegistry:
    def __init__(self, database: Database):
        self.db = database

    @contextmanager
    def _write(self):
        if self.db.readonly:
            raise PermissionError("Asset registry is read only.")
        with Session(self.db.engine) as session, session.begin():
            # Serialize reads-before-writes as well as inserts; stale revisions cannot pass together.
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            yield session

    @staticmethod
    def _asset(session, asset_id):
        row = session.scalar(select(AssetRow).where(AssetRow.id == asset_id))
        if row is None:
            raise RegistryError("asset_not_found", "找不到该资产。", 404)
        return row

    @staticmethod
    def _host(session, host_id, confirmable=False):
        result = session.execute(select(HostRow, JobRow).join(
            JobRow, HostRow.job_id == JobRow.id).where(HostRow.id == host_id)).first()
        if result is None:
            raise RegistryError("discovery_host_not_found", "找不到该发现记录。", 404)
        host, job = result
        if confirmable and (host.confidence != "direct_response"
                            or job.state not in ("completed", "partial")):
            raise RegistryError("observation_not_confirmable", "仅已结束任务中的直接响应记录可确认关联。")
        return host, job

    @staticmethod
    def _revision(asset, expected):
        if asset.revision != expected:
            raise RegistryError("revision_conflict", "资产版本已变化，请读取最新版本后重试。")

    @staticmethod
    def _audit(session, asset, action, reason, host_id=None, details=None, actor="local_cli"):
        session.add(AssetAuditRow(
            id=str(uuid4()), asset_id=asset.id, discovery_host_id=host_id,
            action=action, reason=reason, actor=actor, asset_revision=asset.revision,
            occurred_at=utc_now(), details=details or {},
        ))

    @staticmethod
    def _attach(session, asset, host_id, reason, actor="local_cli"):
        session.add(AssetLinkRow(
            id=str(uuid4()), asset_id=asset.id, discovery_host_id=host_id,
            confirmed_at=utc_now(), reason=reason, actor=actor,
        ))

    @staticmethod
    def _view(session, row):
        count, last = session.execute(select(func.count(AssetLinkRow.sequence),
                                            func.max(HostRow.observed_at)).join(
            HostRow, HostRow.id == AssetLinkRow.discovery_host_id
        ).where(AssetLinkRow.asset_id == row.id)).one()
        return {**{name: getattr(row, name) for name in (
            "id", "scope_id", "name", "asset_kind", "owner", "notes", "revision",
            "created_at", "updated_at",
            "registration_source", "identity_status",
        )}, "management_status": "managed" if row.registration_source == "manual" else "discovered",
            "identity_verified": False, "collection_access": "not_enrolled",
            "host_metrics": None, "host_metrics_status": "not_collected",
            "linked_observation_count": count, "last_observed_at": last}

    def register(self, host_id, *, name, reason, asset_kind="unknown", owner=None, notes=""):
        data = Create(name=name, reason=reason, asset_kind=asset_kind, owner=owner, notes=notes)
        with self._write() as session:
            host, job = self._host(session, host_id, confirmable=True)
            if session.scalar(select(AssetLinkRow).where(AssetLinkRow.discovery_host_id == host.id)):
                raise RegistryError("observation_already_linked", "该发现记录已关联资产，不能重复登记。")
            now = utc_now()
            row = AssetRow(id=str(uuid4()), scope_id=job.scope_id, name=data.name,
                           asset_kind=data.asset_kind, owner=data.owner, notes=data.notes,
                           revision=1, created_at=now, updated_at=now)
            session.add(row)
            session.flush()  # FK parents must exist before association/audit inserts.
            self._attach(session, row, host.id, data.reason)
            self._audit(session, row, "registered", data.reason, host.id,
                        {"name": row.name, "assetKind": row.asset_kind, "owner": row.owner,
                         "notes": row.notes})
            session.flush()
            result = self._view(session, row)
        return result

    def link(self, asset_id, host_id, *, expected_revision, reason):
        data = Revision(expected_revision=expected_revision, reason=reason)
        with self._write() as session:
            asset = self._asset(session, asset_id)
            host, job = self._host(session, host_id, confirmable=True)
            if asset.scope_id != job.scope_id:
                raise RegistryError("scope_mismatch", "本轮不允许跨逻辑网络范围关联，请单独核对网络身份。")
            existing = session.scalar(select(AssetLinkRow).where(
                AssetLinkRow.discovery_host_id == host_id))
            if existing:
                if existing.asset_id != asset_id:
                    raise RegistryError("observation_already_linked", "先撤回错误关联，再确认新的资产关联。")
                return self._view(session, asset)  # Safe retry; do not append duplicate history/audit.
            self._revision(asset, data.expected_revision)
            asset.revision += 1
            asset.updated_at = utc_now()
            self._attach(session, asset, host.id, data.reason)
            self._audit(session, asset, "linked", data.reason, host.id)
            session.flush()
            result = self._view(session, asset)
        return result

    def unlink(self, asset_id, host_id, *, expected_revision, reason):
        data = Revision(expected_revision=expected_revision, reason=reason)
        with self._write() as session:
            asset = self._asset(session, asset_id)
            self._revision(asset, data.expected_revision)
            link = session.scalar(select(AssetLinkRow).where(
                AssetLinkRow.asset_id == asset_id, AssetLinkRow.discovery_host_id == host_id))
            if link is None:
                raise RegistryError("observation_not_linked", "该资产没有此当前关联。")
            details = {"linkId": link.id, "confirmedAt": link.confirmed_at,
                       "originalReason": link.reason}
            session.delete(link)
            asset.revision += 1
            asset.updated_at = utc_now()
            self._audit(session, asset, "unlinked", data.reason, host_id, details)
            session.flush()
            result = self._view(session, asset)
        return result

    def update(self, asset_id, *, expected_revision, reason, **changes):
        data = Update(expected_revision=expected_revision, reason=reason, **changes)
        supplied = data.model_fields_set - {"expected_revision", "reason"}
        if not supplied or any(getattr(data, key) is None for key in supplied - {"owner"}):
            raise RegistryError("invalid_asset_update", "需要至少一个有效元信息字段，只有负责人可以清空。", 422)
        with self._write() as session:
            asset = self._asset(session, asset_id)
            self._revision(asset, data.expected_revision)
            before = {key: getattr(asset, key) for key in supplied}
            after = {key: getattr(data, key) for key in supplied}
            if before == after:
                return self._view(session, asset)
            for key, value in after.items():
                setattr(asset, key, value)
            asset.revision += 1
            asset.updated_at = utc_now()
            self._audit(session, asset, "updated", data.reason, details={"before": before, "after": after})
            session.flush()
            result = self._view(session, asset)
        return result

    def get_asset(self, asset_id):
        with Session(self.db.engine) as session:
            return self._view(session, self._asset(session, asset_id))

    def list_assets(self, limit=50, cursor=None):
        with Session(self.db.engine) as session:
            return self.db._page(session, select(AssetRow), AssetRow,
                                 lambda row: self._view(session, row), limit, cursor)

    def list_observations(self, asset_id, limit=50, cursor=None):
        with Session(self.db.engine) as session:
            self._asset(session, asset_id)

            def view(link):
                host, job = self._host(session, link.discovery_host_id)
                return {"id": link.id, "asset_id": link.asset_id, "discovery_host_id": host.id,
                        "job_id": host.job_id, "scope_id": job.scope_id, "address": host.address,
                        "mac": host.mac, "observed_at": host.observed_at, "confidence": host.confidence,
                        "confirmed_at": link.confirmed_at, "reason": link.reason, "actor": link.actor}

            return self.db._page(session, select(AssetLinkRow).where(
                AssetLinkRow.asset_id == asset_id), AssetLinkRow, view, limit, cursor)

    def list_audit(self, asset_id, limit=50, cursor=None):
        with Session(self.db.engine) as session:
            self._asset(session, asset_id)
            return self.db._page(session, select(AssetAuditRow).where(
                AssetAuditRow.asset_id == asset_id), AssetAuditRow,
                lambda row: {key: getattr(row, key) for key in (
                    "id", "asset_id", "discovery_host_id", "action", "reason", "actor",
                    "asset_revision", "occurred_at", "details",
                )}, limit, cursor)

    def association(self, host_id):
        """Bounded same-scope hints; never associate by name or IP or transfer trust."""
        with Session(self.db.engine) as session:
            host, job = self._host(session, host_id)
            linked = session.scalar(select(AssetLinkRow.asset_id).where(
                AssetLinkRow.discovery_host_id == host_id))
            mac = canonical_mac(host.mac)
            # Normalize legacy MAC spelling inside SQL; all matches still require manual confirmation.
            normalized = func.upper(func.replace(HostRow.mac, "-", ":"))
            base = select(AssetRow.id).join(
                AssetLinkRow, AssetLinkRow.asset_id == AssetRow.id
            ).join(HostRow, HostRow.id == AssetLinkRow.discovery_host_id).where(
                AssetRow.scope_id == job.scope_id)
            ids = list(session.scalars(base.where(normalized == mac).distinct()
                                       .order_by(AssetRow.id).limit(21))) if mac else []
            candidates = [{"asset_id": item, "name": self._asset(session, item).name,
                           "evidence": "same_scope_mac_history", "identity_verified": False}
                          for item in ids[:20]]
            # An IP reuse warning is only evidence from previously confirmed links, not identity proof.
            same_address = base.where(HostRow.address == host.address)
            if mac:
                same_address = same_address.where(
                    (HostRow.mac.is_(None)) | (normalized != mac))
            address_conflict = session.scalar(same_address.limit(1)) is not None
            decision = session.scalar(select(AssetDecisionRow).where(
                AssetDecisionRow.discovery_host_id == host_id))
            return {
                "discovery_host_id": host_id, "asset_id": linked,
                "association_status": "linked" if linked else "unlinked",
                "requires_confirmation": linked is None, "candidates": candidates,
                "ambiguous": len(ids) > 1, "candidates_truncated": len(ids) > 20,
                "address_conflict": address_conflict,
                "confirmable": host.confidence == "direct_response"
                               and job.state in ("completed", "partial"),
                "collection_access": "not_enrolled",
                "automatic_decision": {
                    "outcome": decision.outcome, "rule": decision.rule,
                    "asset_id": decision.asset_id, "evidence": decision.evidence,
                    "decided_at": decision.decided_at,
                } if decision else None,
            }
