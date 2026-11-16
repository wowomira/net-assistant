"""Explainable network-observation correlation, never ownership or authentication."""
from collections import Counter
from uuid import uuid4

from sqlalchemy import func, select

from app.assets.models import AssetDecisionRow, AssetLinkRow, AssetRow
from app.assets.service import AssetRegistry, canonical_mac
from app.discovery.models import HostRow, JobRow, ProbeRow
from app.discovery.types import safe_text, utc_now


ACTOR = "automatic_discovery"


def reconcile_job(db, job_id):
    """Atomically reconcile a finished scan. The caller owns the process scan lock.

    Missing/ambiguous identity still gets an independent needs_review file, not an
    IP-based merge. Decisions survive unlink so replay cannot undo corrections.
    """
    registry = AssetRegistry(db)
    summary = {name: 0 for name in ("registered", "linked", "existing", "skipped", "already_processed")}
    with registry._write() as session:
        job = session.scalar(select(JobRow).where(JobRow.id == job_id))
        if job is None or job.state not in ("completed", "partial"):
            raise ValueError("Automatic registration requires a completed or partial job.")
        hosts = list(session.scalars(select(HostRow).where(
            HostRow.job_id == job_id).order_by(HostRow.sequence)))
        counts = Counter(canonical_mac(host.mac) for host in hosts if canonical_mac(host.mac))
        normalized = func.upper(func.replace(HostRow.mac, "-", ":"))
        for host in hosts:
            previous = session.scalar(select(AssetDecisionRow).where(
                AssetDecisionRow.discovery_host_id == host.id))
            if previous:
                summary["already_processed"] += 1
                continue
            linked_id = session.scalar(select(AssetLinkRow.asset_id).where(
                AssetLinkRow.discovery_host_id == host.id))
            mac = canonical_mac(host.mac)
            evidence = {
                "policyVersion": 1, "scopeId": job.scope_id, "mac": mac,
                "address": host.address, "confidence": host.confidence,
                "sameScanMacCount": counts.get(mac, 0), "identityVerified": False,
            }
            asset_id = linked_id
            if linked_id:
                outcome, rule = "existing", "preserve_explicit_link"
            elif host.confidence != "direct_response":
                outcome, rule = "skipped", "no_direct_response"
            else:
                matches = list(session.scalars(select(AssetRow.id).join(
                    AssetLinkRow, AssetLinkRow.asset_id == AssetRow.id
                ).join(HostRow, HostRow.id == AssetLinkRow.discovery_host_id).where(
                    AssetRow.scope_id == job.scope_id, normalized == mac
                ).distinct().order_by(AssetRow.id).limit(2))) if mac else []
                evidence["historicalAssetCandidates"] = matches
                if not mac:
                    rule = "missing_or_invalid_mac"
                elif counts[mac] > 1:
                    rule = "duplicate_mac_in_scan"
                elif len(matches) > 1:
                    rule = "ambiguous_mac_history"
                elif len(matches) == 1:
                    rule = "unique_mac_same_scope"
                else:
                    rule = "new_mac"
                now = utc_now()
                if rule == "unique_mac_same_scope":
                    asset = registry._asset(session, matches[0])
                    asset.revision += 1
                    asset.updated_at = now
                    # Preserve manual classification and metadata.
                    if asset.registration_source == "automatic":
                        asset.identity_status = "mac_correlated"
                    outcome, action = "linked", "linked"
                else:
                    names = session.scalars(select(ProbeRow).where(
                        ProbeRow.job_id == job_id, ProbeRow.address == host.address,
                        ProbeRow.method == "name", ProbeRow.status == "resolved",
                    ).order_by(ProbeRow.sequence.desc()))
                    observed_name = next((row.evidence.get("hostname") for row in names
                                          if row.evidence.get("hostname")), None)
                    asset = AssetRow(
                        id=str(uuid4()), scope_id=job.scope_id,
                        name=safe_text(observed_name, 120) if observed_name else f"发现设备 {host.address}",
                        asset_kind="unknown",
                        owner=None, notes="", revision=1, created_at=now, updated_at=now,
                        registration_source="automatic",
                        identity_status="observed_mac" if rule == "new_mac" else "needs_review",
                    )
                    session.add(asset)
                    session.flush()
                    outcome, action = "registered", "registered"
                asset_id = asset.id
                # 管理关联只依据观测线索，不授予采集权限或设备认证。
                reason = f"自动资产策略 v1：{rule}"
                registry._attach(session, asset, host.id, reason, actor=ACTOR)
                registry._audit(session, asset, action, reason, host.id,
                                details={"rule": rule, **evidence}, actor=ACTOR)
            session.add(AssetDecisionRow(
                discovery_host_id=host.id, asset_id=asset_id, outcome=outcome,
                rule=rule, evidence=evidence, decided_at=utc_now(),
            ))
            session.flush()
            summary[outcome] += 1
    return summary
