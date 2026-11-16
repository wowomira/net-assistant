"""Complete immutable samples; local device IDs are not inferred asset identities."""
from datetime import datetime, timezone
import json
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assets.models import AssetRow
from app.collectors.contracts import NetworkSnapshot
from app.collectors.models import NetworkDeviceRow, NetworkRunRow
from app.discovery.store import Database, scan_writer_lock
from app.discovery.types import utc_now


class NetworkStore:
    def __init__(self, database: Database):
        self.db = database

    @staticmethod
    def _run(row):
        return {
            "id": row.id, "deviceId": row.device_id, "assetId": row.asset_id,
            "source": "windows_native", "associationSource": "operator_config" if row.asset_id else None,
            "state": row.state, "startedAt": row.started_at, "finishedAt": row.finished_at,
            "observedAt": row.observed_at, "errorCode": row.error_code, "snapshot": row.snapshot,
        }

    def collect(self, device_id, label, *, asset_id=None, collector=None):
        if self.db.readonly:
            raise PermissionError("Network snapshot store is read only.")
        device_id = str(UUID(str(device_id)))
        asset_id = str(UUID(str(asset_id))) if asset_id is not None else None
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 120:
            raise ValueError("A local device label of 1..120 characters is required.")
        if collector is None:
            from app.collectors.windows import collect_network
            collector = collect_network
        # Distinct from the scan writer lock: one local query must not block a network scan.
        lock = self.db.path.parent / f"network-{device_id}.sqlite"
        with scan_writer_lock(lock):
            return self._collect(device_id, label.strip(), asset_id, collector)

    def _collect(self, device_id, label, asset_id, collector):
        run_id, now = str(uuid4()), utc_now()
        with Session(self.db.engine) as session, session.begin():
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            if asset_id and session.scalar(select(AssetRow.id).where(AssetRow.id == asset_id)) is None:
                raise ValueError("Explicit asset mapping does not exist.")
            device = session.scalar(select(NetworkDeviceRow).where(NetworkDeviceRow.id == device_id))
            if device is None:
                session.add(NetworkDeviceRow(id=device_id, label=label, asset_id=asset_id,
                                             source="windows_native", created_at=now))
                session.flush()
            elif device.asset_id != asset_id:
                raise ValueError("Explicit asset mapping differs from the registered collector device.")
            # This per-device OS lock proves there is no active same-device collection.
            for stale in session.scalars(select(NetworkRunRow).where(
                    NetworkRunRow.device_id == device_id, NetworkRunRow.state == "running")):
                stale.state, stale.finished_at = "interrupted", now
                stale.error_code = "previous_collection_interrupted"
            session.add(NetworkRunRow(id=run_id, device_id=device_id, asset_id=asset_id,
                                      state="running", started_at=now))
        payload, observed, error = None, None, None
        try:
            sample = NetworkSnapshot.model_validate(collector())
            if sample.asset_id is not None and str(sample.asset_id) != asset_id:
                raise ValueError("Collector cannot assert a different asset identity.")
            stamp = datetime.fromisoformat(sample.observed_at.replace("Z", "+00:00"))
            if stamp.tzinfo is None or (stamp - datetime.now(timezone.utc)).total_seconds() > 60:
                raise ValueError("A real observation needs a timezone and cannot be in the future.")
            sample = sample.model_copy(update={"asset_id": UUID(asset_id) if asset_id else None})
            payload = sample.model_dump(mode="json")
            if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > 4 * 1024 * 1024:
                raise ValueError("Snapshot exceeds storage budget.")
            observed = sample.observed_at
        except Exception:
            # Do not leak command output/credentials, or re-use an older successful payload.
            payload, observed, error = None, None, "windows_network_collection_failed"
        with Session(self.db.engine) as session, session.begin():
            row = session.scalar(select(NetworkRunRow).where(NetworkRunRow.id == run_id))
            row.state = "failed" if error else "completed"
            row.finished_at, row.observed_at = utc_now(), observed
            row.error_code, row.snapshot = error, payload
            session.flush()
            return self._run(row)

    def devices(self, limit=50, cursor=None):
        with Session(self.db.engine) as session:
            page = Database._page(session, select(NetworkDeviceRow), NetworkDeviceRow, lambda row: {
                "id": row.id, "label": row.label, "assetId": row.asset_id,
                "associationSource": "operator_config" if row.asset_id else None,
                "source": row.source, "createdAt": row.created_at,
            }, limit, cursor)
            return {"items": page["items"], "nextCursor": page["next_cursor"]}

    def latest(self, device_id):
        # Latest attempt, not latest success. A failed new attempt must remain visible.
        with Session(self.db.engine) as session:
            row = session.scalar(select(NetworkRunRow).where(NetworkRunRow.device_id == str(device_id))
                                 .order_by(NetworkRunRow.sequence.desc()).limit(1))
            return self._run(row) if row else None

    def history(self, device_id, limit=50, cursor=None):
        with Session(self.db.engine) as session:
            page = Database._page(session, select(NetworkRunRow).where(
                NetworkRunRow.device_id == str(device_id)), NetworkRunRow, self._run, limit, cursor)
            return {"items": page["items"], "nextCursor": page["next_cursor"]}

    def get(self, run_id):
        with Session(self.db.engine) as session:
            row = session.scalar(select(NetworkRunRow).where(NetworkRunRow.id == str(run_id)))
            return self._run(row) if row else None
