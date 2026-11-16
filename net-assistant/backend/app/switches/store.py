"""Persistent management endpoints; an address is not certified physical identity."""
from uuid import NAMESPACE_URL, uuid4, uuid5
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.discovery.store import Database
from app.discovery.types import utc_now
from app.switches.models import SwitchDeviceRow, SwitchRunRow
from app.switches.projection import device_kind


class SwitchStore:
    def __init__(self, db):
        self.db = db

    @staticmethod
    def device_id(scope_key, address):
        return str(uuid5(NAMESPACE_URL, "net-assistant:switch:" + scope_key + ":" + address))

    @staticmethod
    def _run(row):
        return {
            "id": row.id, "deviceId": row.device_id, "address": row.address,
            "profileId": row.profile_id, "state": row.state,
            "startedAt": row.started_at, "finishedAt": row.finished_at,
            "errorCode": row.error_code, "snapshot": row.snapshot,
        }

    def begin(self, address, profile_id, scope_key):
        if self.db.readonly:
            raise PermissionError("Switch store is read only.")
        run_id = str(uuid4())
        with Session(self.db.engine) as session, session.begin():
            device_id = self.device_id(scope_key, address)
            exists = session.scalar(select(SwitchDeviceRow.id).where(SwitchDeviceRow.id == device_id))
            session.add(SwitchRunRow(
                id=run_id, device_id=exists, scope_key=scope_key, address=address,
                profile_id=profile_id, state="running", started_at=utc_now()))
        return run_id

    def finish(self, run_id, state, *, snapshot=None, error_code=None):
        if self.db.readonly:
            raise PermissionError("Switch store is read only.")
        if state not in ("completed", "partial", "failed", "ignored", "interrupted"):
            raise ValueError("Invalid switch completion state.")
        if (state in ("completed", "partial")) != (snapshot is not None):
            raise ValueError("A successful switch attempt requires its own snapshot.")
        with Session(self.db.engine) as session, session.begin():
            run = session.scalar(select(SwitchRunRow).where(SwitchRunRow.id == run_id))
            if run is None or run.state != "running":
                raise ValueError("Unknown or already finished switch attempt.")
            now = utc_now()
            if snapshot is not None:
                device_id = self.device_id(run.scope_key, run.address)
                device = session.scalar(select(SwitchDeviceRow).where(SwitchDeviceRow.id == device_id))
                system = snapshot["system"]
                if device is None:
                    device = SwitchDeviceRow(
                        id=device_id, scope_key=run.scope_key, address=run.address,
                        name=system.get("name") or run.address, object_id=system["objectId"],
                        first_seen_at=now, last_seen_at=now)
                    session.add(device)
                    session.flush()
                    # Earlier failures to this same management endpoint remain visible in history.
                    for previous in session.scalars(select(SwitchRunRow).where(
                            SwitchRunRow.scope_key == run.scope_key, SwitchRunRow.address == run.address,
                            SwitchRunRow.device_id.is_(None))):
                        previous.device_id = device_id
                device.name = system.get("name") or run.address
                device.object_id, device.last_seen_at = system["objectId"], now
                run.device_id = device_id
            run.state, run.finished_at = state, now
            run.snapshot, run.error_code = snapshot, error_code
            session.flush()
            return self._run(run)

    def interrupt(self):
        if self.db.readonly:
            raise PermissionError("Switch store is read only.")
        # Caller must hold the single switch worker lock.
        with Session(self.db.engine) as session, session.begin():
            for row in session.scalars(select(SwitchRunRow).where(SwitchRunRow.state == "running")):
                row.state, row.finished_at, row.error_code = "interrupted", utc_now(), "previous_worker_interrupted"

    def _device(self, session, row):
        latest = session.scalar(select(SwitchRunRow).where(SwitchRunRow.device_id == row.id)
                                .order_by(SwitchRunRow.sequence.desc()).limit(1))
        return {
            "id": row.id, "address": row.address, "name": row.name,
            "objectId": row.object_id, "vendor": "Ruijie", "assetId": None,
            "deviceKind": device_kind(row.object_id),
            "identityVerified": False, "firstSeenAt": row.first_seen_at,
            "lastSeenAt": row.last_seen_at, "latest": self._run(latest) if latest else None,
        }

    def devices(self, limit=50, cursor=None):
        with Session(self.db.engine) as session:
            return Database._page(session, select(SwitchDeviceRow), SwitchDeviceRow,
                                  lambda row: self._device(session, row), limit, cursor)

    def device(self, device_id):
        with Session(self.db.engine) as session:
            row = session.scalar(select(SwitchDeviceRow).where(SwitchDeviceRow.id == device_id))
            return self._device(session, row) if row else None

    def runs(self, limit=50, cursor=None, device_id=None):
        statement = select(SwitchRunRow)
        if device_id is not None:
            statement = statement.where(SwitchRunRow.device_id == device_id)
        with Session(self.db.engine) as session:
            return Database._page(session, statement, SwitchRunRow, self._run, limit, cursor)

    def run(self, run_id):
        with Session(self.db.engine) as session:
            row = session.scalar(select(SwitchRunRow).where(SwitchRunRow.id == run_id))
            return self._run(row) if row else None
