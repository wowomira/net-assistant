from contextlib import closing, contextmanager
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, event, inspect, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.discovery.config import ROOT, ScanSettings
from app.discovery.models import HostRow, JobRow, ProbeRow, ScopeRow
from app.discovery.types import ProbeResult, bounded_evidence, utc_now


class Database:
    def __init__(self, path: Path, readonly: bool = False):
        self.path = Path(path).resolve()
        self.readonly = readonly

        def connect():
            if readonly:
                return sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True,
                                       check_same_thread=False, timeout=5)
            return sqlite3.connect(str(self.path), check_same_thread=False, timeout=5)

        self.engine = create_engine(
            "sqlite+pysqlite://", creator=connect, poolclass=NullPool,
            json_serializer=lambda value: json.dumps(value, ensure_ascii=False, separators=(",", ":")),
        )

        @event.listens_for(self.engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            if readonly:
                connection.execute("PRAGMA query_only=ON")

    def save_scope(self, settings: ScanSettings) -> tuple[str, int]:
        config = settings.snapshot()
        digest = sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        with Session(self.engine) as session, session.begin():
            row = session.scalar(select(ScopeRow).where(ScopeRow.name == settings.name))
            if row is None:
                row = ScopeRow(id=str(uuid4()), name=settings.name, revision=1,
                               config_hash=digest, config=config, updated_at=utc_now())
                session.add(row)
            elif row.config_hash != digest:
                row.revision += 1
                row.config_hash = digest
                row.config = config
                row.updated_at = utc_now()
            return row.id, row.revision

    def begin_job(self, scope_id: str, revision: int, snapshot: dict,
                  trigger="manual", schedule_run_id=None) -> str:
        job_id = str(uuid4())
        with Session(self.engine) as session, session.begin():
            session.add(JobRow(
                id=job_id, scope_id=scope_id, scope_revision=revision, state="running",
                started_at=utc_now(), finished_at=None, config_snapshot=snapshot,
                coverage={}, error_code=None, trigger=trigger, schedule_run_id=schedule_run_id,
            ))
        return job_id

    @staticmethod
    def _probe(job_id: str, result: ProbeResult) -> ProbeRow:
        return ProbeRow(
            id=str(uuid4()), job_id=job_id, address=result.address,
            phase=result.phase, method=result.method, port=result.port,
            status=result.status, duration_ms=max(0, result.duration_ms),
            reason_code=result.reason_code, evidence=bounded_evidence(result.evidence),
            observed_at=result.observed_at,
        )

    def record_probes(self, job_id: str, results: list[ProbeResult]) -> None:
        with Session(self.engine) as session, session.begin():
            session.add_all([self._probe(job_id, result) for result in results])

    def record_discovery(self, job_id: str, address: str, results: list[ProbeResult],
                         host: dict | None) -> None:
        with Session(self.engine) as session, session.begin():
            session.add_all([self._probe(job_id, result) for result in results])
            if host is not None:
                session.add(HostRow(id=str(uuid4()), job_id=job_id, address=address,
                                    observed_at=utc_now(), **host))

    def confirm_host(self, job_id: str, address: str) -> None:
        with Session(self.engine) as session, session.begin():
            row = session.scalar(select(HostRow).where(
                HostRow.job_id == job_id, HostRow.address == address,
            ))
            if row:
                row.confidence = "direct_response"

    def set_host_mac(self, job_id: str, address: str, mac: str) -> None:
        from app.assets.service import canonical_mac
        value = canonical_mac(mac)
        if value is None:
            raise ValueError("Invalid observed MAC.")
        with Session(self.engine) as session, session.begin():
            row = session.scalar(select(HostRow).where(HostRow.job_id == job_id, HostRow.address == address))
            if row and row.mac is None:
                row.mac = value

    def finish_job(self, job_id: str, state: str, coverage: dict,
                   error_code: str | None = None) -> None:
        with Session(self.engine) as session, session.begin():
            row = session.scalar(select(JobRow).where(JobRow.id == job_id))
            if row is None:
                raise ValueError("Unknown job.")
            row.state, row.coverage, row.error_code = state, dict(coverage), error_code
            if state != "running":
                row.finished_at = utc_now()

    def interrupt_stale_jobs(self) -> int:
        # Called only after the CLI has acquired the database's single-writer lock.
        with Session(self.engine) as session, session.begin():
            rows = list(session.scalars(select(JobRow).where(JobRow.state == "running")))
            for row in rows:
                row.state = "interrupted"
                row.finished_at = utc_now()
                row.error_code = "previous_process_interrupted"
            return len(rows)

    @staticmethod
    def _job(row: JobRow) -> dict:
        result = {name: getattr(row, name) for name in (
            "id", "scope_id", "scope_revision", "state", "started_at",
            "finished_at", "config_snapshot", "coverage", "error_code",
            "trigger", "schedule_run_id",
        )}
        # 保留原库历史，不再把旧 VM 文件配置或说明文案作为工具输出。
        result["config_snapshot"] = {
            key: value for key, value in row.config_snapshot.items() if key != "vmware_context_files"
        }
        result["coverage"] = {
            key: value for key, value in row.coverage.items() if key != "coverageMeaning"
        }
        return result

    def get_job(self, job_id: str) -> dict | None:
        with Session(self.engine) as session:
            row = session.scalar(select(JobRow).where(JobRow.id == job_id))
            return self._job(row) if row else None

    @staticmethod
    def _page(session: Session, statement, table, mapper, limit: int, cursor: str | None):
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200.")
        after = int(cursor or 0)
        if after < 0:
            raise ValueError("Invalid cursor.")
        # The paginated entity is the first selected value. Additional joined
        # columns can be mapped without running separate queries per item.
        rows = session.execute(statement.where(table.sequence > after)
                               .order_by(table.sequence).limit(limit + 1)).all()
        return {"items": [mapper(*row) for row in rows[:limit]],
                "next_cursor": str(rows[limit - 1][0].sequence) if len(rows) > limit else None}

    def list_jobs(self, limit: int = 50, cursor: str | None = None) -> dict:
        with Session(self.engine) as session:
            return self._page(session, select(JobRow), JobRow, self._job, limit, cursor)

    def list_hosts(self, job_id: str, limit: int = 50, cursor: str | None = None) -> dict:
        with Session(self.engine) as session:
            return self._page(session, select(HostRow).where(HostRow.job_id == job_id),
                              HostRow, lambda row: self._host_view(session, row), limit, cursor)

    @staticmethod
    def _host_view(session, row):
        from app.assets.models import AssetLinkRow
        from app.discovery.inventory import summarize_inventory
        asset_id = session.scalar(select(AssetLinkRow.asset_id).where(
            AssetLinkRow.discovery_host_id == row.id))
        observations = [Database._probe_view(probe) for probe in session.scalars(select(ProbeRow).where(
            ProbeRow.job_id == row.job_id, ProbeRow.address == row.address).order_by(ProbeRow.sequence))]
        job = session.scalar(select(JobRow).where(JobRow.id == row.job_id))
        inventory = summarize_inventory(row.address, observations, job.config_snapshot)
        ports = [service["port"] for service in inventory["services"]]
        return {**{name: getattr(row, name) for name in (
            "id", "job_id", "address", "mac", "discovery_methods",
            "confidence", "observed_at", "management_status", "collection_access", "asset_kind",
        )}, **inventory, "open_ports": ports, "asset_id": asset_id,
            "association_status": "linked" if asset_id else "unlinked"}

    @staticmethod
    def _probe_view(row):
        result = {name: getattr(row, name) for name in (
            "id", "job_id", "address", "phase", "method", "port", "status",
            "duration_ms", "reason_code", "evidence", "observed_at",
        )}
        if row.method == "arp":
            # 旧版写入的说明段落不是测量证据，读出时不再附带；原库不改写。
            result["evidence"] = {key: value for key, value in row.evidence.items() if key != "note"}
        return result

    def list_probes(self, job_id: str, limit: int = 50, cursor: str | None = None,
                    address: str | None = None, method: str | None = None,
                    status: str | None = None) -> dict:
        statement = select(ProbeRow).where(ProbeRow.job_id == job_id)
        for field, value in (("address", address), ("method", method), ("status", status)):
            if value is not None:
                statement = statement.where(getattr(ProbeRow, field) == value)
        with Session(self.engine) as session:
            return self._page(session, statement, ProbeRow, self._probe_view, limit, cursor)

    def scan_snapshot(self, job_id: str) -> dict | None:
        # 报告和比对在同一个读事务内取数；不迁移、不发包、不写业务记录。
        with Session(self.engine) as session, session.begin():
            session.connection().exec_driver_sql("BEGIN")
            current = session.scalar(select(JobRow).where(JobRow.id == job_id))
            if current is None:
                return None

            def read(row):
                return {
                    "job": self._job(row),
                    "hosts": [self._host_view(session, host) for host in session.scalars(
                        select(HostRow).where(HostRow.job_id == row.id).order_by(HostRow.sequence))],
                    "probes": [self._probe_view(probe) for probe in session.scalars(
                        select(ProbeRow).where(ProbeRow.job_id == row.id).order_by(ProbeRow.sequence))],
                }

            previous = session.scalar(select(JobRow).where(
                JobRow.scope_id == current.scope_id, JobRow.sequence < current.sequence,
                JobRow.state.in_(("completed", "partial")),
                JobRow.finished_at <= current.started_at,
            ).order_by(JobRow.sequence.desc()).limit(1))
            return {**read(current), "previous": read(previous) if previous else None}


def backup_database(path: Path) -> Path:
    """Consistent SQLite backup, validated before a migration may modify the source."""
    path = Path(path).resolve()
    directory = path.parent / "backups"
    directory.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().replace(":", "").replace("-", "").replace(".", "")
    target = directory / f"{path.stem}.pre-migration.{stamp}.{uuid4().hex[:8]}.sqlite"
    with target.open("xb"):
        pass
    try:
        # sqlite3.Connection's context manager commits/rolls back but does not
        # close the native handle. Explicit closing is essential on Windows.
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as source:
            with closing(sqlite3.connect(target)) as destination:
                source.backup(destination)
                if destination.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise ValueError("Pre-migration backup integrity check failed.")
                if destination.execute("PRAGMA foreign_key_check").fetchall():
                    raise ValueError("Pre-migration backup foreign-key check failed.")
    except Exception:
        # Keep failed backup for diagnostics; never proceed to migrate after failure.
        raise
    return target


def initialize_database(path: Path) -> Database:
    # Import all mapped tables so SQLAlchemy resolves foreign keys in either entry point.
    from app.scheduling import models as _schedule_models
    from app.collectors import models as _collector_models
    from app.switches import models as _switch_models
    from app.auth import models as _auth_models
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = Database(path)
    names = set(inspect(db.engine).get_table_names())
    allowed = {"alembic_version", "discovery_scopes", "discovery_jobs",
               "discovery_hosts", "discovery_probes", "assets",
               "asset_discovery_links", "asset_audit_events", "asset_identity_decisions",
               "scheduled_scan_runs", "network_devices", "network_collection_runs",
               "switch_devices", "switch_collection_runs",
               "auth_users", "auth_sessions", "auth_throttles", "access_audit",
               "terminal_sessions", "terminal_operations"}
    if names - allowed:
        raise ValueError("Refusing to migrate an unrelated database (including shared progress).")
    config = Config()
    config.set_main_option("script_location", str(ROOT / "migrations"))
    with db.engine.connect() as connection:
        current_heads = set(MigrationContext.configure(connection).get_current_heads())
    desired_heads = set(ScriptDirectory.from_config(config).get_heads())
    if names and current_heads != desired_heads:
        backup_database(path)
    with db.engine.begin() as connection:
        # sqlite3 legacy transaction mode does not BEGIN for DDL. Start explicitly so
        # a failed migration rolls back both schema changes and version changes.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    return db


class ScanBusyError(OSError):
    """A live scan/registry writer owns the lock, distinct from storage failure."""


@contextmanager
def scan_writer_lock(path: Path):
    """OS releases the lock on process exit; no stale PID-file guessing."""
    lock_path = Path(path).resolve().with_suffix(".scan.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if __import__("os").name == "nt":
            import msvcrt
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                if error.errno not in (11, 13, 36):
                    raise
                raise ScanBusyError("Another scan or registry writer is active.") from error
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ScanBusyError("Another scan or registry writer is active.") from error
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
