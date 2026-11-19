"""Private historical-data bundles. Never migrate or write the source database."""
from collections import Counter
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workspace import check_database

# Dependency order is intentional. Auth, terminal, access audit and switch data
# are not part of this export, even when populated in the source.
BUSINESS_TABLES = (
    "discovery_scopes", "scheduled_scan_runs", "discovery_jobs",
    "discovery_hosts", "discovery_probes", "assets", "asset_discovery_links",
    "asset_audit_events", "asset_identity_decisions",
    "network_devices", "network_collection_runs",
)
EXCLUDED_TABLES = (
    "auth_users", "auth_sessions", "auth_throttles", "access_audit",
    "terminal_sessions", "terminal_operations", "switch_devices", "switch_collection_runs",
)
EXPECTED_TABLES = set(BUSINESS_TABLES + EXCLUDED_TABLES) | {"alembic_version"}
SCREENSHOT_NAME = re.compile(r"[a-f0-9]{32}\.png")
SENSITIVE_KEY = re.compile(
    r"password|passwd|passphrase|(?:^|_)pwd|secret|credential|"
    r"authorization|authentication|(?:access|refresh|bearer|session|api|auth|csrf)?token|"
    r"cookie|community|privatekey|sshkey|keyfile|keypath|apikey|"
    r"(?:snmp)?(?:auth|priv)(?:key|pass)|密码|口令|令牌|私钥", re.I,
)
PEM = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----", re.S
)
URL_USERINFO = re.compile(r"([a-z][a-z0-9+.-]*://)[^\s/@]+(?::[^\s/@]*)?@", re.I)
AUTH_HEADER = re.compile(
    r"\b(?:authorization|proxy-authorization)\s*[:=]\s*[^\r\n\"<]+", re.I
)
BEARER = re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.I)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:password|passwd|passphrase|pwd|client[_-]?secret|api[_-]?key|"
    r"(?:access[_-]?|refresh[_-]?|auth[_-]?)?token|community(?:[_-]?string)?)"
    r"\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s&,;]+)"
)
REDACTED = "[REDACTED]"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def file_hash(path):
    with Path(path).open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def readonly(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro",
                                 uri=True, timeout=5)
    connection.execute("PRAGMA query_only=ON")
    return connection


def table_names(connection):
    return {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )}


def columns(connection, table):
    return [row[1] for row in connection.execute(f"PRAGMA table_info({quote(table)})")]


def schema_hash(connection):
    definitions = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    return sha256(json.dumps(definitions, ensure_ascii=False).encode()).hexdigest()


def table_digest(connection, table):
    info = connection.execute(f"PRAGMA table_info({quote(table)})").fetchall()
    keys = [row[1] for row in sorted(info, key=lambda row: row[5]) if row[5]]
    order = ",".join(quote(name) for name in keys)
    digest = sha256()
    count = 0
    for row in connection.execute(f"SELECT * FROM {quote(table)} ORDER BY {order}"):
        digest.update(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode())
        digest.update(b"\n")
        count += 1
    return {"rows": count, "sha256": digest.hexdigest()}


def integrity(connection):
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("Database integrity check failed; no source data was changed.")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise ValueError("Database foreign-key check failed; no source data was changed.")


def sanitize(value):
    """Return sanitized evidence and a count, never values/secret field names in logs."""
    changes = 0
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9\u4e00-\u9fff]", "", key.lower())
            if SENSITIVE_KEY.search(normalized):
                changes += 1
                continue
            output[key], count = sanitize(item)
            changes += count
        return output, changes
    if isinstance(value, list):
        output = []
        for item in value:
            cleaned, count = sanitize(item)
            output.append(cleaned)
            changes += count
        return output, changes
    if not isinstance(value, str):
        return value, 0
    # JSON also occurs inside text evidence/preview fields.
    if value.lstrip().startswith(("{", "[")):
        try:
            decoded = json.loads(value)
        except (ValueError, RecursionError):
            pass
        else:
            cleaned, count = sanitize(decoded)
            if count:
                return json.dumps(cleaned, ensure_ascii=False, separators=(",", ":")), count
    for pattern, replacement in (
        (PEM, REDACTED), (URL_USERINFO, r"\1" + REDACTED + "@"),
        (AUTH_HEADER, "Authorization: " + REDACTED),
        (BEARER, REDACTED), (SECRET_ASSIGNMENT, r"\1" + REDACTED),
    ):
        value, count = pattern.subn(replacement, value)
        changes += count
    return value, changes


def initialize(path):
    sys.path.insert(0, str(ROOT / "net-assistant/backend"))
    from app import main as _models
    from app.discovery.store import initialize_database
    database = initialize_database(path)
    database.engine.dispose()
    check_database(path)


def snapshot(source, destination):
    started = now()
    deadline = time.monotonic() + 60

    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise ValueError("Snapshot timed out; retry without stopping or modifying the source.")

    with closing(readonly(source)) as original, closing(sqlite3.connect(destination)) as copy:
        original.backup(copy, pages=256, progress=progress, sleep=0.05)
        integrity(copy)
    return {"started_at": started, "completed_at": now(),
            "sha256": file_hash(destination)}


def copy_business(source, target):
    redactions = Counter()
    summary = {}
    for table in BUSINESS_TABLES:
        source_columns = columns(source, table)
        target_columns = columns(target, table)
        if source_columns != target_columns:
            raise ValueError(f"Unsupported source columns in {table}; no automatic source migration.")
        info = source.execute(f"PRAGMA table_info({quote(table)})").fetchall()
        json_columns = {row[1] for row in info if row[2].upper() == "JSON"}
        names = ",".join(quote(name) for name in target_columns)
        insert = f"INSERT INTO {quote(table)} ({names}) VALUES ({','.join('?' for _ in target_columns)})"
        expected = sha256()
        count = 0
        keys = [row[1] for row in sorted(info, key=lambda row: row[5]) if row[5]]
        order = ",".join(quote(name) for name in keys)
        for raw in source.execute(f"SELECT * FROM {quote(table)} ORDER BY {order}"):
            row = list(raw)
            for index, name in enumerate(target_columns):
                value = row[index]
                if value is None:
                    continue
                if name in json_columns:
                    try:
                        value = json.loads(value)
                    except (ValueError, TypeError):
                        raise ValueError(f"Invalid historical JSON in {table}.{name}.") from None
                    value, changed = sanitize(value)
                    # Keep unmodified JSON bytes as well as all observation timestamps.
                    if changed:
                        row[index] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                elif isinstance(value, str):
                    row[index], changed = sanitize(value)
                else:
                    changed = 0
                if changed:
                    redactions[f"{table}.{name}"] += changed
            if table == "discovery_scopes" and row != list(raw):
                index = target_columns.index("config_hash")
                config = json.loads(row[target_columns.index("config")])
                row[index] = sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            target.execute(insert, row)
            expected.update(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode())
            expected.update(b"\n")
            count += 1
        actual = table_digest(target, table)
        if actual != {"rows": count, "sha256": expected.hexdigest()}:
            raise ValueError(f"Row verification failed in {table}.")
        summary[table] = actual
    # Preserve high-water marks, including IDs deleted before this snapshot.
    if source.execute("SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'").fetchone():
        for name, sequence in source.execute("SELECT name,seq FROM sqlite_sequence"):
            if name in BUSINESS_TABLES:
                target.execute("DELETE FROM sqlite_sequence WHERE name=?", (name,))
                target.execute("INSERT INTO sqlite_sequence(name,seq) VALUES (?,?)", (name, sequence))
    return summary, dict(redactions)


def screenshots(connection, source_root, destination_root):
    entries = []
    for probe_id, evidence in connection.execute(
        "SELECT id,evidence FROM discovery_probes "
        "WHERE method='screenshot' AND status='captured' ORDER BY sequence"
    ):
        name = json.loads(evidence).get("file", "")
        entry = {"probe_id": probe_id, "status": "missing"}
        if not isinstance(name, str) or not SCREENSHOT_NAME.fullmatch(name):
            entry["reason"] = "invalid_artifact_name"
        else:
            entry["file"] = name
            original = source_root / name
            if original.resolve() != original:
                entry["reason"] = "artifact_redirected"
            elif not original.is_file():
                entry["reason"] = "artifact_missing"
            else:
                destination_root.mkdir(parents=True, exist_ok=True)
                output = destination_root / name
                shutil.copyfile(original, output)
                entry.update(status="copied", sha256=file_hash(output), bytes=output.stat().st_size)
        entries.append(entry)
    return entries


def manifest_path(path):
    return Path(path).with_suffix(".manifest.json")


def build_seed(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    bundle = destination.parent
    if not source.is_file():
        raise ValueError("Source database not found; no empty replacement was created.")
    if bundle.exists():
        raise ValueError("Seed bundle directory already exists; choose a new location, never overwrite.")
    bundle.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".seed-build-", dir=bundle.parent) as temporary:
        staging = Path(temporary)
        historical = staging / "snapshot.sqlite"
        snapshot_info = snapshot(source, historical)
        published = staging / "bundle"
        published.mkdir()
        output = published / destination.name
        initialize(output)
        with closing(readonly(historical)) as original, closing(sqlite3.connect(output)) as target:
            if not set(BUSINESS_TABLES).issubset(table_names(original)):
                raise ValueError("Source is not a compatible inspection database.")
            source_version = original.execute("SELECT version_num FROM alembic_version").fetchall()
            target_version = target.execute("SELECT version_num FROM alembic_version").fetchall()
            if source_version != target_version:
                raise ValueError("Source version differs; this exporter does not migrate historical data.")
            target.execute("PRAGMA foreign_keys=ON")
            with target:
                summary, redactions = copy_business(original, target)
            integrity(target)
            artifacts = screenshots(target, source.parent / "artifacts/screenshots",
                                    published / "artifacts/screenshots")
            skipped = [entry for entry in artifacts if entry["status"] != "copied"]
            if skipped:
                reasons = Counter(entry.get("reason", "unknown") for entry in skipped)
                print(f"Warning: {len(skipped)} screenshot(s) not exported: " + ", ".join(
                    f"{reason}={count}" for reason, count in sorted(reasons.items())), file=sys.stderr)
            manifest = {
                "format_version": 1, "created_at": now(), "private_data": True,
                "source_snapshot": snapshot_info,
                "source_schema_sha256": schema_hash(original),
                "schema_version": target_version[0][0], "schema_sha256": schema_hash(target),
                "tables": summary, "redactions": redactions, "screenshots": artifacts,
                "excluded_tables": {
                    table: original.execute(f"SELECT count(*) FROM {quote(table)}").fetchone()[0]
                    for table in sorted(table_names(original) - set(BUSINESS_TABLES)
                                        - {"alembic_version"})
                },
                "historical_only": True, "automatic_collection_enabled": False,
            }
        manifest["database_sha256"] = file_hash(output)
        manifest_path(output).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        validate_seed(output)
        # Publish only the sanitized bundle. The unsanitized snapshot is removed
        # with the private staging directory, and is never copied into the bundle.
        os.rename(published, bundle)
    return manifest


def validate_database(path, manifest):
    if file_hash(path) != manifest["database_sha256"]:
        raise ValueError("Seed checksum mismatch; no runtime data was changed.")
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() and sidecar.stat().st_size:
            raise ValueError("Seed is not standalone; journal/WAL sidecars are not allowed.")
    check_database(path)
    with closing(readonly(path)) as connection:
        connection.execute("BEGIN")
        if table_names(connection) != EXPECTED_TABLES:
            raise ValueError("Unexpected seed tables.")
        if schema_hash(connection) != manifest["schema_sha256"]:
            raise ValueError("Seed schema mismatch.")
        integrity(connection)
        for table in BUSINESS_TABLES:
            if table_digest(connection, table) != manifest["tables"][table]:
                raise ValueError(f"Seed row verification failed in {table}.")
        for table in EXCLUDED_TABLES:
            if connection.execute(f"SELECT count(*) FROM {quote(table)}").fetchone()[0]:
                raise ValueError("Seed contains excluded data; import refused.")
    return manifest


def validate_seed(path):
    path = Path(path).resolve()
    try:
        manifest = json.loads(manifest_path(path).read_text("utf-8"))
        if manifest["format_version"] != 1 or set(manifest["tables"]) != set(BUSINESS_TABLES):
            raise ValueError("Unsupported seed manifest.")
        validate_database(path, manifest)
        root = path.parent / "artifacts/screenshots"
        for entry in manifest["screenshots"]:
            if entry["status"] != "copied":
                continue
            name = entry["file"]
            if not SCREENSHOT_NAME.fullmatch(name):
                raise ValueError("Unsafe screenshot name.")
            artifact = root / name
            if (artifact.resolve() != artifact or not artifact.is_file()
                    or file_hash(artifact) != entry["sha256"]):
                raise ValueError("Screenshot checksum/path mismatch.")
    except (KeyError, TypeError, sqlite3.Error, OSError, json.JSONDecodeError):
        raise ValueError("Seed bundle is incomplete or invalid; no runtime data was changed.") from None
    return manifest


def assert_empty(connection, expected_schema):
    if table_names(connection) != EXPECTED_TABLES or schema_hash(connection) != expected_schema:
        raise ValueError("Runtime schema mismatch; no automatic migration or replacement.")
    for table in EXPECTED_TABLES - {"alembic_version"}:
        if connection.execute(f"SELECT count(*) FROM {quote(table)}").fetchone()[0]:
            raise ValueError("Runtime database must be completely empty; no overwrite or merge.")
    integrity(connection)


def publish_file(source, target):
    """Atomic no-clobber publication; staging is on the destination volume."""
    if os.name == "nt":
        os.rename(source, target)  # Windows rename never overwrites an existing file.
    else:
        os.link(source, target)
        source.unlink()


@contextmanager
def installation_lock(target):
    """Serialize artifacts and DB activation together; released by the OS on exit."""
    lock = Path(target).with_suffix(".seed-install.lock")
    if lock.is_symlink() or lock.is_junction():
        raise ValueError("Seed import lock must not be redirected.")
    with lock.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError("Another seed import is active; retry after it finishes.") from None
        try:
            yield
        finally:
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def import_seed(source, target, *, into_empty=False):
    source, target = Path(source).resolve(), Path(target).absolute()
    # Do not allow junction/symlink redirection to a working DB or personal path.
    for part in (target, *target.parents):
        if part.is_symlink() or part.is_junction():
            raise ValueError("Runtime path must not be redirected by a symlink or junction.")
    target = target.resolve()
    if target == source or target == ROOT / "net-assistant/backend/data/inspection.sqlite":
        raise ValueError("Refusing to import into the seed or original working database.")
    manifest = validate_seed(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    with installation_lock(target):
        return _install_validated_seed(source, target, manifest, into_empty=into_empty)


def _install_validated_seed(source, target, manifest, *, into_empty):
    existed = target.exists()
    if not existed and any(Path(str(target) + suffix).exists()
                           for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("Runtime has orphan SQLite sidecar files; no import or cleanup performed.")
    if existed:
        if not into_empty:
            raise ValueError("Existing runtime requires explicit --into-empty; nothing was overwritten.")
        with closing(readonly(target)) as connection:
            assert_empty(connection, manifest["schema_sha256"])
    copied = []
    try:
        with tempfile.TemporaryDirectory(prefix=".seed-import-", dir=target.parent) as temporary:
            staged = Path(temporary) / target.name
            shutil.copyfile(source, staged)
            validate_database(staged, manifest)
            root = target.parent / "artifacts/screenshots"
            for entry in manifest["screenshots"]:
                if entry["status"] != "copied":
                    continue
                artifact = root / entry["file"]
                if root.is_symlink() or root.is_junction() or (
                    root.parent.exists() and (root.parent.is_symlink() or root.parent.is_junction())
                ):
                    raise ValueError("Runtime artifact directory is redirected.")
                if artifact.exists():
                    if artifact.is_symlink() or file_hash(artifact) != entry["sha256"]:
                        raise ValueError("Existing screenshot differs; no overwrite.")
                    continue
                root.mkdir(parents=True, exist_ok=True)
                staged_artifact = Path(temporary) / entry["file"]
                shutil.copyfile(source.parent / "artifacts/screenshots" / entry["file"], staged_artifact)
                if file_hash(staged_artifact) != entry["sha256"]:
                    raise ValueError("Screenshot changed during import.")
                publish_file(staged_artifact, artifact)
                copied.append(artifact)
            if existed:
                # Keep the existing DB inode/handles. Recheck emptiness under a write
                # lock and install in one transaction, instead of replacing an open
                # SQLite file or racing a newly created account.
                with closing(sqlite3.connect(target.as_uri() + "?mode=rw", uri=True,
                                             timeout=5)) as connection:
                    connection.execute("PRAGMA foreign_keys=ON")
                    connection.execute("ATTACH DATABASE ? AS seed_source",
                                       (staged.as_uri() + "?mode=ro",))
                    try:
                        connection.execute("BEGIN IMMEDIATE")
                        assert_empty(connection, manifest["schema_sha256"])
                        for table in BUSINESS_TABLES:
                            connection.execute(
                                f"INSERT INTO {quote(table)} SELECT * FROM seed_source.{quote(table)}")
                        connection.execute("DELETE FROM sqlite_sequence")
                        connection.execute(
                            "INSERT INTO sqlite_sequence SELECT * FROM seed_source.sqlite_sequence")
                        integrity(connection)
                        for table in BUSINESS_TABLES:
                            if table_digest(connection, table) != manifest["tables"][table]:
                                raise ValueError("Transactional import verification failed.")
                        connection.commit()
                    except BaseException:
                        connection.rollback()
                        raise
            else:
                publish_file(staged, target)
    except BaseException:
        # Only remove artifact files created by this invocation, never other files.
        for artifact in copied:
            artifact.unlink(missing_ok=True)
        raise
    receipt = {
        "imported_at": now(), "seed_sha256": manifest["database_sha256"],
        "snapshot_window": manifest["source_snapshot"],
        "table_counts": {name: data["rows"] for name, data in manifest["tables"].items()},
        "accounts_imported": 0, "automatic_collection_enabled": False,
    }
    receipt_file = target.with_suffix(".seed-import.json")
    try:
        with receipt_file.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except OSError:
        # The committed import is successful even if the optional receipt cannot
        # be written. Never report rollback or delete a successfully imported DB.
        receipt["receipt_warning"] = "Import succeeded; receipt was not written."
    return receipt
