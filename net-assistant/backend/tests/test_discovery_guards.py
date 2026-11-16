import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from app.discovery.config import ScanSettings
from app.discovery.store import initialize_database, scan_writer_lock


def test_boolean_port_is_not_silently_coerced_to_port_one():
    with pytest.raises(ValidationError):
        ScanSettings(name="bad", targets=["10.1.1.1"], ports=[True])


def test_huge_excluded_range_is_rejected_without_iterating_billions_of_addresses():
    settings = ScanSettings(name="bad", targets=["0.0.0.0/0"], exclude=["0.0.0.0/0"], ports=[80])
    with pytest.raises(ValueError, match="max_addresses"):
        settings.addresses()


def test_foreign_keys_are_enabled_and_failed_transaction_rolls_back(tmp_path):
    db = initialize_database(tmp_path / "test.sqlite")
    with pytest.raises(IntegrityError):
        db.begin_job("nonexistent-scope", 1, {})
    assert db.list_jobs()["items"] == []


def test_scan_writer_lock_rejects_second_writer_and_releases(tmp_path):
    path = tmp_path / "test.sqlite"
    with scan_writer_lock(path):
        with pytest.raises(OSError):
            with scan_writer_lock(path):
                pytest.fail("A second scan writer must not acquire the lock.")
    with scan_writer_lock(path):
        pass
