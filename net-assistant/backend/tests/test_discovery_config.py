import json

import pytest
from pydantic import ValidationError

from app.discovery.config import ScanSettings, load_settings


def test_ranges_cidr_exclusions_and_deduplication():
    settings = ScanSettings(
        name="test",
        targets=["10.10.8.0/30", "10.10.8.2-10.10.8.4"],
        exclude=["10.10.8.3"],
        ports=[443, 80, 443],
        discovery_ports=[80],
    )
    assert settings.addresses() == ["10.10.8.1", "10.10.8.2", "10.10.8.4"]
    assert settings.ports == [80, 443]
    assert not settings.permits("10.10.9.1")
    assert not settings.permits("10.10.8.3")


@pytest.mark.parametrize("targets", [["0.0.0.0/0"], ["224.0.0.1"], ["127.0.0.1"]])
def test_unsafe_or_excessive_ranges_are_rejected(targets):
    with pytest.raises((ValueError, ValidationError)):
        ScanSettings(name="bad", targets=targets, ports=[80], discovery_ports=[80]).addresses()


def test_loopback_is_explicit_for_tests_and_small_host_ranges_work():
    settings = ScanSettings(
        name="local", targets=["127.0.0.1/32"],
        ports=[80], discovery_ports=[80], allow_loopback=True,
    )
    assert settings.addresses() == ["127.0.0.1"]


def test_invalid_ports_and_discovery_subset_are_rejected():
    with pytest.raises(ValidationError):
        ScanSettings(name="bad", targets=["10.1.1.1"], ports=[0])
    with pytest.raises(ValidationError):
        ScanSettings(name="bad", targets=["10.1.1.1"], ports=[80], discovery_ports=[22])


def test_profile_is_configuration_not_algorithm(tmp_path):
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"name": "test-profile", "ports": [22, 8080],
                                   "discovery_ports": [22], "http_ports": [8080]}))
    config = tmp_path / "scope.json"
    config.write_text(json.dumps({"name": "other-network", "targets": ["10.33.4.9"],
                                  "port_profile": "profile.json"}))
    settings = load_settings(config)
    assert settings.addresses() == ["10.33.4.9"]
    assert settings.ports == [22, 8080]
    assert settings.http_ports == [8080]


def test_scan_budget_and_address_limit_are_real_configuration():
    settings = ScanSettings(
        name="budget", targets=["10.0.0.0/29"], ports=[80], discovery_ports=[80],
        max_addresses=2,
    )
    with pytest.raises(ValueError, match="max_addresses"):
        settings.addresses()
