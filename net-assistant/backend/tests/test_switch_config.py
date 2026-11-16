"""All addresses and credentials in this module are isolated fixtures."""
import json
import pytest
from pydantic import ValidationError


def config(tmp_path, **overrides):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({
        "name": "isolated-switch-test", "targets": ["10.99.0.0/30"],
        "exclude": ["10.99.0.1"], "ports": [80],
    }), encoding="utf-8")
    values = {
        "enabled": True, "database": str(tmp_path / "test.sqlite"),
        "scan_config": str(scope), "storage": str(tmp_path / "runtime"),
        "profiles": [{"id": "lab", "username": "readonly",
                      "auth_key_env": "TEST_SWITCH_AUTH", "priv_key_env": "TEST_SWITCH_PRIV"}],
    }
    values.update(overrides)
    path = tmp_path / "switches.json"
    path.write_text(json.dumps(values), encoding="utf-8")
    return path


def test_scope_expansion_preserves_exclusions_and_explicit_target_restriction(tmp_path):
    from app.switches.config import load_switch_plan
    plan = load_switch_plan(config(tmp_path))
    assert plan.addresses() == ["10.99.0.2"]
    with pytest.raises(ValueError, match="authorized"):
        load_switch_plan(config(tmp_path, targets=["10.100.0.1"])).addresses()


def test_missing_credentials_never_supply_default_password_and_secrets_are_redacted(tmp_path, monkeypatch):
    from app.switches.config import load_switch_plan, credentials
    monkeypatch.delenv("TEST_SWITCH_AUTH", raising=False)
    monkeypatch.delenv("TEST_SWITCH_PRIV", raising=False)
    plan = load_switch_plan(config(tmp_path))
    assert credentials(plan.profiles[0]) is None
    monkeypatch.setenv("TEST_SWITCH_AUTH", "isolated-auth-secret")
    monkeypatch.setenv("TEST_SWITCH_PRIV", "isolated-priv-secret")
    value = credentials(plan.profiles[0])
    assert value.auth_key.get_secret_value() == "isolated-auth-secret"
    assert "isolated-auth-secret" not in repr(value)
    assert "isolated-priv-secret" not in value.model_dump_json()


def test_insecure_protocols_duplicate_profiles_and_excessive_scope_rejected(tmp_path):
    from app.switches.config import load_switch_plan
    with pytest.raises(ValidationError):
        load_switch_plan(config(tmp_path, profiles=[{
            "id": "bad", "username": "readonly", "auth_key_env": "X", "priv_key_env": "Y",
            "auth_protocol": "NONE",
        }]))
    profile = {"id": "same", "username": "readonly", "auth_key_env": "X", "priv_key_env": "Y"}
    with pytest.raises(ValueError):
        load_switch_plan(config(tmp_path, profiles=[profile, profile]))
    path = config(tmp_path)
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"name": "too-large", "targets": ["10.0.0.0/8"],
                                 "ports": [80]}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_switch_plan(path).addresses()
