import ipaddress
import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from app.discovery.config import load_settings


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    username: str = Field(min_length=1, max_length=64)
    auth_key_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,127}$")
    priv_key_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,127}$")
    auth_protocol: Literal["SHA", "SHA256", "SHA512"] = "SHA256"
    priv_protocol: Literal["AES128"] = "AES128"
    context_name: str = Field(default="", max_length=64)


class Credentials(BaseModel):
    auth_key: SecretStr
    priv_key: SecretStr


def credentials(profile: Profile):
    # No default community/password and no credential values in configuration or API.
    auth, privacy = os.environ.get(profile.auth_key_env), os.environ.get(profile.priv_key_env)
    if not auth or not privacy or min(len(auth), len(privacy)) < 8:
        return None
    return Credentials(auth_key=auth, priv_key=privacy)


class SwitchPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    database: Path
    scan_config: Path
    storage: Path
    targets: list[str] = Field(default_factory=list, max_length=4096)
    profiles: list[Profile] = Field(default_factory=list, max_length=4)
    port: int = Field(default=161, ge=1, le=65535)
    interval_seconds: int = Field(default=300, ge=30, le=86400)
    timeout_seconds: float = Field(default=2, ge=0.2, le=10)
    target_budget_seconds: float = Field(default=45, ge=1, le=180)
    concurrency: int = Field(default=4, ge=1, le=8)
    max_rows: int = Field(default=4096, ge=1, le=16384)

    @field_validator("database", "scan_config", "storage")
    @classmethod
    def absolute(cls, value):
        if not value.is_absolute():
            raise ValueError("Switch paths must be absolute after loading.")
        return value.resolve()

    @field_validator("targets")
    @classmethod
    def numeric_targets(cls, values):
        return list(dict.fromkeys(str(ipaddress.ip_address(value)) for value in values))

    @model_validator(mode="after")
    def unique_profiles(self):
        if len({profile.id for profile in self.profiles}) != len(self.profiles):
            raise ValueError("Duplicate SNMP profile identifiers.")
        return self

    def addresses(self):
        # Reuse exactly the existing authorization validator and all exclusions.
        authorized = load_settings(self.scan_config).addresses()
        if len(authorized) > 4096:
            raise ValueError("Switch scope exceeds the 4096-address bound.")
        if self.targets:
            if set(self.targets) - set(authorized):
                raise ValueError("Switch target is outside the authorized scan scope.")
            return self.targets
        return authorized


def load_switch_plan(path):
    path = Path(path).resolve()
    values = json.loads(path.read_text(encoding="utf-8-sig"))
    for key in ("database", "scan_config", "storage"):
        if key in values:
            values[key] = (path.parent / values[key]).resolve()
    plan = SwitchPlan.model_validate(values)
    plan.addresses()  # Validation is local only; never probes the network.
    return plan


def readiness(plan):
    if not plan.enabled:
        return {"state": "disabled", "reasonCode": "switch_collection_disabled"}
    if not any(credentials(profile) for profile in plan.profiles):
        return {"state": "waiting_configuration", "reasonCode": "snmp_credentials_required"}
    return {"state": "ready", "reasonCode": None}
