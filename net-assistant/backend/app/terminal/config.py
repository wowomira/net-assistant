"""Only an operator-controlled server file can enroll SSH destinations and key paths."""
import ipaddress
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    label: str = Field(min_length=1, max_length=120)
    address: str
    port: int = Field(default=22, ge=1, le=65535, strict=True)
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{1,64}$")
    private_key: Path
    known_hosts: Path
    vendor: Literal["ruijie", "cisco", "huawei", "h3c"]
    platform: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=120)
    compatibility_confirmed: bool = False
    allowed_users: list[str] = Field(default_factory=list, max_length=100)
    allowed_commands: list[str] = Field(default_factory=list, max_length=30)
    command_timeout_seconds: int = Field(default=15, ge=1, le=60)

    @field_validator("address")
    @classmethod
    def address_is_literal(cls, value):
        parsed = ipaddress.ip_address(value)
        if parsed.is_unspecified or parsed.is_multicast or "%" in value:
            raise ValueError("Use one explicitly enrolled unicast IP, not a hostname or subnet.")
        return str(parsed)

    @field_validator("private_key", "known_hosts")
    @classmethod
    def absolute_file(cls, path):
        if not path.is_absolute() or not path.is_file():
            raise ValueError("SSH key and known_hosts must be existing absolute server file paths.")
        return path.resolve()

    @model_validator(mode="after")
    def platform_matches_vendor(self):
        expected = {"ruijie": "rgos", "cisco": "ios", "huawei": "vrp", "h3c": "comware"}
        if self.platform != expected[self.vendor]:
            raise ValueError("Unsupported vendor/platform combination.")
        if any(user != user.lower() for user in self.allowed_users):
            raise ValueError("Platform usernames are lowercase.")
        return self

    def view(self):
        return {"id": self.id, "label": self.label, "address": self.address, "port": self.port,
                "vendor": self.vendor, "platform": self.platform, "version": self.version,
                "compatibilityConfirmed": self.compatibility_confirmed,
                "authenticationMethod": "server_private_key", "hostKeyPolicy": "strict_known_hosts"}


class TerminalPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    targets: list[Target] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_ids(self):
        if len({t.id for t in self.targets}) != len(self.targets):
            raise ValueError("Duplicate terminal target IDs.")
        return self


def load_plan(path: Path | None):
    if path is None:
        return TerminalPlan()
    if not path.is_absolute():
        raise ValueError("Terminal configuration path must be absolute.")
    return TerminalPlan.model_validate(json.loads(path.read_text(encoding="utf-8")))
