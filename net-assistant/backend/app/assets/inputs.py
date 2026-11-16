from typing import Literal
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

AssetKind = Literal["unknown", "server", "workstation", "virtual_machine", "network_device", "other"]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="before")
    @classmethod
    def reject_controls(cls, value):
        if isinstance(value, str) and re.search(r"[\x00-\x08\x0b-\x1f\x7f]", value):
            raise ValueError("Control characters are not allowed.")
        return value


class Reason(Input):
    reason: str = Field(min_length=1, max_length=500)


class Create(Reason):
    name: str = Field(min_length=1, max_length=120)
    asset_kind: AssetKind = "unknown"
    owner: str | None = Field(default=None, min_length=1, max_length=120)
    notes: str = Field(default="", max_length=2000)


class Revision(Reason):
    expected_revision: int = Field(strict=True, ge=1)


class Update(Revision):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    asset_kind: AssetKind | None = None
    owner: str | None = Field(default=None, min_length=1, max_length=120)
    notes: str | None = Field(default=None, max_length=2000)
