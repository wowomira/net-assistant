import ipaddress
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.assets.service import canonical_mac


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Address(Record):
    address: str
    prefix_length: int = Field(ge=0, le=128)
    source: str

    @field_validator("address")
    @classmethod
    def valid_address(cls, value):
        return str(ipaddress.ip_address(value))


class Interface(Record):
    interface_index: int = Field(ge=1)
    name: str = Field(max_length=256)
    description: str | None = None
    mac: str | None = None
    state: str | None = None
    addresses: list[Address] = Field(default_factory=list)

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, value):
        if value is not None and canonical_mac(value) is None:
            raise ValueError("Invalid interface MAC.")
        return canonical_mac(value)


class Neighbor(Record):
    interface_index: int = Field(ge=1)
    address: str
    mac: str | None = None
    state: str
    online_verified: Literal[False] = False


class Forwarding(Record):
    interface_index: int = Field(ge=1)
    vlan: int = Field(ge=1, le=4094)
    mac: str

    @field_validator("mac")
    @classmethod
    def valid_mac(cls, value):
        result = canonical_mac(value)
        if result is None:
            raise ValueError("Invalid forwarding MAC.")
        return result


class LLDP(Record):
    local_interface_index: int = Field(ge=1)
    remote_chassis_id: str
    remote_port_id: str
    remote_system_name: str | None = None


class NetworkSnapshot(Record):
    source: Literal["windows_native"]
    observed_at: str
    asset_id: UUID | None = None
    identity_verified: Literal[False] = False
    interfaces: list[Interface]
    neighbors: list[Neighbor]


class SwitchSnapshot(Record):
    device_address: str
    source: Literal["snmpv3_readonly"]
    observed_at: str
    identity_verified: Literal[False] = False
    interfaces: list[Interface]
    neighbors: list[Neighbor]
    forwarding: list[Forwarding]
    lldp: list[LLDP]

    @field_validator("device_address")
    @classmethod
    def valid_device(cls, value):
        return str(ipaddress.ip_address(value))
