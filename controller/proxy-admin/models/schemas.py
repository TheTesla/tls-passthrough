from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime
import re


# ── User Schemas ─────────────────────────────────────────────────────────────

class UserOut(BaseModel):
    id: int
    github_id: int
    github_login: str
    github_name: Optional[str]
    github_avatar: Optional[str]
    email: Optional[str]
    is_admin: bool
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None


# ── InternalIP Schemas ────────────────────────────────────────────────────────

class InternalIPBase(BaseModel):
    label: str
    ip_address: str
    description: Optional[str] = None
    hostname: Optional[str] = None
    is_active: bool = True

    @field_validator("ip_address")
    @classmethod
    def validate_internal_ip(cls, v: str) -> str:
        pattern = r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if not re.match(pattern, v):
            raise ValueError("IP must be in the 10.x.x.x range")
        parts = v.split(".")
        if not all(0 <= int(p) <= 255 for p in parts):
            raise ValueError("Invalid IP address octets")
        return v


class InternalIPCreate(InternalIPBase):
    pass


class InternalIPUpdate(BaseModel):
    label: Optional[str] = None
    ip_address: Optional[str] = None
    description: Optional[str] = None
    hostname: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("ip_address")
    @classmethod
    def validate_internal_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        pattern = r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if not re.match(pattern, v):
            raise ValueError("IP must be in the 10.x.x.x range")
        return v


class InternalIPOut(InternalIPBase):
    id: int
    created_at: datetime
    updated_at: datetime
    created_by_id: Optional[int]

    model_config = {"from_attributes": True}


# ── BackendRouter Schemas ─────────────────────────────────────────────────────

class BackendRouterBase(BaseModel):
    name: str
    description: Optional[str] = None
    ip_address_id: Optional[int] = None
    port: int = 443
    protocol: str = "https"
    is_active: bool = True

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        if v not in ("http", "https", "tcp", "udp"):
            raise ValueError("Protocol must be http, https, tcp, or udp")
        return v


class BackendRouterCreate(BackendRouterBase):
    pass


class BackendRouterUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    ip_address_id: Optional[int] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    is_active: Optional[bool] = None


class BackendRouterOut(BackendRouterBase):
    id: int
    created_at: datetime
    updated_at: datetime
    created_by_id: Optional[int]
    ip_address: Optional[InternalIPOut] = None

    model_config = {"from_attributes": True}


# ── SNIDomain Schemas ─────────────────────────────────────────────────────────

class SNIDomainBase(BaseModel):
    domain: str
    description: Optional[str] = None
    backend_router_id: Optional[int] = None
    is_active: bool = True

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        pattern = r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid domain name")
        return v.lower()


class SNIDomainCreate(SNIDomainBase):
    pass


class SNIDomainUpdate(BaseModel):
    domain: Optional[str] = None
    description: Optional[str] = None
    backend_router_id: Optional[int] = None
    is_active: Optional[bool] = None


class SNIDomainOut(SNIDomainBase):
    id: int
    created_at: datetime
    updated_at: datetime
    created_by_id: Optional[int]
    backend_router: Optional[BackendRouterOut] = None

    model_config = {"from_attributes": True}


# ── Aggregated payload for full sync ─────────────────────────────────────────

class FullSync(BaseModel):
    users: list[UserOut]
    sni_domains: list[SNIDomainOut]
    backend_routers: list[BackendRouterOut]
    internal_ips: list[InternalIPOut]
    current_user: UserOut
