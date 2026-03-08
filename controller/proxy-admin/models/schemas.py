from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime
import re


# ── User Schemas ──────────────────────────────────────────────────────────────

class UserOut(BaseModel):
    id: int
    github_id: int
    github_login: str
    github_name: Optional[str]
    github_avatar: Optional[str]
    email: Optional[str]
    is_admin: bool
    is_active: bool
    domain_quota: int
    router_quota: int
    created_at: datetime
    last_login: Optional[datetime]

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    """Admin-only fields."""
    is_active: Optional[bool] = None
    domain_quota: Optional[int] = None
    router_quota: Optional[int] = None
    is_admin: Optional[bool] = None


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
        if not re.match(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v):
            raise ValueError("IP muss im Bereich 10.x.x.x liegen")
        if not all(0 <= int(p) <= 255 for p in v.split(".")):
            raise ValueError("Ungültige IP-Adresse")
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
        if not re.match(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v):
            raise ValueError("IP muss im Bereich 10.x.x.x liegen")
        return v


class InternalIPOut(InternalIPBase):
    id: int
    subnet: Optional[str] = None
    auto_allocated: bool = False
    created_at: datetime
    updated_at: datetime
    created_by_id: Optional[int]

    model_config = {"from_attributes": True}


# ── BackendRouter Schemas ─────────────────────────────────────────────────────

class BackendRouterBase(BaseModel):
    name: str
    description: Optional[str] = None
    port: int = 443
    protocol: str = "https"
    enabled: bool = True

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Port muss zwischen 1 und 65535 liegen")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        if v not in ("http", "https", "tcp", "udp"):
            raise ValueError("Protokoll muss http, https, tcp oder udp sein")
        return v


class BackendRouterCreate(BackendRouterBase):
    """pairing_code is optional: if given, wg_public_key is resolved from the pairing request."""
    pairing_code: Optional[str] = None

    @field_validator("pairing_code")
    @classmethod
    def validate_code(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = re.sub(r'[^A-Z2-9]', '', v.strip().upper())
        if len(v) == 8:
            v = v[:4] + '-' + v[4:]
        if not re.match(r"^[A-Z2-9]{4}-[A-Z2-9]{4}$", v):
            raise ValueError("Ungültiger Pairing-Code (Format: XXXX-XXXX oder XXXXXXXX)")
        return v


class BackendRouterUpdate(BaseModel):
    """Fields any owner can update."""
    name: Optional[str] = None
    description: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    enabled: Optional[bool] = None


class BackendRouterAdminUpdate(BackendRouterUpdate):
    """Additional fields only admins may set."""
    ip_address_id: Optional[int] = None


class BackendRouterOut(BackendRouterBase):
    id: int
    owner_id: Optional[int]
    # Set by controller from pairing_code — public identifier
    router_id: Optional[str] = None
    device_status: str = "uninitialized"  # uninitialized | ok | error
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    poll_interval: int = 30  # expected polling interval in seconds
    # WireGuard public key sent by the router device during polling
    wireguard_public_key: Optional[str] = None
    ip_address_id: Optional[int]
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
        if not re.match(r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", v):
            raise ValueError("Ungültiger Domainname")
        return v.lower()


class SNIDomainCreate(SNIDomainBase):
    pass


class SNIDomainUpdate(BaseModel):
    description: Optional[str] = None
    backend_router_id: Optional[int] = None
    is_active: Optional[bool] = None


class SNIDomainOut(SNIDomainBase):
    id: int
    owner_id: Optional[int]
    verification_token: Optional[str]
    verification_status: str
    verified_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    created_by_id: Optional[int]
    backend_router: Optional[BackendRouterOut] = None

    model_config = {"from_attributes": True}


class VerifyResult(BaseModel):
    success: bool
    message: str
    verification_status: str


# ── Full Sync ─────────────────────────────────────────────────────────────────

class FullSync(BaseModel):
    users: list[UserOut]
    sni_domains: list[SNIDomainOut]
    backend_routers: list[BackendRouterOut]
    internal_ips: list[InternalIPOut]
    current_user: UserOut
    network_config: Optional["NetworkConfigOut"] = None


# ── Pairing Schemas ───────────────────────────────────────────────────────────

class PairingStatusResponse(BaseModel):
    enabled: bool = True
    router_id: Optional[int] = None
    router_name: Optional[str] = None
    subnet: Optional[str] = None
    ip_address: Optional[str] = None
    wg_public_key: Optional[str] = None
    server_wg_public_key: Optional[str] = None
    server_endpoint: Optional[str] = None
    device_status: Optional[str] = None
    poll_interval: int = 10



# ── NetworkConfig Schemas ─────────────────────────────────────────────────────

class NetworkConfigOut(BaseModel):
    ip_range: str
    router_prefix: int
    server_wg_public_key: Optional[str] = None
    server_endpoint: Optional[str] = None
    updated_at: Optional[datetime]

    model_config = {"from_attributes": True}


class NetworkConfigUpdate(BaseModel):
    ip_range: Optional[str] = None
    router_prefix: Optional[int] = None
    server_wg_public_key: Optional[str] = None
    server_endpoint: Optional[str] = None

    @field_validator("ip_range")
    @classmethod
    def validate_ip_range(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            import ipaddress
            net = ipaddress.ip_network(v, strict=True)
            if not str(net.network_address).startswith("10."):
                raise ValueError("Nur 10.x.x.x Netzwerke erlaubt")
            return str(net)
        except ValueError as e:
            raise ValueError(f"Ungültiges Netzwerk: {e}")

    @field_validator("router_prefix")
    @classmethod
    def validate_prefix(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return v
        if not (8 <= v <= 30):
            raise ValueError("Präfixlänge muss zwischen 8 und 30 liegen")
        return v
