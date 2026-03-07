import enum
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./proxy_admin.db")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class VerificationStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    failed = "failed"


class NetworkConfig(Base):
    """Singleton row (always id=1). Admin-managed network settings."""
    __tablename__ = "network_config"

    id = Column(Integer, primary_key=True, default=1)
    # Full IP pool available for router allocation
    ip_range = Column(String(18), nullable=False, default="10.0.0.0/9")
    # Prefix length for each router's subnet (e.g. 28 → /28 = 16 IPs, 14 usable)
    router_prefix = Column(Integer, nullable=False, default=28)
    # WireGuard server config — sent to clients after pairing
    server_wg_public_key = Column(String(64), nullable=True)
    server_endpoint = Column(String(253), nullable=True)   # e.g. "vpn.example.com:51820"
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
    updated_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    updated_by = relationship("User", foreign_keys="NetworkConfig.updated_by_id")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    github_id = Column(Integer, unique=True, index=True, nullable=False)
    github_login = Column(String(100), unique=True, nullable=False)
    github_name = Column(String(200), nullable=True)
    github_avatar = Column(String(500), nullable=True)
    email = Column(String(200), nullable=True)
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    domain_quota = Column(Integer, default=10, nullable=False)
    router_quota = Column(Integer, default=5, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime, nullable=True)


class InternalIP(Base):
    __tablename__ = "internal_ips"

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String(100), unique=True, nullable=False)
    # The full subnet this entry represents, e.g. "10.0.0.0/28"
    subnet = Column(String(18), nullable=True)
    # First usable host in the subnet, e.g. "10.0.0.1" — used for routing
    ip_address = Column(String(15), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    hostname = Column(String(253), nullable=True)
    is_active = Column(Boolean, default=True)
    auto_allocated = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    backend_routers = relationship("BackendRouter", back_populates="ip_address")
    created_by = relationship("User", foreign_keys="InternalIP.created_by_id")


class BackendRouter(Base):
    __tablename__ = "backend_routers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    # router_id = HMAC-SHA256(pairing_code, ROUTER_ID_SECRET) — set by admin during pairing
    router_id = Column(String(32), unique=True, nullable=True, index=True)
    pairing_status = Column(String(10), nullable=False, default="pending")  # pending|active|inactive
    first_seen_at = Column(DateTime, nullable=True)   # when router first polled
    last_seen_at = Column(DateTime, nullable=True)    # most recent poll
    wireguard_public_key = Column(String(64), nullable=True)
    ip_address_id = Column(Integer, ForeignKey("internal_ips.id"), nullable=True)
    port = Column(Integer, nullable=False, default=443)
    protocol = Column(String(10), default="https")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    ip_address = relationship("InternalIP", back_populates="backend_routers")
    sni_domains = relationship("SNIDomain", back_populates="backend_router")
    created_by = relationship("User", foreign_keys="BackendRouter.created_by_id")
    owner = relationship("User", foreign_keys="BackendRouter.owner_id")


class SNIDomain(Base):
    __tablename__ = "sni_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(253), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    backend_router_id = Column(Integer, ForeignKey("backend_routers.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    verification_token = Column(String(64), nullable=True)
    verification_status = Column(String(10), nullable=False,
                                 default=VerificationStatus.pending.value)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    backend_router = relationship("BackendRouter", back_populates="sni_domains")
    created_by = relationship("User", foreign_keys="SNIDomain.created_by_id")
    owner = relationship("User", foreign_keys="SNIDomain.owner_id")


_MIGRATIONS = [
    ("network_config",   "server_wg_public_key", "VARCHAR(64)"),
    ("network_config",   "server_endpoint",      "VARCHAR(253)"),
    ("backend_routers",  "router_id",             "VARCHAR(32)"),
    ("backend_routers",  "pairing_status",        "VARCHAR(10) NOT NULL DEFAULT 'pending'"),
    ("backend_routers",  "first_seen_at",         "DATETIME"),
    ("backend_routers",  "last_seen_at",          "DATETIME"),
    # network_config is created by create_all; only column additions needed here
    ("users",           "domain_quota",        "INTEGER NOT NULL DEFAULT 10"),
    ("users",           "router_quota",         "INTEGER NOT NULL DEFAULT 5"),
    ("internal_ips",    "subnet",               "VARCHAR(18)"),
    ("internal_ips",    "auto_allocated",       "BOOLEAN NOT NULL DEFAULT 0"),
    ("internal_ips",    "created_by_id",        "INTEGER REFERENCES users(id)"),
    ("backend_routers", "owner_id",             "INTEGER REFERENCES users(id)"),
    ("backend_routers", "wireguard_public_key", "VARCHAR(64)"),
    ("backend_routers", "created_by_id",        "INTEGER REFERENCES users(id)"),
    ("sni_domains",     "owner_id",             "INTEGER REFERENCES users(id)"),
    ("sni_domains",     "verification_token",   "VARCHAR(64)"),
    ("sni_domains",     "verification_status",  "VARCHAR(10) NOT NULL DEFAULT 'pending'"),
    ("sni_domains",     "verified_at",          "DATETIME"),
]


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for table, column, col_def in _MIGRATIONS:
            try:
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
            except Exception:
                pass  # already exists
        # Ensure singleton NetworkConfig row exists
        row = await conn.execute(text("SELECT id FROM network_config WHERE id=1"))
        if not row.fetchone():
            await conn.execute(text(
                "INSERT INTO network_config (id, ip_range, router_prefix) VALUES (1, '10.0.0.0/9', 28)"
            ))


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
