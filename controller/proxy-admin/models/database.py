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
    domain_quota = Column(Integer, default=10, nullable=False)  # max domains per user; 0 = unlimited
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime, nullable=True)


class InternalIP(Base):
    __tablename__ = "internal_ips"

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String(100), unique=True, nullable=False)
    ip_address = Column(String(15), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    hostname = Column(String(253), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    backend_routers = relationship("BackendRouter", back_populates="ip_address")
    created_by = relationship("User", foreign_keys="InternalIP.created_by_id")


class BackendRouter(Base):
    __tablename__ = "backend_routers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    ip_address_id = Column(Integer, ForeignKey("internal_ips.id"), nullable=True)
    port = Column(Integer, nullable=False, default=443)
    protocol = Column(String(10), default="https")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    ip_address = relationship("InternalIP", back_populates="backend_routers")
    sni_domains = relationship("SNIDomain", back_populates="backend_router")
    created_by = relationship("User", foreign_keys="BackendRouter.created_by_id")


class SNIDomain(Base):
    __tablename__ = "sni_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(253), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    backend_router_id = Column(Integer, ForeignKey("backend_routers.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    verification_token = Column(String(64), nullable=True)
    verification_status = Column(String(10), nullable=False, default=VerificationStatus.pending.value)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    backend_router = relationship("BackendRouter", back_populates="sni_domains")
    created_by = relationship("User", foreign_keys="SNIDomain.created_by_id")
    owner = relationship("User", foreign_keys="SNIDomain.owner_id")


# Idempotent migrations: add columns that didn't exist in earlier schema versions
_MIGRATIONS = [
    ("users",       "domain_quota",         "INTEGER NOT NULL DEFAULT 10"),
    ("sni_domains", "owner_id",             "INTEGER REFERENCES users(id)"),
    ("sni_domains", "verification_token",   "VARCHAR(64)"),
    ("sni_domains", "verification_status",  "VARCHAR(10) NOT NULL DEFAULT 'pending'"),
    ("sni_domains", "verified_at",          "DATETIME"),
    ("backend_routers", "created_by_id",    "INTEGER REFERENCES users(id)"),
    ("internal_ips",    "created_by_id",    "INTEGER REFERENCES users(id)"),
]


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for table, column, col_def in _MIGRATIONS:
            try:
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}"))
            except Exception:
                pass  # column already exists


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
