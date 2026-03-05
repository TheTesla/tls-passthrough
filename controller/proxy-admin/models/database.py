from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.ext.asyncio import async_sessionmaker
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./proxy_admin.db")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


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
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime, nullable=True)


class SNIDomain(Base):
    __tablename__ = "sni_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(253), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    backend_router_id = Column(Integer, ForeignKey("backend_routers.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    backend_router = relationship("BackendRouter", back_populates="sni_domains")
    created_by = relationship("User")


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
    created_by = relationship("User")


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
    created_by = relationship("User")


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
