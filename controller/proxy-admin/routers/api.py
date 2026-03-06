import secrets
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from models.database import get_db, User, SNIDomain, BackendRouter, InternalIP, VerificationStatus
from models.schemas import (
    SNIDomainCreate, SNIDomainUpdate, SNIDomainOut, VerifyResult,
    BackendRouterCreate, BackendRouterUpdate, BackendRouterOut,
    InternalIPCreate, InternalIPUpdate, InternalIPOut,
    UserOut, UserUpdate, FullSync,
)
from routers.auth import require_user, require_admin

api_router = APIRouter(prefix="/api", tags=["api"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _can_modify_domain(domain: SNIDomain, user: User) -> bool:
    """Owner or admin may edit/delete a domain."""
    return user.is_admin or domain.owner_id == user.id


def _domain_q():
    return select(SNIDomain).options(
        selectinload(SNIDomain.backend_router).selectinload(BackendRouter.ip_address)
    )


async def _check_txt_record(domain: str, token: str) -> bool:
    try:
        import dns.resolver
        check_name = f"_proxy-verify.{domain.lstrip('*.')}"
        answers = dns.resolver.resolve(check_name, "TXT", lifetime=10)
        for rdata in answers:
            for string in rdata.strings:
                if string.decode("utf-8", errors="ignore") == token:
                    return True
    except Exception:
        pass
    return False


def _generate_token() -> str:
    return "proxy-verify=" + secrets.token_hex(24)


# ── Full Sync ─────────────────────────────────────────────────────────────────

@api_router.get("/sync", response_model=FullSync)
async def full_sync(
    current_user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    users_q = await db.execute(select(User).order_by(User.github_login))
    sni_q = await db.execute(_domain_q().order_by(SNIDomain.domain))
    router_q = await db.execute(
        select(BackendRouter).options(selectinload(BackendRouter.ip_address)).order_by(BackendRouter.name)
    )
    ip_q = await db.execute(select(InternalIP).order_by(InternalIP.label))

    return FullSync(
        users=[UserOut.model_validate(u) for u in users_q.scalars().all()],
        sni_domains=[SNIDomainOut.model_validate(d) for d in sni_q.scalars().all()],
        backend_routers=[BackendRouterOut.model_validate(r) for r in router_q.scalars().all()],
        internal_ips=[InternalIPOut.model_validate(i) for i in ip_q.scalars().all()],
        current_user=UserOut.model_validate(current_user),
    )


# ── Internal IPs (Admin: write; all: read) ────────────────────────────────────

@api_router.get("/ips", response_model=list[InternalIPOut])
async def list_ips(current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InternalIP).order_by(InternalIP.label))
    return [InternalIPOut.model_validate(r) for r in result.scalars().all()]


@api_router.post("/ips", response_model=InternalIPOut, status_code=201)
async def create_ip(body: InternalIPCreate, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(InternalIP).where(InternalIP.ip_address == body.ip_address))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "IP-Adresse existiert bereits")
    ip = InternalIP(**body.model_dump(), created_by_id=current_user.id)
    db.add(ip)
    await db.commit()
    await db.refresh(ip)
    return InternalIPOut.model_validate(ip)


@api_router.put("/ips/{ip_id}", response_model=InternalIPOut)
async def update_ip(ip_id: int, body: InternalIPUpdate, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InternalIP).where(InternalIP.id == ip_id))
    ip = result.scalar_one_or_none()
    if not ip:
        raise HTTPException(404, "IP nicht gefunden")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(ip, k, v)
    ip.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(ip)
    return InternalIPOut.model_validate(ip)


@api_router.delete("/ips/{ip_id}", status_code=204)
async def delete_ip(ip_id: int, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InternalIP).where(InternalIP.id == ip_id))
    ip = result.scalar_one_or_none()
    if not ip:
        raise HTTPException(404, "IP nicht gefunden")
    await db.delete(ip)
    await db.commit()


# ── Backend Routers (Admin: write; all: read) ─────────────────────────────────

@api_router.get("/routers", response_model=list[BackendRouterOut])
async def list_routers(current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(BackendRouter).options(selectinload(BackendRouter.ip_address)).order_by(BackendRouter.name)
    )
    return [BackendRouterOut.model_validate(r) for r in result.scalars().all()]


@api_router.post("/routers", response_model=BackendRouterOut, status_code=201)
async def create_router(body: BackendRouterCreate, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(BackendRouter).where(BackendRouter.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Router-Name existiert bereits")
    r = BackendRouter(**body.model_dump(), created_by_id=current_user.id)
    db.add(r)
    await db.commit()
    result = await db.execute(
        select(BackendRouter).options(selectinload(BackendRouter.ip_address)).where(BackendRouter.id == r.id)
    )
    return BackendRouterOut.model_validate(result.scalar_one())


@api_router.put("/routers/{router_id}", response_model=BackendRouterOut)
async def update_router(router_id: int, body: BackendRouterUpdate, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(BackendRouter).options(selectinload(BackendRouter.ip_address)).where(BackendRouter.id == router_id)
    )
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Router nicht gefunden")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(r, k, v)
    r.updated_at = datetime.now(timezone.utc)
    await db.commit()
    result2 = await db.execute(
        select(BackendRouter).options(selectinload(BackendRouter.ip_address)).where(BackendRouter.id == router_id)
    )
    return BackendRouterOut.model_validate(result2.scalar_one())


@api_router.delete("/routers/{router_id}", status_code=204)
async def delete_router(router_id: int, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BackendRouter).where(BackendRouter.id == router_id))
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Router nicht gefunden")
    await db.delete(r)
    await db.commit()


# ── SNI Domains (all users: full CRUD on own domains) ─────────────────────────

@api_router.get("/domains", response_model=list[SNIDomainOut])
async def list_domains(current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(_domain_q().order_by(SNIDomain.domain))
    return [SNIDomainOut.model_validate(d) for d in result.scalars().all()]


@api_router.post("/domains", response_model=SNIDomainOut, status_code=201)
async def create_domain(body: SNIDomainCreate, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    # Check quota (0 = unlimited, admins are always unlimited)
    if not current_user.is_admin and current_user.domain_quota > 0:
        count_q = await db.execute(
            select(func.count()).select_from(SNIDomain).where(SNIDomain.owner_id == current_user.id)
        )
        current_count = count_q.scalar_one()
        if current_count >= current_user.domain_quota:
            raise HTTPException(
                403,
                f"Domain-Quota erreicht ({current_count}/{current_user.domain_quota}). "
                "Bitte einen Admin kontaktieren."
            )

    existing = await db.execute(select(SNIDomain).where(SNIDomain.domain == body.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Domain existiert bereits")

    token = _generate_token()
    d = SNIDomain(
        **body.model_dump(),
        created_by_id=current_user.id,
        owner_id=current_user.id,
        verification_token=token,
        verification_status=VerificationStatus.pending.value,
    )
    db.add(d)
    await db.commit()
    result = await db.execute(_domain_q().where(SNIDomain.id == d.id))
    return SNIDomainOut.model_validate(result.scalar_one())


@api_router.post("/domains/{domain_id}/verify", response_model=VerifyResult)
async def verify_domain(domain_id: int, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SNIDomain).where(SNIDomain.id == domain_id))
    d = result.scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Domain nicht gefunden")
    if not _can_modify_domain(d, current_user):
        raise HTTPException(403, "Nur der Eigentümer oder ein Admin kann diese Domain verifizieren")
    if d.verification_status == VerificationStatus.verified.value:
        return VerifyResult(success=True, message="Bereits verifiziert", verification_status="verified")

    found = await _check_txt_record(d.domain, d.verification_token)
    if found:
        d.verification_status = VerificationStatus.verified.value
        d.verified_at = datetime.now(timezone.utc)
        msg = "Domain erfolgreich verifiziert!"
    else:
        d.verification_status = VerificationStatus.failed.value
        bare = d.domain.lstrip("*.")
        msg = f"TXT-Record nicht gefunden. Bitte setze:\n_proxy-verify.{bare}  TXT  \"{d.verification_token}\""
    await db.commit()
    return VerifyResult(success=found, message=msg, verification_status=d.verification_status)


@api_router.post("/domains/{domain_id}/reset-token", response_model=SNIDomainOut)
async def reset_verification_token(domain_id: int, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SNIDomain).where(SNIDomain.id == domain_id))
    d = result.scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Domain nicht gefunden")
    if not _can_modify_domain(d, current_user):
        raise HTTPException(403, "Nur der Eigentümer oder ein Admin kann das Token zurücksetzen")
    d.verification_token = _generate_token()
    d.verification_status = VerificationStatus.pending.value
    d.verified_at = None
    await db.commit()
    result2 = await db.execute(_domain_q().where(SNIDomain.id == domain_id))
    return SNIDomainOut.model_validate(result2.scalar_one())


@api_router.put("/domains/{domain_id}", response_model=SNIDomainOut)
async def update_domain(domain_id: int, body: SNIDomainUpdate, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(_domain_q().where(SNIDomain.id == domain_id))
    d = result.scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Domain nicht gefunden")
    if not _can_modify_domain(d, current_user):
        raise HTTPException(403, "Nur der Eigentümer oder ein Admin kann diese Domain bearbeiten")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(d, k, v)
    d.updated_at = datetime.now(timezone.utc)
    await db.commit()
    result2 = await db.execute(_domain_q().where(SNIDomain.id == domain_id))
    return SNIDomainOut.model_validate(result2.scalar_one())


@api_router.delete("/domains/{domain_id}", status_code=204)
async def delete_domain(domain_id: int, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SNIDomain).where(SNIDomain.id == domain_id))
    d = result.scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Domain nicht gefunden")
    if not _can_modify_domain(d, current_user):
        raise HTTPException(403, "Nur der Eigentümer oder ein Admin kann diese Domain löschen")
    await db.delete(d)
    await db.commit()


# ── Users (Admin: write; all: read own) ──────────────────────────────────────

@api_router.get("/users", response_model=list[UserOut])
async def list_users(current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.github_login))
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@api_router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    body: UserUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if user_id == current_user.id and body.is_active is False:
        raise HTTPException(400, "Du kannst dich nicht selbst deaktivieren")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Nutzer nicht gefunden")

    if body.is_active is not None:
        user.is_active = body.is_active
    if body.domain_quota is not None:
        if body.domain_quota < 0:
            raise HTTPException(400, "Quota muss >= 0 sein (0 = unbegrenzt)")
        user.domain_quota = body.domain_quota
    if body.is_admin is not None and user_id != current_user.id:
        user.is_admin = body.is_admin

    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@api_router.delete("/users/{user_id}", status_code=204)
async def delete_user(user_id: int, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if user_id == current_user.id:
        raise HTTPException(400, "Du kannst dich nicht selbst löschen")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Nutzer nicht gefunden")
    await db.delete(user)
    await db.commit()
