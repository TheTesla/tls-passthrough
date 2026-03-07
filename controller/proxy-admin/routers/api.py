import ipaddress
import secrets
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from models.database import get_db, User, SNIDomain, BackendRouter, InternalIP, NetworkConfig, VerificationStatus
from models.schemas import (
    SNIDomainCreate, SNIDomainUpdate, SNIDomainOut, VerifyResult,
    BackendRouterCreate, BackendRouterUpdate, BackendRouterAdminUpdate, BackendRouterOut,
    InternalIPCreate, InternalIPUpdate, InternalIPOut,
    UserOut, UserUpdate, FullSync,
    NetworkConfigOut, NetworkConfigUpdate,
)
from routers.auth import require_user, require_admin
from routers.router_auth import compute_router_id

api_router = APIRouter(prefix="/api", tags=["api"])


# ── IP allocation helpers ─────────────────────────────────────────────────────

async def _get_config(db: AsyncSession) -> NetworkConfig:
    result = await db.execute(select(NetworkConfig).where(NetworkConfig.id == 1))
    cfg = result.scalar_one_or_none()
    if not cfg:
        cfg = NetworkConfig(id=1, ip_range="10.0.0.0/9", router_prefix=28)
        db.add(cfg)
        await db.commit()
        await db.refresh(cfg)
    return cfg


async def _allocate_ip(db: AsyncSession, cfg: NetworkConfig, label: str, created_by_id: int) -> InternalIP:
    """Carve the next free subnet from the pool and create an InternalIP record."""
    pool = ipaddress.ip_network(cfg.ip_range, strict=True)
    prefix = cfg.router_prefix

    if prefix <= pool.prefixlen:
        raise HTTPException(400, f"Router-Präfix /{prefix} ist nicht kleiner als Pool-Präfix /{pool.prefixlen}")

    # Collect all already-allocated subnets
    used_q = await db.execute(
        select(InternalIP.subnet).where(InternalIP.subnet.is_not(None))
    )
    used_subnets = {row[0] for row in used_q.fetchall()}

    # Find first free subnet
    for subnet in pool.subnets(new_prefix=prefix):
        subnet_str = str(subnet)
        if subnet_str not in used_subnets:
            first_host = str(list(subnet.hosts())[0])
            ip = InternalIP(
                label=label,
                subnet=subnet_str,
                ip_address=first_host,
                auto_allocated=True,
                is_active=True,
                created_by_id=created_by_id,
                description=f"Auto-alloziert aus {cfg.ip_range} (/{prefix})",
            )
            db.add(ip)
            await db.flush()  # get ip.id without committing
            return ip

    raise HTTPException(503, f"Kein freies Subnetz mehr im Pool {cfg.ip_range}/{prefix}")


# ── General helpers ───────────────────────────────────────────────────────────

def _can_modify_domain(domain: SNIDomain, user: User) -> bool:
    return user.is_admin or domain.owner_id == user.id


def _can_modify_router(router: BackendRouter, user: User) -> bool:
    return user.is_admin or router.owner_id == user.id


def _domain_q():
    return select(SNIDomain).options(
        selectinload(SNIDomain.backend_router).selectinload(BackendRouter.ip_address)
    )


def _router_q():
    return select(BackendRouter).options(selectinload(BackendRouter.ip_address))


async def _check_txt_record(domain: str, token: str) -> bool:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(f"_proxy-verify.{domain.lstrip('*.')}", "TXT", lifetime=10)
        for rdata in answers:
            for string in rdata.strings:
                if string.decode("utf-8", errors="ignore") == token:
                    return True
    except Exception:
        pass
    return False


def _generate_token() -> str:
    return "proxy-verify=" + secrets.token_hex(24)


async def _count_owned(db: AsyncSession, model, owner_id: int) -> int:
    q = await db.execute(select(func.count()).select_from(model).where(model.owner_id == owner_id))
    return q.scalar_one()


# ── Network Config (Admin) ────────────────────────────────────────────────────

@api_router.get("/config", response_model=NetworkConfigOut)
async def get_config(current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    return NetworkConfigOut.model_validate(await _get_config(db))


@api_router.put("/config", response_model=NetworkConfigOut)
async def update_config(
    body: NetworkConfigUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    cfg = await _get_config(db)
    if body.ip_range is not None:
        new_pool = ipaddress.ip_network(body.ip_range, strict=True)
        used_q = await db.execute(
            select(InternalIP.subnet).where(InternalIP.auto_allocated == True)
        )
        for row in used_q.fetchall():
            if row[0]:
                allocated = ipaddress.ip_network(row[0], strict=True)
                if not allocated.subnet_of(new_pool):
                    raise HTTPException(400,
                        f"Bereits alloziertes Subnetz {row[0]} liegt außerhalb des neuen Pools {body.ip_range}. "
                        "Bitte erst die betroffenen Router löschen.")
        cfg.ip_range = body.ip_range
    if body.router_prefix is not None:
        cfg.router_prefix = body.router_prefix
    if body.server_wg_public_key is not None:
        cfg.server_wg_public_key = body.server_wg_public_key or None
    if body.server_endpoint is not None:
        cfg.server_endpoint = body.server_endpoint or None
    cfg.updated_by_id = current_user.id
    cfg.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(cfg)
    return NetworkConfigOut.model_validate(cfg)


# ── Full Sync ─────────────────────────────────────────────────────────────────

@api_router.get("/sync", response_model=FullSync)
async def full_sync(
    current_user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    users_q   = await db.execute(select(User).order_by(User.github_login))
    sni_q     = await db.execute(_domain_q().order_by(SNIDomain.domain))
    router_q  = await db.execute(_router_q().order_by(BackendRouter.name))
    ip_q      = await db.execute(select(InternalIP).order_by(InternalIP.ip_address))
    cfg       = await _get_config(db)

    return FullSync(
        users=           [UserOut.model_validate(u) for u in users_q.scalars().all()],
        sni_domains=     [SNIDomainOut.model_validate(d) for d in sni_q.scalars().all()],
        backend_routers= [BackendRouterOut.model_validate(r) for r in router_q.scalars().all()],
        internal_ips=    [InternalIPOut.model_validate(i) for i in ip_q.scalars().all()],
        current_user=    UserOut.model_validate(current_user),
        network_config=  NetworkConfigOut.model_validate(cfg),
    )


# ── Internal IPs (Admin: manual CRUD; auto-allocation is internal) ────────────

@api_router.get("/ips", response_model=list[InternalIPOut])
async def list_ips(current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InternalIP).order_by(InternalIP.ip_address))
    return [InternalIPOut.model_validate(r) for r in result.scalars().all()]


@api_router.post("/ips", response_model=InternalIPOut, status_code=201)
async def create_ip(body: InternalIPCreate, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(InternalIP).where(InternalIP.ip_address == body.ip_address))).scalar_one_or_none():
        raise HTTPException(400, "IP-Adresse existiert bereits")
    ip = InternalIP(**body.model_dump(), created_by_id=current_user.id, auto_allocated=False)
    db.add(ip)
    await db.commit()
    await db.refresh(ip)
    return InternalIPOut.model_validate(ip)


@api_router.put("/ips/{ip_id}", response_model=InternalIPOut)
async def update_ip(ip_id: int, body: InternalIPUpdate, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    ip = (await db.execute(select(InternalIP).where(InternalIP.id == ip_id))).scalar_one_or_none()
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
    ip = (await db.execute(select(InternalIP).where(InternalIP.id == ip_id))).scalar_one_or_none()
    if not ip:
        raise HTTPException(404, "IP nicht gefunden")
    # Check if any router still uses this IP
    used = (await db.execute(select(BackendRouter).where(BackendRouter.ip_address_id == ip_id))).scalar_one_or_none()
    if used:
        raise HTTPException(400, f"IP wird noch von Router \"{used.name}\" verwendet")
    await db.delete(ip)
    await db.commit()


# ── Backend Routers ───────────────────────────────────────────────────────────


@api_router.get("/routers", response_model=list[BackendRouterOut])
async def list_routers(current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(_router_q().order_by(BackendRouter.name))
    return [BackendRouterOut.model_validate(r) for r in result.scalars().all()]


@api_router.post("/routers", response_model=BackendRouterOut, status_code=201)
async def create_router(body: BackendRouterCreate, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    # Quota check
    if not current_user.is_admin and current_user.router_quota > 0:
        count = await _count_owned(db, BackendRouter, current_user.id)
        if count >= current_user.router_quota:
            raise HTTPException(403,
                f"Router-Quota erreicht ({count}/{current_user.router_quota}).")

    if (await db.execute(select(BackendRouter).where(BackendRouter.name == body.name))).scalar_one_or_none():
        raise HTTPException(400, "Router-Name existiert bereits")

    # Compute router_id from pairing_code using HMAC
    router_id = None
    if body.pairing_code:
        router_id = compute_router_id(body.pairing_code)
        # Check not already used
        conflict = (await db.execute(
            select(BackendRouter).where(BackendRouter.router_id == router_id)
        )).scalar_one_or_none()
        if conflict:
            raise HTTPException(409, "Dieser Pairing-Code ist bereits einem Router zugewiesen")

    data = body.model_dump(exclude={"pairing_code"})
    r = BackendRouter(
        **data,
        router_id=router_id,
        pairing_status="active" if router_id else "pending",
        owner_id=current_user.id,
        created_by_id=current_user.id,
    )
    db.add(r)
    await db.flush()  # get r.id

    # Auto-allocate an IP from the pool
    cfg = await _get_config(db)
    label = f"router-{r.name}"
    ip = await _allocate_ip(db, cfg, label, current_user.id)
    r.ip_address_id = ip.id

    await db.commit()
    result = await db.execute(_router_q().where(BackendRouter.id == r.id))
    return BackendRouterOut.model_validate(result.scalar_one())


@api_router.put("/routers/{router_id}", response_model=BackendRouterOut)
async def update_router(
    router_id: int,
    body: BackendRouterAdminUpdate,
    current_user: User = Depends(require_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(_router_q().where(BackendRouter.id == router_id))
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Router nicht gefunden")
    if not _can_modify_router(r, current_user):
        raise HTTPException(403, "Nur der Eigentümer oder ein Admin kann diesen Router bearbeiten")

    data = body.model_dump(exclude_unset=True)
    if "ip_address_id" in data and not current_user.is_admin:
        raise HTTPException(403, "Nur Admins dürfen die IP-Zuordnung ändern")

    for k, v in data.items():
        setattr(r, k, v)
    r.updated_at = datetime.now(timezone.utc)
    await db.commit()
    result2 = await db.execute(_router_q().where(BackendRouter.id == router_id))
    return BackendRouterOut.model_validate(result2.scalar_one())


@api_router.patch("/routers/{router_id}/status", response_model=BackendRouterOut)
async def set_router_status(
    router_id: int,
    status: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Admin can set router pairing_status to active or inactive."""
    if status not in ("active", "inactive", "pending"):
        raise HTTPException(400, "Status muss 'active', 'inactive' oder 'pending' sein")
    result = await db.execute(_router_q().where(BackendRouter.id == router_id))
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Router nicht gefunden")
    r.pairing_status = status
    r.updated_at = datetime.now(timezone.utc)
    await db.commit()
    result2 = await db.execute(_router_q().where(BackendRouter.id == router_id))
    return BackendRouterOut.model_validate(result2.scalar_one())


@api_router.delete("/routers/{router_id}", status_code=204)
async def delete_router(router_id: int, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    r = (await db.execute(select(BackendRouter).where(BackendRouter.id == router_id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Router nicht gefunden")
    if not _can_modify_router(r, current_user):
        raise HTTPException(403, "Nur der Eigentümer oder ein Admin kann diesen Router löschen")

    ip_id = r.ip_address_id
    await db.delete(r)
    await db.flush()

    # Free the auto-allocated IP
    if ip_id:
        ip = (await db.execute(select(InternalIP).where(InternalIP.id == ip_id))).scalar_one_or_none()
        if ip and ip.auto_allocated:
            # Check no other router uses it
            other = (await db.execute(
                select(BackendRouter).where(BackendRouter.ip_address_id == ip_id)
            )).scalar_one_or_none()
            if not other:
                await db.delete(ip)

    await db.commit()


# ── SNI Domains ───────────────────────────────────────────────────────────────

@api_router.get("/domains", response_model=list[SNIDomainOut])
async def list_domains(current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(_domain_q().order_by(SNIDomain.domain))
    return [SNIDomainOut.model_validate(d) for d in result.scalars().all()]


@api_router.post("/domains", response_model=SNIDomainOut, status_code=201)
async def create_domain(body: SNIDomainCreate, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    if not current_user.is_admin and current_user.domain_quota > 0:
        count = await _count_owned(db, SNIDomain, current_user.id)
        if count >= current_user.domain_quota:
            raise HTTPException(403,
                f"Domain-Quota erreicht ({count}/{current_user.domain_quota}).")

    if (await db.execute(select(SNIDomain).where(SNIDomain.domain == body.domain))).scalar_one_or_none():
        raise HTTPException(400, "Domain existiert bereits")

    d = SNIDomain(
        **body.model_dump(),
        created_by_id=current_user.id,
        owner_id=current_user.id,
        verification_token=_generate_token(),
        verification_status=VerificationStatus.pending.value,
    )
    db.add(d)
    await db.commit()
    result = await db.execute(_domain_q().where(SNIDomain.id == d.id))
    return SNIDomainOut.model_validate(result.scalar_one())


@api_router.post("/domains/{domain_id}/verify", response_model=VerifyResult)
async def verify_domain(domain_id: int, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    d = (await db.execute(select(SNIDomain).where(SNIDomain.id == domain_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Domain nicht gefunden")
    if not _can_modify_domain(d, current_user):
        raise HTTPException(403, "Kein Zugriff")
    if d.verification_status == VerificationStatus.verified.value:
        return VerifyResult(success=True, message="Bereits verifiziert", verification_status="verified")

    found = await _check_txt_record(d.domain, d.verification_token)
    if found:
        d.verification_status = VerificationStatus.verified.value
        d.verified_at = datetime.now(timezone.utc)
        msg = "Domain erfolgreich verifiziert!"
    else:
        bare = d.domain.lstrip("*.")
        d.verification_status = VerificationStatus.failed.value
        msg = f"TXT-Record nicht gefunden. Bitte setze:\n_proxy-verify.{bare}  TXT  \"{d.verification_token}\""
    await db.commit()
    return VerifyResult(success=found, message=msg, verification_status=d.verification_status)


@api_router.post("/domains/{domain_id}/reset-token", response_model=SNIDomainOut)
async def reset_verification_token(domain_id: int, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    d = (await db.execute(select(SNIDomain).where(SNIDomain.id == domain_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Domain nicht gefunden")
    if not _can_modify_domain(d, current_user):
        raise HTTPException(403, "Kein Zugriff")
    d.verification_token = _generate_token()
    d.verification_status = VerificationStatus.pending.value
    d.verified_at = None
    await db.commit()
    result = await db.execute(_domain_q().where(SNIDomain.id == domain_id))
    return SNIDomainOut.model_validate(result.scalar_one())


@api_router.put("/domains/{domain_id}", response_model=SNIDomainOut)
async def update_domain(domain_id: int, body: SNIDomainUpdate, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(_domain_q().where(SNIDomain.id == domain_id))
    d = result.scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Domain nicht gefunden")
    if not _can_modify_domain(d, current_user):
        raise HTTPException(403, "Nur Eigentümer oder Admin")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(d, k, v)
    d.updated_at = datetime.now(timezone.utc)
    await db.commit()
    result2 = await db.execute(_domain_q().where(SNIDomain.id == domain_id))
    return SNIDomainOut.model_validate(result2.scalar_one())


@api_router.delete("/domains/{domain_id}", status_code=204)
async def delete_domain(domain_id: int, current_user: User = Depends(require_user), db: AsyncSession = Depends(get_db)):
    d = (await db.execute(select(SNIDomain).where(SNIDomain.id == domain_id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Domain nicht gefunden")
    if not _can_modify_domain(d, current_user):
        raise HTTPException(403, "Nur Eigentümer oder Admin")
    await db.delete(d)
    await db.commit()


# ── Users (Admin only) ────────────────────────────────────────────────────────

@api_router.get("/users", response_model=list[UserOut])
async def list_users(current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.github_login))
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@api_router.put("/users/{user_id}", response_model=UserOut)
async def update_user(user_id: int, body: UserUpdate, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if user_id == current_user.id and body.is_active is False:
        raise HTTPException(400, "Du kannst dich nicht selbst deaktivieren")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Nutzer nicht gefunden")
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.domain_quota is not None:
        if body.domain_quota < 0:
            raise HTTPException(400, "Quota muss >= 0 sein")
        user.domain_quota = body.domain_quota
    if body.router_quota is not None:
        if body.router_quota < 0:
            raise HTTPException(400, "Quota muss >= 0 sein")
        user.router_quota = body.router_quota
    if body.is_admin is not None and user_id != current_user.id:
        user.is_admin = body.is_admin
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@api_router.delete("/users/{user_id}", status_code=204)
async def delete_user(user_id: int, current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    if user_id == current_user.id:
        raise HTTPException(400, "Du kannst dich nicht selbst löschen")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "Nutzer nicht gefunden")
    await db.delete(user)
    await db.commit()
