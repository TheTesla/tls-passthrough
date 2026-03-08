"""
Router registration API — no user authentication required.
Security model:
  - In production: HTTPS with a CA certificate known to the router device.
    This prevents MITM and ensures the pairing_code never leaks.
  - For local testing: plain HTTP is allowed (set ALLOW_HTTP=true in env).

Authentication flow:
  1. Router has a printed pairing_code (e.g. "A5GN-YMQ5").
     router_id = HMAC-SHA256(pairing_code, ROUTER_ID_SECRET)[:32]
     The router_id is the public identifier — safe to print on the device.

  2. Admin enters the pairing_code in the web frontend when creating a router slot.
     Controller computes and stores the expected router_id.

  3. Router polls:  GET /api/router/{router_id}
                    Authorization: Bearer {pairing_code}
     Controller verifies: HMAC(bearer) == router_id  → authenticated.

  4. While router slot not yet created:
       → { status: "pending" }   (slot exists, but admin hasn't confirmed yet)
     After admin creates the router with the pairing_code:
       → { status: "active", subnet, ip, server_wg_public_key, server_endpoint, wg_public_key }
     The router configures WireGuard and becomes active.

  5. On every poll the controller updates last_seen_at (heartbeat).

ROUTER_ID_SECRET must be identical on router devices and controller.
Set via env var.  Default value is for local testing only.
"""
import os
from datetime import datetime, timezone

import logging
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

from models.database import get_db, BackendRouter, InternalIP, NetworkConfig
from models.schemas import PairingStatusResponse
from routers.router_auth import compute_router_id, verify_router_auth

pairing_router = APIRouter(tags=["pairing"])

ALLOW_HTTP = os.getenv("ALLOW_HTTP", "false").lower() in ("true", "1", "yes")


def _require_tls(request: Request):
    """Reject plain HTTP connections unless ALLOW_HTTP is set."""
    if not ALLOW_HTTP and request.url.scheme != "https":
        raise HTTPException(
            403,
            "TLS required. Set ALLOW_HTTP=true for local testing only."
        )


async def _build_active_response(
    db: AsyncSession,
    router: BackendRouter,
) -> PairingStatusResponse:
    ip = None
    if router.ip_address_id:
        ip = (await db.execute(
            select(InternalIP).where(InternalIP.id == router.ip_address_id)
        )).scalar_one_or_none()

    cfg = (await db.execute(
        select(NetworkConfig).where(NetworkConfig.id == 1)
    )).scalar_one_or_none()

    return PairingStatusResponse(
        enabled=router.enabled,
        router_id=router.id,
        router_name=router.name,
        subnet=ip.subnet if ip else None,
        ip_address=ip.ip_address if ip else None,
        server_wg_public_key=cfg.server_wg_public_key if cfg else None,
        server_endpoint=cfg.server_endpoint if cfg else None,
        wg_public_key=router.wireguard_public_key,
        poll_interval=router.poll_interval,
        device_status=router.device_status,
    )


# ── Single polling endpoint ───────────────────────────────────────────────────

@pairing_router.get("/api/router/{router_id}", response_model=PairingStatusResponse)
async def router_poll(
    router_id: str,
    request: Request,
    authorization: str = Header(..., description="Bearer {pairing_code}"),
    wg_public_key: str | None = Header(None, alias="X-WG-Public-Key"),
    hostname: str | None = Header(None, alias="X-Hostname"),
    version: str | None = Header(None, alias="X-Version"),
    db: AsyncSession = Depends(get_db),
):
    """
    Single endpoint polled by router devices.

    Headers:
      Authorization:   Bearer <pairing_code>   — proves identity
      X-WG-Public-Key: <base64 key>            — router's WireGuard public key
      X-Hostname:      <hostname>               — optional, for display
      X-Version:       <firmware version>       — optional, for display

    Returns current pairing status and — once active — full WireGuard config.
    """
    _require_tls(request)

    # Parse Bearer token
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be 'Bearer <pairing_code>'")
    pairing_code = authorization[7:].strip()

    # Verify: HMAC(pairing_code) must equal the router_id in the URL
    if not verify_router_auth(router_id, pairing_code):
        logger.warning(f"Auth failed for router_id={router_id} from {request.client.host}")
        raise HTTPException(401, "Invalid pairing code for this router ID")

    # Look up router slot
    router = (await db.execute(
        select(BackendRouter).where(BackendRouter.router_id == router_id)
    )).scalar_one_or_none()

    now = datetime.now(timezone.utc)

    if router is None:
        # Credentials valid but no slot exists yet
        logger.info(f"Poll from unknown router_id={router_id} (not yet registered)")
        return PairingStatusResponse(poll_interval=10)

    # Update heartbeat
    if router.first_seen_at is None:
        router.first_seen_at = now
        logger.info(f"First contact from router '{router.name}' (id={router.id})")
    router.last_seen_at = now

    # Validate WG key and update device_status
    if wg_public_key:
        import re as _re
        if _re.match(r"^[A-Za-z0-9+/]{43}=$", wg_public_key):
            if router.wireguard_public_key != wg_public_key:
                router.wireguard_public_key = wg_public_key
                logger.info(f"WG key updated for router '{router.name}'")
            router.device_status = "ok"
        else:
            router.device_status = "error"
            logger.warning(f"Invalid WG key from router '{router.name}': {wg_public_key!r}")
    elif router.device_status == "uninitialized":
        pass  # no key sent yet — stay uninitialized
    # else: keep existing device_status

    await db.commit()
    # Expire and reload to pick up any external changes (e.g. enabled toggled via admin)
    db.expire_all()
    router = (await db.execute(
        select(BackendRouter).where(BackendRouter.router_id == router_id)
    )).scalar_one()
    logger.info(f"Heartbeat router='{router.name}' device_status={router.device_status}")

    # Send full config
    return await _build_active_response(db, router)
