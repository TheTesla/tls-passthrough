"""
Shared authentication helpers for router pairing.
Imported by both pairing.py (device-side) and api.py (admin-side).
"""
import hmac as _hmac
import hashlib
import os
import re

ROUTER_ID_SECRET = os.getenv("ROUTER_ID_SECRET", "dev-secret-change-in-production")


def normalize_pairing_code(code: str) -> str:
    """Strip dashes/spaces, uppercase — 'A5GN-YMQ5' and 'A5GNYMQ5' become 'A5GNYMQ5'."""
    return re.sub(r'[^A-Z2-9]', '', code.strip().upper())


def compute_router_id(pairing_code: str) -> str:
    """
    Deterministic public identifier derived from the pairing code.
    Safe to print on the device label — does not reveal the pairing_code.
    router_id = HMAC-SHA256(normalize(pairing_code), ROUTER_ID_SECRET)[:32]
    """
    clean = normalize_pairing_code(pairing_code)
    return _hmac.new(
        ROUTER_ID_SECRET.encode(),
        clean.encode(),
        hashlib.sha256,
    ).hexdigest()[:32]


def verify_router_auth(router_id: str, bearer_token: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    expected = compute_router_id(bearer_token)
    return _hmac.compare_digest(expected, router_id)
