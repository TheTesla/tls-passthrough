import os
import secrets
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.database import get_db, User

router = APIRouter(prefix="/auth", tags=["auth"])

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/auth/callback")
SECRET_KEY = os.getenv("SECRET_KEY", "changeme")
ADMIN_USERS = [u.strip() for u in os.getenv("ADMIN_USERS", "").split(",") if u.strip()]

_serializer = URLSafeTimedSerializer(SECRET_KEY)
_state_store: dict[str, str] = {}


def create_session_token(user_id: int) -> str:
    return _serializer.dumps({"user_id": user_id})


def decode_session_token(token: str) -> Optional[int]:
    try:
        data = _serializer.loads(token, max_age=86400 * 7)
        return data.get("user_id")
    except (BadSignature, Exception):
        return None


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> Optional[User]:
    token = request.cookies.get("session")
    if not token:
        return None
    user_id = decode_session_token(token)
    if not user_id:
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def require_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    user = await get_current_user(request, db)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


async def require_admin(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    user = await require_user(request, db)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@router.get("/login")
async def login(request: Request):
    state = secrets.token_urlsafe(32)
    _state_store[state] = "pending"
    params = (
        f"client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&scope=read:user+user:email"
        f"&state={state}"
    )
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{params}")


@router.get("/callback")
async def callback(code: str, state: str, response: Response, db: AsyncSession = Depends(get_db)):
    if state not in _state_store:
        raise HTTPException(status_code=400, detail="Invalid state")
    del _state_store[state]

    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_REDIRECT_URI,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_resp.json()

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Failed to get access token")

    # Fetch GitHub user info
    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}", "Accept": "application/json"},
        )
        gh_user = user_resp.json()

        email_resp = await client.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"token {access_token}", "Accept": "application/json"},
        )
        emails = email_resp.json() if email_resp.status_code == 200 else []

    primary_email = next(
        (e["email"] for e in emails if isinstance(e, dict) and e.get("primary")),
        gh_user.get("email"),
    )

    # Upsert user
    result = await db.execute(select(User).where(User.github_id == gh_user["id"]))
    user = result.scalar_one_or_none()

    is_admin = gh_user["login"] in ADMIN_USERS

    if user is None:
        user = User(
            github_id=gh_user["id"],
            github_login=gh_user["login"],
            github_name=gh_user.get("name"),
            github_avatar=gh_user.get("avatar_url"),
            email=primary_email,
            is_admin=is_admin,
            is_active=True,
        )
        db.add(user)
    else:
        user.github_login = gh_user["login"]
        user.github_name = gh_user.get("name")
        user.github_avatar = gh_user.get("avatar_url")
        user.email = primary_email
        if is_admin:
            user.is_admin = True

    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    token = create_session_token(user.id)
    redirect = RedirectResponse(url="/", status_code=302)
    redirect.set_cookie("session", token, httponly=True, samesite="lax", max_age=86400 * 7)
    return redirect


@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie("session")
    return response


@router.get("/me")
async def me(user: User = Depends(require_user)):
    from models.schemas import UserOut
    return UserOut.model_validate(user)
