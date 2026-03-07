import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

load_dotenv()

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from models.database import init_db, AsyncSessionLocal, User
from sqlalchemy import select
from routers.auth import router as auth_router, decode_session_token
from routers.api import api_router
from routers.pairing import pairing_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="Proxy Admin",
    description="SNI Domain & Backend Router Management",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    redirect_slashes=False,
)

import pathlib
static_path = pathlib.Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

templates = Jinja2Templates(directory="templates")

app.include_router(auth_router)
app.include_router(api_router)
app.include_router(pairing_router)

@app.middleware("http")
async def log_errors(request: Request, call_next):
    try:
        response = await call_next(request)
        if response.status_code >= 500:
            logger.error(f"500 on {request.method} {request.url.path}")
        return response
    except Exception as exc:
        logger.exception(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
        raise


async def _user_from_request(request: Request):
    """Standalone session check — no DI, no Depends, no surprises."""
    token = request.cookies.get("session")
    if not token:
        return None
    user_id = decode_session_token(token)
    if not user_id:
        return None
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa(request: Request, full_path: str):
    user = await _user_from_request(request)
    if not user or not user.is_active:
        return RedirectResponse("/login")
    return templates.TemplateResponse("app.html", {"request": request, "user": user})


if __name__ == "__main__":
    import uvicorn

    ssl_cert = os.getenv("HTTPS_CERT_FILE")
    ssl_key  = os.getenv("HTTPS_KEY_FILE")

    if ssl_cert and ssl_key:
        logger.info("TLS enabled — starting HTTPS server")
        uvicorn.run(
            "main:app",
            host=os.getenv("APP_HOST", "0.0.0.0"),
            port=int(os.getenv("APP_PORT", 8443)),
            ssl_certfile=ssl_cert,
            ssl_keyfile=ssl_key,
        )
    else:
        allow_http = os.getenv("ALLOW_HTTP", "false").lower() in ("true", "1", "yes")
        if not allow_http:
            logger.warning(
                "Neither HTTPS_CERT_FILE/HTTPS_KEY_FILE nor ALLOW_HTTP=true is set. "
                "Router devices will reject connections. "
                "Set ALLOW_HTTP=true for local testing only."
            )
        else:
            logger.warning(
                "ALLOW_HTTP=true — running without TLS. "
                "For production, set HTTPS_CERT_FILE and HTTPS_KEY_FILE."
            )
        uvicorn.run(
            "main:app",
            host=os.getenv("APP_HOST", "0.0.0.0"),
            port=int(os.getenv("APP_PORT", 8000)),
            reload=os.getenv("DEV_RELOAD", "false").lower() in ("true", "1"),
        )
