import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

load_dotenv()

from models.database import init_db
from routers.auth import router as auth_router, get_current_user
from routers.api import api_router


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
)

# Static files (if directory exists)
import pathlib
static_path = pathlib.Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

templates = Jinja2Templates(directory="templates")

app.include_router(auth_router)
app.include_router(api_router)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa(request: Request, full_path: str):
    from models.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        user = await get_current_user(request, db)
    if not user or not user.is_active:
        return RedirectResponse("/login")
    return templates.TemplateResponse("app.html", {"request": request, "user": user})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=int(os.getenv("APP_PORT", 8000)),
        reload=True,
    )
