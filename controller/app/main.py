from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
import os

import auth
import redis_store

app = FastAPI()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")


@app.get("/")
def root():
    return {"status": "running"}


@app.get("/login")
def login():
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}"
    )


@app.get("/auth/callback")
async def callback(code: str):
    token_data = await auth.exchange_code(code)

    if "access_token" not in token_data:
        raise HTTPException(400, "OAuth failed")

    gh_user = await auth.get_github_user(token_data["access_token"])

    github_id = str(gh_user["id"])
    username = gh_user["login"]

    user = redis_store.get_user_by_github(github_id)

    if not user:
        user_id = redis_store.create_user(github_id, username)
    else:
        user_id = redis_store.r.get(f"github:{github_id}")

    jwt_token = auth.create_jwt(user_id)

    return {
        "jwt": jwt_token,
        "username": username
    }

