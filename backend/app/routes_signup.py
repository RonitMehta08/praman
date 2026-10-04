"""Self-service operator registration using the existing password/session store."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend.app import config
from backend.app.auth import (
    COOKIE_NAME,
    MIN_PASSWORD_LENGTH,
    ROLES,
    SERVICE_PREFIX,
    SESSION_TTL_SECONDS,
    Principal,
    create_user,
    open_session,
    validate_username,
)
from backend.app.state import STATE

router = APIRouter()


class SignupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=56)
    role: Literal["viewer", "auditor", "approver"]
    password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=512)


@router.get("/auth/options")
def auth_options() -> dict:
    """The login screen's registration policy, without any operator data."""
    return {
        "signup_enabled": config.SIGNUP_ENABLED,
        "roles": list(ROLES) if config.SIGNUP_ENABLED else [],
        "min_password_length": MIN_PASSWORD_LENGTH,
    }


@router.post("/auth/signup", status_code=201)
def auth_signup(req: SignupRequest, request: Request) -> JSONResponse:
    """Create an account and sign it in immediately, including download cookies.

    Synchronous so password derivation runs in FastAPI's thread pool instead of
    blocking the event loop. Role selection is explicit for the shared demo.
    """
    if not config.SIGNUP_ENABLED:
        raise HTTPException(status_code=403, detail="Account signup is disabled on this deployment.")
    username = req.username.strip()
    try:
        validate_username(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if username.startswith(SERVICE_PREFIX):
        raise HTTPException(status_code=400, detail="Service account names cannot be registered.")

    conn = STATE.connect()
    try:
        # The UNIQUE constraint in create_user also handles concurrent signups.
        try:
            create_user(conn, username, req.role, req.password)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        principal = Principal(username=username, role=req.role)
        token, expires_at = open_session(conn, principal)
    finally:
        conn.close()

    request.state.principal = principal
    response = JSONResponse(status_code=201, content={
        "token": token,
        "username": username,
        "role": req.role,
        "expires_at": expires_at,
    })
    response.set_cookie(
        COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS,
        httponly=True, samesite="strict", path="/",
    )
    return response
