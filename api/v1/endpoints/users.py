# -*- coding: utf-8 -*-
"""User management endpoints.

Multi-user authentication endpoints backed by the SQLite user store
(`src/user_store.py`). The endpoints under ``/api/v1/users`` are
self-governing:

* ``GET /api/v1/users/me``  - Any logged-in user can fetch their own profile.
* ``GET /api/v1/users``     - Admin only: list all users.
* ``POST /api/v1/users``    - Admin only: create a new user.
* ``PATCH /api/v1/users/{user_id}``  - Admin only: update role / active state.
* ``POST /api/v1/users/{user_id}/reset-password`` - Admin only: reset password.
* ``DELETE /api/v1/users/{user_id}`` - Admin only: delete a user.

Admin-only routes are enforced by ``_require_admin`` which inspects the
``request.state.user`` populated by ``AuthMiddleware``.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from src.user_store import (
    ROLE_ADMIN,
    ROLE_USER,
    VALID_ROLES,
    admin_reset_password,
    create_user,
    delete_user,
    get_user_by_id,
    get_user_by_username,
    list_users,
    update_user,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class CreateUserRequest(BaseModel):
    """Body for POST /users."""

    model_config = {"populate_by_name": True}

    username: str = Field(..., description="Username (2-64 chars)")
    password: str = Field(..., description="Initial password (>=6 chars)")
    role: str = Field(default=ROLE_USER, description="User role: 'admin' | 'user'")


class UpdateUserRequest(BaseModel):
    """Body for PATCH /users/{id}.

    All fields optional; only provided fields are applied.
    """

    model_config = {"populate_by_name": True}

    role: str | None = Field(default=None, description="New role: 'admin' | 'user'")
    is_active: bool | None = Field(default=None, alias="isActive", description="Toggle active state")


class ResetPasswordRequest(BaseModel):
    """Body for POST /users/{id}/reset-password."""

    model_config = {"populate_by_name": True}

    new_password: str = Field(..., alias="newPassword", description="New password (>=6 chars)")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _current_user(request: Request) -> dict | None:
    return getattr(request.state, "user", None)


def _require_admin(request: Request) -> JSONResponse | None:
    """Return a 403 JSONResponse if the current user is not an admin.

    Returns ``None`` when access is allowed so callers can write
    ``err = _require_admin(request); if err: return err``.
    """
    current = _current_user(request)
    if not current or current.get("role") != ROLE_ADMIN:
        return JSONResponse(
            status_code=403,
            content={
                "error": "forbidden",
                "message": "需要管理员权限",
            },
        )
    return None


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@router.get(
    "/me",
    summary="Get the current user",
    description="Return the username and role of the currently authenticated user.",
)
async def get_current_user(request: Request):
    """Return the profile of the logged-in user (any role)."""
    current = _current_user(request)
    if not current:
        return JSONResponse(
            status_code=401,
            content={"error": "unauthorized", "message": "Login required"},
        )
    # Look up the live record so we can surface isActive etc.
    record = get_user_by_username(current["username"]) if current.get("username") else None
    if record is None:
        # Fall back to whatever the session carries.
        return {
            "username": current.get("username"),
            "role": current.get("role"),
            "isActive": True,
        }
    return {
        "id": record["id"],
        "username": record["username"],
        "role": record["role"],
        "isActive": record["isActive"],
        "createdAt": record["createdAt"],
        "updatedAt": record["updatedAt"],
    }


@router.get(
    "",
    summary="List all users",
    description="Admin only. Returns every user (without password hashes).",
)
async def list_all_users(request: Request):
    """Admin only: return all users."""
    err = _require_admin(request)
    if err is not None:
        return err
    return {"users": list_users()}


@router.post(
    "",
    summary="Create a new user",
    description="Admin only. Creates a new user with the given username, password, and role.",
)
async def create_new_user(request: Request, body: CreateUserRequest):
    """Admin only: create a new user."""
    err = _require_admin(request)
    if err is not None:
        return err

    username = (body.username or "").strip()
    password = body.password or ""
    role = (body.role or ROLE_USER).strip().lower()

    if role not in VALID_ROLES:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_role", "message": f"无效的角色: {role}"},
        )

    try:
        created = create_user(username, password, role)
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_user", "message": str(exc)},
        )
    return JSONResponse(status_code=201, content=created)


@router.patch(
    "/{user_id}",
    summary="Update a user",
    description="Admin only. Update role and/or active state of an existing user.",
)
async def update_existing_user(request: Request, user_id: int, body: UpdateUserRequest):
    """Admin only: update role / isActive for a user."""
    err = _require_admin(request)
    if err is not None:
        return err

    role = (body.role or "").strip().lower() or None
    if role is not None and role not in VALID_ROLES:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_role", "message": f"无效的角色: {role}"},
        )

    try:
        updated = update_user(
            user_id,
            role=role,
            is_active=body.is_active if body.is_active is not None else None,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_update", "message": str(exc)},
        )
    if updated is None:
        return JSONResponse(
            status_code=404,
            content={"error": "user_not_found", "message": "用户不存在"},
        )
    return JSONResponse(content=updated)


@router.post(
    "/{user_id}/reset-password",
    summary="Reset a user's password",
    description="Admin only. Force-reset the password of any user without supplying the current password.",
)
async def reset_user_password(request: Request, user_id: int, body: ResetPasswordRequest):
    """Admin only: reset a user's password."""
    err = _require_admin(request)
    if err is not None:
        return err

    new_password = body.new_password or ""
    err_msg = admin_reset_password(user_id, new_password)
    if err_msg:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_password", "message": err_msg},
        )
    return Response(status_code=204)


@router.delete(
    "/{user_id}",
    summary="Delete a user",
    description="Admin only. Delete a user by id. The last admin cannot be deleted.",
)
async def delete_existing_user(request: Request, user_id: int):
    """Admin only: delete a user."""
    err = _require_admin(request)
    if err is not None:
        return err

    # Prevent an admin from deleting their own account.
    current = _current_user(request)
    if current and current.get("username"):
        target = get_user_by_id(user_id)
        if target and target["username"].lower() == current["username"].lower():
            return JSONResponse(
                status_code=400,
                content={"error": "cannot_delete_self", "message": "不能删除自己当前登录的账户"},
            )

    try:
        deleted = delete_user(user_id)
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "cannot_delete", "message": str(exc)},
        )
    if not deleted:
        return JSONResponse(
            status_code=404,
            content={"error": "user_not_found", "message": "用户不存在"},
        )
    return Response(status_code=204)
