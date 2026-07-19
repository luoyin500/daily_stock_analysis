# -*- coding: utf-8 -*-
"""
SQLite-backed user store for multi-user authentication.

The user database is created on demand by the backend service (NOT by the
Docker image build) on first run. It lives in a dedicated SQLite file
(`./data/users.db` by default, overridable via ``USER_DB_PATH`` env var) so
that it stays independent from the main analysis database.

Schema:
    users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,           -- "salt_b64:hash_b64"
        role TEXT NOT NULL,                    -- "admin" | "user"
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )

Default admin credentials (created on first init if no users exist):
    username: admin
    password: 123456   (can be changed via web UI or CLI)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

PBKDF2_ITERATIONS = 100_000
MIN_PASSWORD_LEN = 6
MIN_USERNAME_LEN = 2
MAX_USERNAME_LEN = 64

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "123456"

ROLE_ADMIN = "admin"
ROLE_USER = "user"
VALID_ROLES = (ROLE_ADMIN, ROLE_USER)

_lock = threading.Lock()
_db_path: Optional[str] = None


# --------------------------------------------------------------------------- #
# DB path resolution
# --------------------------------------------------------------------------- #
def _ensure_env_loaded() -> None:
    """Ensure .env is loaded before reading config (mirrors src.auth)."""
    try:
        from src.config import setup_env
        setup_env()
    except Exception:  # noqa: BLE001
        # In standalone use (no full app context) we silently fall back
        # to whatever os.environ already provides.
        pass


def _resolve_db_path() -> Path:
    """Return the SQLite file path for the user store, creating its parent dir."""
    _ensure_env_loaded()
    env_path = os.getenv("USER_DB_PATH", "").strip()
    if env_path:
        path = Path(env_path)
    else:
        # Default: ./data/users.db (sibling of stock_analysis.db)
        env_data_dir = os.getenv("DATA_DIR", "").strip()
        if env_data_dir:
            path = Path(env_data_dir) / "users.db"
        else:
            db_path_env = os.getenv("DATABASE_PATH", "./data/stock_analysis.db")
            path = Path(db_path_env).resolve().parent / "users.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def get_db_path() -> str:
    """Return the resolved DB path (cached)."""
    global _db_path
    if _db_path is None:
        _db_path = str(_resolve_db_path())
    return _db_path


def _connect() -> sqlite3.Connection:
    """Open a new connection configured for sane concurrency."""
    conn = sqlite3.connect(get_db_path(), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Improve durability + concurrency for the small user table.
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    """Create the schema if missing and seed the default admin if empty."""
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)"
            )
            conn.commit()

            # Seed default admin if there are no users at all.
            cur = conn.execute("SELECT COUNT(*) AS c FROM users")
            row = cur.fetchone()
            count = row["c"] if row else 0
            if count == 0:
                _create_user_locked(
                    conn,
                    username=DEFAULT_ADMIN_USERNAME,
                    password=DEFAULT_ADMIN_PASSWORD,
                    role=ROLE_ADMIN,
                )
                logger.info(
                    "User store initialised with default admin user %r. "
                    "Please change the default password after first login.",
                    DEFAULT_ADMIN_USERNAME,
                )
        finally:
            conn.close()


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
def _hash_password(password: str) -> str:
    """Return 'salt_b64:hash_b64' for the given password."""
    salt = secrets.token_bytes(32)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    salt_b64 = base64.standard_b64encode(salt).decode("ascii")
    hash_b64 = base64.standard_b64encode(derived).decode("ascii")
    return f"{salt_b64}:{hash_b64}"


def _verify_password(password: str, stored: str) -> bool:
    """Verify a submitted password against a 'salt_b64:hash_b64' string."""
    if not stored or ":" not in stored:
        return False
    parts = stored.split(":", 1)
    if len(parts) != 2:
        return False
    try:
        salt = base64.standard_b64decode(parts[0].strip())
        expected = base64.standard_b64decode(parts[1].strip())
    except (ValueError, TypeError):
        return False
    if not salt or not expected:
        return False
    computed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(computed, expected)


def _validate_username(username: str) -> Optional[str]:
    """Return error message if invalid, None if valid."""
    if not username or not username.strip():
        return "用户名不能为空"
    uname = username.strip()
    if len(uname) < MIN_USERNAME_LEN:
        return f"用户名至少 {MIN_USERNAME_LEN} 位"
    if len(uname) > MAX_USERNAME_LEN:
        return f"用户名不能超过 {MAX_USERNAME_LEN} 位"
    # Allow letters, digits, underscore, hyphen, dot, and CJK chars.
    if not all(c.isalnum() or c in "_-." or ord(c) > 127 for c in uname):
        return "用户名仅允许字母、数字、下划线、连字符或点"
    return None


def _validate_password(password: str) -> Optional[str]:
    """Return error message if invalid, None if valid."""
    if not password or not password.strip():
        return "密码不能为空"
    if len(password) < MIN_PASSWORD_LEN:
        return f"密码至少 {MIN_PASSWORD_LEN} 位"
    return None


# --------------------------------------------------------------------------- #
# Internal CRUD helpers (assume caller holds the connection)
# --------------------------------------------------------------------------- #
def _row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "isActive": bool(row["is_active"]),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def _create_user_locked(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    role: str = ROLE_USER,
    is_active: bool = True,
) -> dict:
    """Insert a new user. Caller must hold `_lock` + the connection."""
    uname = (username or "").strip()
    err = _validate_username(uname)
    if err:
        raise ValueError(err)
    err = _validate_password(password)
    if err:
        raise ValueError(err)
    if role not in VALID_ROLES:
        raise ValueError(f"无效的角色: {role}")

    now = datetime.utcnow().isoformat(timespec="seconds")
    password_hash = _hash_password(password)
    cur = conn.execute(
        """
        INSERT INTO users (username, password_hash, role, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (uname, password_hash, role, 1 if is_active else 0, now, now),
    )
    conn.commit()
    user_id = cur.lastrowid
    return {
        "id": user_id,
        "username": uname,
        "role": role,
        "isActive": is_active,
        "createdAt": now,
        "updatedAt": now,
    }


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def verify_user_credentials(username: str, password: str) -> Optional[dict]:
    """Return the user dict if (username, password) match an active user."""
    if not username or not password:
        return None
    uname = username.strip()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE LIMIT 1",
                (uname,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            if not row["is_active"]:
                return None
            if not _verify_password(password, row["password_hash"]):
                return None
            return _row_to_dict(row)
        finally:
            conn.close()


def get_user_by_username(username: str) -> Optional[dict]:
    """Look up a user by username (case-insensitive)."""
    if not username:
        return None
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE LIMIT 1",
                (username.strip(),),
            )
            row = cur.fetchone()
            return _row_to_dict(row) if row is not None else None
        finally:
            conn.close()


def get_user_by_id(user_id: int) -> Optional[dict]:
    """Look up a user by id."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
            row = cur.fetchone()
            return _row_to_dict(row) if row is not None else None
        finally:
            conn.close()


def list_users() -> list[dict]:
    """Return all users (without password hashes)."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "SELECT * FROM users ORDER BY id ASC"
            )
            rows = cur.fetchall()
            return [_row_to_dict(r) for r in rows]
        finally:
            conn.close()


def create_user(username: str, password: str, role: str = ROLE_USER) -> dict:
    """Create a new user. Raises ValueError on invalid input or duplicate."""
    with _lock:
        conn = _connect()
        try:
            # Duplicate check (case-insensitive)
            cur = conn.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE LIMIT 1",
                ((username or "").strip(),),
            )
            if cur.fetchone() is not None:
                raise ValueError("用户名已存在")
            return _create_user_locked(conn, username, password, role)
        finally:
            conn.close()


def delete_user(user_id: int) -> bool:
    """Delete a user. Returns True if a row was removed.

    Raises ValueError when attempting to delete the last remaining admin.
    """
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
            row = cur.fetchone()
            if row is None:
                return False
            if row["role"] == ROLE_ADMIN:
                # Prevent deleting the last admin.
                cur2 = conn.execute(
                    "SELECT COUNT(*) AS c FROM users WHERE role = ? AND is_active = 1",
                    (ROLE_ADMIN,),
                )
                count_row = cur2.fetchone()
                active_admins = count_row["c"] if count_row else 0
                if active_admins <= 1:
                    raise ValueError("不能删除最后一个管理员账户")
            cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def update_user(
    user_id: int,
    *,
    password: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
) -> Optional[dict]:
    """Update password / role / active state. Returns updated user dict or None."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
            row = cur.fetchone()
            if row is None:
                return None

            updates: list[str] = []
            params: list = []

            if password is not None:
                err = _validate_password(password)
                if err:
                    raise ValueError(err)
                updates.append("password_hash = ?")
                params.append(_hash_password(password))

            if role is not None:
                if role not in VALID_ROLES:
                    raise ValueError(f"无效的角色: {role}")
                # Demote-admin guard: don't allow removing the last admin.
                if row["role"] == ROLE_ADMIN and role != ROLE_ADMIN:
                    cur2 = conn.execute(
                        "SELECT COUNT(*) AS c FROM users WHERE role = ? AND is_active = 1",
                        (ROLE_ADMIN,),
                    )
                    count_row = cur2.fetchone()
                    active_admins = count_row["c"] if count_row else 0
                    if active_admins <= 1:
                        raise ValueError("不能取消最后一个管理员的管理员角色")
                updates.append("role = ?")
                params.append(role)

            if is_active is not None:
                # Deactivate-admin guard
                if (
                    row["role"] == ROLE_ADMIN
                    and not is_active
                    and row["is_active"] == 1
                ):
                    cur2 = conn.execute(
                        "SELECT COUNT(*) AS c FROM users WHERE role = ? AND is_active = 1",
                        (ROLE_ADMIN,),
                    )
                    count_row = cur2.fetchone()
                    active_admins = count_row["c"] if count_row else 0
                    if active_admins <= 1:
                        raise ValueError("不能停用最后一个管理员账户")
                updates.append("is_active = ?")
                params.append(1 if is_active else 0)

            if not updates:
                return _row_to_dict(row)

            updates.append("updated_at = ?")
            params.append(datetime.utcnow().isoformat(timespec="seconds"))
            params.append(user_id)
            conn.execute(
                f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            conn.commit()

            cur = conn.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
            new_row = cur.fetchone()
            return _row_to_dict(new_row) if new_row is not None else None
        finally:
            conn.close()


def change_password(
    user_id: int,
    current_password: str,
    new_password: str,
) -> Optional[str]:
    """Change a user's password after verifying the current one.

    Returns an error message or None on success.
    """
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
            row = cur.fetchone()
            if row is None:
                return "用户不存在"
            if not _verify_password(current_password, row["password_hash"]):
                return "当前密码错误"
            err = _validate_password(new_password)
            if err:
                return err
            now = datetime.utcnow().isoformat(timespec="seconds")
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (_hash_password(new_password), now, user_id),
            )
            conn.commit()
            return None
        finally:
            conn.close()


def admin_reset_password(user_id: int, new_password: str) -> Optional[str]:
    """Admin-forced password reset (no current password check)."""
    err = _validate_password(new_password)
    if err:
        return err
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("SELECT id FROM users WHERE id = ? LIMIT 1", (user_id,))
            if cur.fetchone() is None:
                return "用户不存在"
            now = datetime.utcnow().isoformat(timespec="seconds")
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (_hash_password(new_password), now, user_id),
            )
            conn.commit()
            return None
        finally:
            conn.close()


def count_users() -> int:
    """Return the total number of users (any role, any active state)."""
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("SELECT COUNT(*) AS c FROM users")
            row = cur.fetchone()
            return row["c"] if row else 0
        finally:
            conn.close()


def has_users() -> bool:
    """Return True if the users table has at least one row."""
    return count_users() > 0
