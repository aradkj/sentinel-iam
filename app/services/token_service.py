import json
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_token,
)
from app.core.security import hash_token, parse_device_name
from app.database.session import ResilientRedisClient
from app.models.role import Role
from app.models.token import RefreshToken, UserSession
from app.models.user import User


class TokenService:
    """Service responsible for JWT lifecycle, Redis blacklisting, DB/Redis sessions, and refresh rotation."""

    BLACKLIST_PREFIX = "blacklist:"
    SESSION_PREFIX = "session:"

    @classmethod
    def blacklist_key(cls, jti: str) -> str:
        """Build the Redis key for a blacklisted JWT ID."""
        return f"{cls.BLACKLIST_PREFIX}{jti}"

    @classmethod
    def session_key(cls, user_id: int, jti: str) -> str:
        """Build the Redis key for an active user session."""
        return f"{cls.SESSION_PREFIX}{user_id}:{jti}"

    @classmethod
    async def blacklist_jti(
        cls,
        redis: ResilientRedisClient,
        jti: str,
        exp_timestamp: int | float,
    ) -> None:
        """Add a JWT ID to the Redis blacklist with a TTL matching its remaining lifetime."""
        now_ts = int(datetime.now(timezone.utc).timestamp())
        ttl = max(1, int(exp_timestamp) - now_ts)
        await redis.set(cls.blacklist_key(jti), "true", ex=ttl)

    @classmethod
    async def is_blacklisted(cls, redis: ResilientRedisClient, jti: str) -> bool:
        """Check whether a JWT ID exists in the Redis blacklist."""
        value = await redis.get(cls.blacklist_key(jti))
        return value is not None and str(value).lower() == "true"

    @classmethod
    async def store_session(
        cls,
        redis: ResilientRedisClient,
        user_id: int,
        jti: str,
        exp_timestamp: int,
        ip_address: str | None = None,
        device_name: str = "Chrome Windows",
        session_id: int | None = None,
    ) -> None:
        """Store an active session record in Redis."""
        now = datetime.now(timezone.utc)
        ttl = max(1, int(exp_timestamp) - int(now.timestamp()))
        session_data = {
            "id": session_id,
            "jti": jti,
            "user_id": user_id,
            "device": device_name,
            "device_name": device_name,
            "ip": ip_address or "127.0.0.1",
            "ip_address": ip_address or "127.0.0.1",
            "last_activity": now.strftime("%Y-%m-%d"),
            "created_at": now.isoformat(),
            "expires_at": datetime.fromtimestamp(exp_timestamp, tz=timezone.utc).isoformat(),
            "revoked": False,
        }
        await redis.set(
            cls.session_key(user_id, jti),
            json.dumps(session_data),
            ex=ttl,
        )

    @classmethod
    async def remove_session(
        cls,
        redis: ResilientRedisClient,
        user_id: int,
        jti: str,
    ) -> None:
        """Remove a specific active session from Redis."""
        await redis.delete(cls.session_key(user_id, jti))

    @classmethod
    async def remove_all_user_sessions(
        cls,
        redis: ResilientRedisClient,
        user_id: int,
    ) -> int:
        """Remove all active sessions for a user from Redis."""
        keys = await redis.keys(f"{cls.SESSION_PREFIX}{user_id}:*")
        if not keys:
            return 0
        return await redis.delete(*keys)

    @classmethod
    async def list_user_sessions(
        cls,
        redis: ResilientRedisClient,
        user_id: int,
    ) -> list[dict[str, Any]]:
        """Return all active sessions for a user currently stored in Redis."""
        keys = await redis.keys(f"{cls.SESSION_PREFIX}{user_id}:*")
        sessions: list[dict[str, Any]] = []
        for key in keys:
            raw = await redis.get(key)
            if raw:
                try:
                    sessions.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        return sessions

    @classmethod
    async def list_db_sessions(
        cls,
        db: AsyncSession,
        user_id: int,
        current_jti: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all active non-revoked database sessions for a user."""
        now = datetime.now(timezone.utc)
        stmt = (
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked.is_(False),
            )
            .order_by(UserSession.last_activity.desc(), UserSession.id.desc())
        )
        res = await db.execute(stmt)
        rows = res.scalars().all()

        results: list[dict[str, Any]] = []
        for s in rows:
            exp = s.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= now:
                continue
            last_act_str = (
                s.last_activity.strftime("%Y-%m-%d")
                if s.last_activity
                else now.strftime("%Y-%m-%d")
            )
            results.append(
                {
                    "id": s.id,
                    "jti": s.jti,
                    "user_id": s.user_id,
                    "device": s.device_name,
                    "device_name": s.device_name,
                    "ip": s.ip_address or "127.0.0.1",
                    "ip_address": s.ip_address or "127.0.0.1",
                    "user_agent": s.user_agent,
                    "last_activity": last_act_str,
                    "created_at": s.created_at.isoformat() if s.created_at else now.isoformat(),
                    "expires_at": exp.isoformat(),
                    "revoked": s.revoked,
                    "is_current": bool(current_jti and s.jti == current_jti),
                }
            )
        return results

    @classmethod
    async def revoke_session_by_id(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        user_id: int,
        session_id: int,
    ) -> UserSession:
        """Revoke a specific user session by ID and blacklist its tokens in Redis."""
        stmt = select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
        )
        res = await db.execute(stmt)
        session_obj = res.scalar_one_or_none()
        if session_obj is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session with id={session_id} not found.",
            )

        session_obj.revoked = True
        db.add(session_obj)

        exp_ts = int(
            (
                session_obj.expires_at.replace(tzinfo=timezone.utc)
                if session_obj.expires_at.tzinfo is None
                else session_obj.expires_at
            ).timestamp()
        )

        if session_obj.jti:
            await cls.blacklist_jti(redis, session_obj.jti, exp_ts)
            await cls.remove_session(redis, user_id, session_obj.jti)

        if session_obj.refresh_jti:
            await cls.blacklist_jti(redis, session_obj.refresh_jti, exp_ts)
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.jti == session_obj.refresh_jti)
                .values(revoked=True)
            )

        await db.commit()
        await db.refresh(session_obj)
        return session_obj

    @classmethod
    async def revoke_all_sessions(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        user_id: int,
    ) -> int:
        """Revoke all active sessions and refresh tokens for a user across all devices."""
        stmt = select(UserSession).where(
            UserSession.user_id == user_id,
            UserSession.revoked.is_(False),
        )
        res = await db.execute(stmt)
        active_sessions = list(res.scalars().all())

        for s in active_sessions:
            s.revoked = True
            exp_ts = int(
                (
                    s.expires_at.replace(tzinfo=timezone.utc)
                    if s.expires_at.tzinfo is None
                    else s.expires_at
                ).timestamp()
            )
            if s.jti:
                await cls.blacklist_jti(redis, s.jti, exp_ts)
            if s.refresh_jti:
                await cls.blacklist_jti(redis, s.refresh_jti, exp_ts)

        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
            .values(revoked=True)
        )
        await db.commit()
        await cls.remove_all_user_sessions(redis, user_id)
        return len(active_sessions)

    @classmethod
    async def issue_tokens_for_user(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        user: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Create a new access/refresh JWT pair, persist refresh hash & DB session, and track in Redis."""
        access_token = create_access_token(
            user_id=user.id,
            role=user.primary_role,
            roles=user.role_names,
            permissions=user.permission_names,
        )
        refresh_token = create_refresh_token(
            user_id=user.id,
            role=user.primary_role,
        )

        access_payload = decode_token(access_token)
        refresh_payload = decode_token(refresh_token)

        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc)
        device_name = parse_device_name(user_agent)

        db_refresh = RefreshToken(
            user_id=user.id,
            token_hash=hash_token(refresh_token),
            jti=refresh_payload["jti"],
            expires_at=expires_at,
            revoked=False,
        )
        db_session = UserSession(
            user_id=user.id,
            session_token_hash=hash_token(access_token),
            jti=access_payload["jti"],
            refresh_jti=refresh_payload["jti"],
            device_name=device_name,
            ip_address=ip_address or "127.0.0.1",
            user_agent=user_agent or "Chrome Windows",
            last_activity=now,
            created_at=now,
            expires_at=expires_at,
            revoked=False,
        )
        db.add(db_refresh)
        db.add(db_session)
        await db.commit()
        await db.refresh(db_session)

        await cls.store_session(
            redis=redis,
            user_id=user.id,
            jti=access_payload["jti"],
            exp_timestamp=access_payload["exp"],
            ip_address=ip_address,
            device_name=device_name,
            session_id=db_session.id,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "requires_2fa": False,
            "temp_token": None,
            "session_id": db_session.id,
        }

    @classmethod
    async def rotate_refresh_token(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        raw_refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Validate a refresh token, revoke it, and issue a rotated token pair."""
        payload = verify_token(raw_refresh_token, expected_type="refresh")
        jti = str(payload["jti"])
        user_id = int(payload["user_id"])

        if await cls.is_blacklisted(redis, jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token_digest = hash_token(raw_refresh_token)
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_digest)
        result = await db.execute(stmt)
        stored_token = result.scalar_one_or_none()

        if stored_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token is not recognized",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if stored_token.revoked:
            await cls.revoke_all_sessions(db, redis, user_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has already been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        now = datetime.now(timezone.utc)
        expires_at = stored_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            stored_token.revoked = True
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Revoke the current refresh token, its linked session, and blacklist its JTI
        stored_token.revoked = True
        await db.execute(
            update(UserSession)
            .where(UserSession.refresh_jti == jti)
            .values(revoked=True)
        )
        await cls.blacklist_jti(redis, jti, payload["exp"])

        user_stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.id == user_id)
        )
        user_result = await db.execute(user_stmt)
        user = user_result.scalar_one_or_none()
        if user is None or not user.is_active:
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive or does not exist",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await cls.issue_tokens_for_user(
            db=db,
            redis=redis,
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @classmethod
    async def revoke_tokens_on_logout(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        access_payload: dict[str, Any],
        raw_refresh_token: str | None = None,
    ) -> None:
        """Blacklist the active access token, revoke DB & Redis session, and revoke refresh tokens."""
        jti = str(access_payload["jti"])
        user_id = int(access_payload["user_id"])
        exp = int(access_payload["exp"])

        await cls.blacklist_jti(redis, jti, exp)
        await cls.remove_session(redis, user_id, jti)

        await db.execute(
            update(UserSession)
            .where(UserSession.jti == jti)
            .values(revoked=True)
        )

        if raw_refresh_token:
            try:
                refresh_payload = decode_token(raw_refresh_token, verify_exp=False)
                if "jti" in refresh_payload and "exp" in refresh_payload:
                    await cls.blacklist_jti(
                        redis,
                        str(refresh_payload["jti"]),
                        int(refresh_payload["exp"]),
                    )
            except Exception:
                pass

            token_digest = hash_token(raw_refresh_token)
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.token_hash == token_digest)
                .values(revoked=True)
            )
        else:
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
                .values(revoked=True)
            )
        await db.commit()
