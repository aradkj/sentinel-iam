from httpx import AsyncClient


async def test_create_session(client: AsyncClient) -> None:
    """Verify login creates a database session record returned by GET /api/v1/sessions."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "session.user@example.com",
            "username": "session_user",
            "password": "ValidPassword123!",
            "first_name": "Session",
            "last_name": "Owner",
        },
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "session.user@example.com", "password": "ValidPassword123!"},
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36",
            "X-Forwarded-For": "192.168.1.5",
        },
    )
    assert login_res.status_code == 200
    access_token = login_res.json()["access_token"]

    sessions_res = await client.get(
        "/api/v1/sessions",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert sessions_res.status_code == 200
    sessions = sessions_res.json()
    assert len(sessions) == 1
    assert sessions[0]["device"] == "Chrome Windows"
    assert sessions[0]["ip"] == "192.168.1.5"
    assert "last_activity" in sessions[0]


async def test_revoke_session(client: AsyncClient) -> None:
    """Verify DELETE /api/v1/sessions/{id} and POST /api/v1/sessions/revoke-all revoke sessions and blacklist tokens."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "multi.device@example.com",
            "username": "multi_device",
            "password": "ValidPassword123!",
            "first_name": "Multi",
            "last_name": "Device",
        },
    )

    # Login from Device 1
    login1 = await client.post(
        "/api/v1/auth/login",
        json={"email": "multi.device@example.com", "password": "ValidPassword123!"},
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/128.0 Safari/537.36"},
    )
    token1 = login1.json()["access_token"]

    # Login from Device 2
    login2 = await client.post(
        "/api/v1/auth/login",
        json={"email": "multi.device@example.com", "password": "ValidPassword123!"},
        headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/130.0"},
    )
    token2 = login2.json()["access_token"]
    session2_id = login2.json()["session_id"]

    # Device 1 revokes Device 2's session via DELETE /api/v1/sessions/{id}
    revoke_res = await client.delete(
        f"/api/v1/sessions/{session2_id}",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert revoke_res.status_code == 200

    # Device 2's token is now blacklisted and rejected with HTTP 401
    device2_me = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert device2_me.status_code == 401

    # Device 1 calls POST /api/v1/sessions/revoke-all
    revoke_all_res = await client.post(
        "/api/v1/sessions/revoke-all",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert revoke_all_res.status_code == 200

    # Device 1's token is now also revoked
    device1_me = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token1}"},
    )
    assert device1_me.status_code == 401
