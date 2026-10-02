from httpx import AsyncClient


async def test_login_rate_limit(client: AsyncClient) -> None:
    """Verify Redis rate limiter allows 5 requests per IP per minute and returns 429 on the 6th."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "ratelimit@example.com",
            "username": "ratelimit_user",
            "password": "ValidPassword123!",
            "first_name": "Rate",
            "last_name": "Limited",
        },
        headers={"X-Forwarded-For": "203.0.113.10"},
    )

    test_ip_headers = {"X-Forwarded-For": "203.0.113.55"}

    # First 5 requests within 1 minute should be processed (200 or 401, not 429)
    for attempt in range(5):
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "ratelimit@example.com",
                "password": "WrongPassword!",
            },
            headers=test_ip_headers,
        )
        assert response.status_code == 401, f"Attempt {attempt + 1} unexpectedly returned {response.status_code}"

    # 6th request from the same IP within the 1-minute window must return 429 Too Many Requests
    blocked_response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "ratelimit@example.com",
            "password": "ValidPassword123!",
        },
        headers=test_ip_headers,
    )
    assert blocked_response.status_code == 429
    assert "Too Many Requests" in blocked_response.json()["detail"]
    assert "Retry-After" in blocked_response.headers
