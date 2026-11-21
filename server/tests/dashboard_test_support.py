"""Dashboard JWT transport inputs shared by the real serving test stacks."""

import time
import jwt

_JWT_SECRET = "test-dashboard-secret-at-least-32bytes!"


def _make_jwt(
    team_ids: list[str], user_id: str = "user-123", *, lifetime_seconds: int = 3600
) -> str:
    return jwt.encode(
        {
            "user_id": user_id,
            "team_ids": team_ids,
            "exp": int(time.time()) + lifetime_seconds,
        },
        _JWT_SECRET,
        algorithm="HS256",
    )
