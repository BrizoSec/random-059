"""GET /health — liveness check."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health")
async def health(request: Request) -> dict:  # type: ignore[type-arg]
    try:
        # Ping MongoDB to verify connectivity
        await request.app.state.mongo_client.admin.command("ping")
        db_status = "connected"
    except Exception:
        db_status = "unavailable"

    return {"status": "ok", "db": db_status}
