"""SessionStore — async Motor CRUD for per-host time-window session docs."""

from __future__ import annotations

from datetime import datetime

from motor.motor_asyncio import AsyncIOMotorDatabase

COLLECTION = "sessions"


class SessionStore:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:  # type: ignore[type-arg]
        self._col = db[COLLECTION]

    async def ensure_indexes(self) -> None:
        await self._col.create_index([("host_id", 1), ("window_start", -1)], unique=True)

    async def upsert_window(
        self,
        host_id: str,
        window_start: datetime,
        auth_count: int,
        keytab_access: bool,
    ) -> None:
        key = {"host_id": host_id, "window_start": window_start.isoformat()}
        update = {
            "$set": {
                "auth_count": auth_count,
                "keytab_access": keytab_access,
                "updated_at": datetime.utcnow().isoformat(),
            }
        }
        await self._col.update_one(key, update, upsert=True)

    async def get_window(
        self, host_id: str, window_start: datetime
    ) -> dict | None:  # type: ignore[type-arg]
        return await self._col.find_one(
            {"host_id": host_id, "window_start": window_start.isoformat()},
            {"_id": 0},
        )
