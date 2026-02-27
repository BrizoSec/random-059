"""AlertStore — async Motor CRUD for the alerts collection."""

from __future__ import annotations

from datetime import datetime

from motor.motor_asyncio import AsyncIOMotorDatabase

from privesc_detector.model.alert import Alert, DetectionType

COLLECTION = "alerts"


class AlertStore:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:  # type: ignore[type-arg]
        self._col = db[COLLECTION]

    async def ensure_indexes(self) -> None:
        await self._col.create_index([("triggered_at", -1)])
        await self._col.create_index([("detection_type", 1), ("triggered_at", -1)])
        await self._col.create_index([("acknowledged", 1)])

    async def insert(self, alert: Alert) -> str:
        doc = alert.model_dump(mode="json")
        await self._col.insert_one(doc)
        return alert.id

    async def list_alerts(
        self,
        skip: int = 0,
        limit: int = 50,
        detection_type: DetectionType | None = None,
        since: datetime | None = None,
    ) -> list[Alert]:
        query: dict = {}  # type: ignore[type-arg]
        if detection_type:
            query["detection_type"] = detection_type
        if since:
            query["triggered_at"] = {"$gte": since.isoformat()}

        cursor = self._col.find(query, {"_id": 0}).sort("triggered_at", -1).skip(skip).limit(limit)
        return [Alert(**doc) async for doc in cursor]

    async def get_by_id(self, alert_id: str) -> Alert | None:
        doc = await self._col.find_one({"id": alert_id}, {"_id": 0})
        return Alert(**doc) if doc else None

    async def acknowledge(self, alert_id: str) -> bool:
        result = await self._col.update_one(
            {"id": alert_id}, {"$set": {"acknowledged": True}}
        )
        return result.modified_count == 1
