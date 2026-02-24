"""EdgeStore — async Motor CRUD for the edges collection."""

from __future__ import annotations

from datetime import datetime

from motor.motor_asyncio import AsyncIOMotorDatabase

from privesc_detector.models.edge import AuthEdge

COLLECTION = "edges"


class EdgeStore:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:  # type: ignore[type-arg]
        self._col = db[COLLECTION]

    async def ensure_indexes(self) -> None:
        await self._col.create_index([("host_id", 1), ("timestamp", -1)])
        await self._col.create_index([("src_node_id", 1), ("dst_node_id", 1)])
        await self._col.create_index([("timestamp", -1)])

    async def insert(self, edge: AuthEdge) -> str:
        doc = edge.model_dump(mode="json")
        await self._col.insert_one(doc)
        return edge.id

    async def get_recent(self, host_id: str, since: datetime) -> list[AuthEdge]:
        cursor = self._col.find(
            {"host_id": host_id, "timestamp": {"$gte": since.isoformat()}}
        ).sort("timestamp", -1)
        return [AuthEdge(**doc) async for doc in cursor]

    async def get_by_ids(self, ids: list[str]) -> list[AuthEdge]:
        cursor = self._col.find({"id": {"$in": ids}})
        return [AuthEdge(**doc) async for doc in cursor]

    async def get_all_for_graph(self) -> list[AuthEdge]:
        """Fetch all edges for building the in-memory NetworkX graph."""
        cursor = self._col.find({})
        return [AuthEdge(**doc) async for doc in cursor]
