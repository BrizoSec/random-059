"""NodeStore — async Motor CRUD for the nodes collection."""

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase

from privesc_detector.model.node import AccountNode, HostNode

COLLECTION = "nodes"
NodeModel = AccountNode | HostNode


class NodeStore:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:  # type: ignore[type-arg]
        self._col = db[COLLECTION]

    async def ensure_indexes(self) -> None:
        await self._col.create_index([("id", 1)], unique=True)
        await self._col.create_index([("environment", 1), ("privilege_tier", -1)])

    async def upsert(self, node: NodeModel) -> None:
        doc = node.model_dump(mode="json")
        await self._col.update_one({"id": node.id}, {"$set": doc}, upsert=True)

    async def get_by_id(self, node_id: str) -> NodeModel | None:
        doc = await self._col.find_one({"id": node_id})
        if doc is None:
            return None
        return _deserialize(doc)

    async def get_many(self, ids: list[str]) -> list[NodeModel]:
        cursor = self._col.find({"id": {"$in": ids}})
        return [_deserialize(doc) async for doc in cursor]


def _deserialize(doc: dict) -> NodeModel:  # type: ignore[type-arg]
    # AccountNode has 'username'; HostNode has 'hostname'
    if "username" in doc:
        return AccountNode(**doc)
    return HostNode(**doc)
