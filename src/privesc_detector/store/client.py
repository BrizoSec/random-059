"""Motor async client setup.

The client is created once at app startup via FastAPI lifespan and stored
on app.state so all routes share the same connection pool.
"""

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase


def get_motor_client(uri: str) -> AsyncIOMotorClient:  # type: ignore[type-arg]
    return AsyncIOMotorClient(uri)


def get_database(
    client: AsyncIOMotorClient,  # type: ignore[type-arg]
    db_name: str,
) -> AsyncIOMotorDatabase:  # type: ignore[type-arg]
    return client[db_name]
