"""EnrichmentCacheManager — holds all enrichment caches and runs background refresh."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass

from privesc_detector.config import EnrichmentConfig
from privesc_detector.enrichment.critical_accounts import (
    CriticalAccountsCache,
    CriticalAccountsEnrichment,
)
from privesc_detector.enrichment.vault import VaultCache, VaultEnrichment


@dataclass
class AllEnrichments:
    vault: VaultCache
    critical_accounts: CriticalAccountsCache


class EnrichmentCacheManager:
    """
    Holds all enrichment caches and runs a background asyncio task
    to refresh them at a configurable interval.

    Detection functions receive an AllEnrichments snapshot — a plain
    dataclass with no async — keeping detections fully synchronous.
    """

    def __init__(self, config: EnrichmentConfig) -> None:
        self._config = config
        self._vault_store = VaultEnrichment()
        self._accounts_store = CriticalAccountsEnrichment()
        self._cache: AllEnrichments | None = None
        self._task: asyncio.Task | None = None

    def load_sync(self) -> None:
        """Initial synchronous load at startup (before event loop tasks start)."""
        self._cache = self._build_cache()

    async def start_refresh_loop(self) -> None:
        """Start the background refresh task — call from FastAPI lifespan."""
        self._task = asyncio.create_task(self._refresh_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    @property
    def current(self) -> AllEnrichments:
        if self._cache is None:
            raise RuntimeError("EnrichmentCacheManager not yet loaded")
        return self._cache

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self._config.refresh_interval_seconds)
            self._cache = self._build_cache()

    def _build_cache(self) -> AllEnrichments:
        return AllEnrichments(
            vault=VaultEnrichment.to_cache(self._vault_store.load()),
            critical_accounts=CriticalAccountsEnrichment.to_cache(
                self._accounts_store.load()
            ),
        )
