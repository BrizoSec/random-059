"""GET /enrichment/status — report current enrichment cache state."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from privesc_detector.api.dependencies import get_enrichment_cache
from privesc_detector.enrichment.cache import EnrichmentCacheManager

router = APIRouter()


class EnrichmentStatus(BaseModel):
    vault_host_count: int
    critical_account_count: int


@router.get("/enrichment/status", response_model=EnrichmentStatus)
def enrichment_status(
    cache: EnrichmentCacheManager = Depends(get_enrichment_cache),
) -> EnrichmentStatus:
    """Return item counts from the current enrichment cache snapshot."""
    current = cache.current
    return EnrichmentStatus(
        vault_host_count=len(current.vault.keytabs_by_host),
        critical_account_count=len(current.critical_accounts.accounts),
    )
