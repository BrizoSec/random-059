"""Unit tests for CriticalAccountsEnrichment and CriticalAccountsCache."""

from __future__ import annotations

import pytest

from privesc_detector.enrichment.critical_accounts import (
    CriticalAccountsCache,
    CriticalAccountsEnrichment,
)


@pytest.fixture
def accounts_cache() -> CriticalAccountsCache:
    return CriticalAccountsEnrichment.to_cache(CriticalAccountsEnrichment().load())


def test_critical_account_found(accounts_cache: CriticalAccountsCache) -> None:
    assert accounts_cache.is_critical("account:root") is True


def test_non_critical_account(accounts_cache: CriticalAccountsCache) -> None:
    # Insert a non-critical account into cache for testing
    from privesc_detector.enrichment.critical_accounts import CriticalAccount

    cache = CriticalAccountsCache(
        accounts={
            "account:svc-readonly": CriticalAccount(
                account_id="account:svc-readonly",
                account_type="service",
                is_critical=False,
                allowed_hosts=[],
                sensitivity_score=0.1,
            )
        }
    )
    assert cache.is_critical("account:svc-readonly") is False


def test_unknown_account(accounts_cache: CriticalAccountsCache) -> None:
    assert accounts_cache.is_critical("account:nobody") is False


def test_get_returns_account(accounts_cache: CriticalAccountsCache) -> None:
    acct = accounts_cache.get("account:alice-admin")
    assert acct is not None
    assert acct.account_id == "account:alice-admin"
    assert acct.is_critical is True


def test_get_returns_none_for_unknown(accounts_cache: CriticalAccountsCache) -> None:
    assert accounts_cache.get("account:ghost") is None


def test_load_returns_dict() -> None:
    raw = CriticalAccountsEnrichment().load()
    assert isinstance(raw, dict)
    assert len(raw) > 0
