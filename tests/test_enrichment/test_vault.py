"""Unit tests for VaultEnrichment and VaultCache."""

from __future__ import annotations

import pytest

from privesc_detector.enrichment.vault import VaultCache, VaultEnrichment


@pytest.fixture
def vault_cache() -> VaultCache:
    return VaultEnrichment.to_cache(VaultEnrichment().load())


def test_keytab_in_expected_location(vault_cache: VaultCache) -> None:
    assert vault_cache.is_keytab_expected("host:web-prod-01", "/etc/krb5.keytab") is True


def test_keytab_wrong_host(vault_cache: VaultCache) -> None:
    # /etc/http.keytab is only expected on web-prod-01, not bastion-01
    assert vault_cache.is_keytab_expected("host:bastion-01", "/etc/http.keytab") is False


def test_keytab_not_in_vault(vault_cache: VaultCache) -> None:
    assert vault_cache.is_keytab_in_vault("/tmp/smuggled.keytab") is False


def test_keytab_in_vault(vault_cache: VaultCache) -> None:
    assert vault_cache.is_keytab_in_vault("/etc/krb5.keytab") is True


def test_load_returns_dict() -> None:
    raw = VaultEnrichment().load()
    assert isinstance(raw, dict)
    assert len(raw) > 0
