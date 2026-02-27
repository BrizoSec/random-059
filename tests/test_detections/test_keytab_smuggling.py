"""Unit tests for Detection D — Keytab Smuggling."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from privesc_detector.config import KeytabSmugglingConfig
from privesc_detector.detections import keytab_smuggling
from privesc_detector.enrichment.cache import AllEnrichments
from privesc_detector.enrichment.critical_accounts import (
    CriticalAccountsCache,
    CriticalAccountsEnrichment,
)
from privesc_detector.enrichment.vault import VaultCache, VaultEnrichment
from privesc_detector.models.edge import AuthEdge


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault_cache() -> VaultCache:
    return VaultEnrichment.to_cache(VaultEnrichment().load())


@pytest.fixture
def critical_accounts_cache() -> CriticalAccountsCache:
    return CriticalAccountsEnrichment.to_cache(CriticalAccountsEnrichment().load())


@pytest.fixture
def all_enrichments(vault_cache: VaultCache, critical_accounts_cache: CriticalAccountsCache) -> AllEnrichments:
    return AllEnrichments(vault=vault_cache, critical_accounts=critical_accounts_cache)


@pytest.fixture
def keytab_config() -> KeytabSmugglingConfig:
    return KeytabSmugglingConfig(enabled=True)


def _make_kinit_edge(**kwargs: Any) -> AuthEdge:
    defaults: dict[str, Any] = {
        "src_account_id": "account:alice",
        "src_host_id": "host:app-dev-02",
        "dst_account_id": "account:alice-admin",
        "dst_host_id": "host:app-dev-02",
        "edge_type": "kinit",
        "src_privilege": 0.1,
        "dst_privilege": 0.6,
        "host_id": "host:app-dev-02",
        "raw_source": "unix_auth",
        "timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "auth_success": True,
        "metadata": {"keytab_path": "/tmp/smuggled.keytab"},
    }
    defaults.update(kwargs)
    return AuthEdge(**defaults)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_alert_on_non_kinit_edge(all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig) -> None:
    edge = _make_kinit_edge(edge_type="ssh", auth_success=True)
    assert keytab_smuggling.detect(edge, all_enrichments, keytab_config) is None


def test_no_alert_when_auth_success_false(all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig) -> None:
    edge = _make_kinit_edge(auth_success=False)
    assert keytab_smuggling.detect(edge, all_enrichments, keytab_config) is None


def test_no_alert_when_keytab_in_expected_location(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    # /etc/krb5.keytab IS expected on host:app-dev-02
    edge = _make_kinit_edge(
        host_id="host:app-dev-02",
        metadata={"keytab_path": "/etc/krb5.keytab"},
    )
    assert keytab_smuggling.detect(edge, all_enrichments, keytab_config) is None


def test_alert_when_keytab_wrong_host(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    # /etc/http.keytab is in vault but only expected on host:web-prod-01
    edge = _make_kinit_edge(
        host_id="host:bastion-01",
        metadata={"keytab_path": "/etc/http.keytab"},
    )
    result = keytab_smuggling.detect(edge, all_enrichments, keytab_config)
    assert result is not None
    assert result.detection_type == "keytab_smuggling"
    assert result.metadata["in_vault"] is True
    assert result.metadata["in_expected_location"] is False


def test_alert_when_keytab_not_in_vault(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    edge = _make_kinit_edge(metadata={"keytab_path": "/tmp/smuggled.keytab"})
    result = keytab_smuggling.detect(edge, all_enrichments, keytab_config)
    assert result is not None
    assert result.detection_type == "keytab_smuggling"
    assert result.metadata["in_vault"] is False
    assert result.metadata["in_expected_location"] is False


def test_no_alert_when_no_keytab_path_in_metadata(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    edge = _make_kinit_edge(metadata={})
    assert keytab_smuggling.detect(edge, all_enrichments, keytab_config) is None


def test_severity_critical_for_critical_account(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    # account:alice-admin is in the critical accounts cache
    edge = _make_kinit_edge(
        src_account_id="account:alice-admin",
        metadata={"keytab_path": "/tmp/smuggled.keytab"},
    )
    result = keytab_smuggling.detect(edge, all_enrichments, keytab_config)
    assert result is not None
    assert result.severity == "critical"
    assert result.metadata["account_is_critical"] is True


def test_severity_high_for_non_critical_account(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    # account:alice is NOT in the critical accounts cache
    edge = _make_kinit_edge(
        src_account_id="account:alice",
        metadata={"keytab_path": "/tmp/smuggled.keytab"},
    )
    result = keytab_smuggling.detect(edge, all_enrichments, keytab_config)
    assert result is not None
    assert result.severity == "high"
    assert result.metadata["account_is_critical"] is False


def test_disabled_detection_returns_none(
    all_enrichments: AllEnrichments,
) -> None:
    config = KeytabSmugglingConfig(enabled=False)
    edge = _make_kinit_edge(metadata={"keytab_path": "/tmp/smuggled.keytab"})
    assert keytab_smuggling.detect(edge, all_enrichments, config) is None


def test_metadata_includes_vault_flags(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    edge = _make_kinit_edge(metadata={"keytab_path": "/tmp/smuggled.keytab"})
    result = keytab_smuggling.detect(edge, all_enrichments, keytab_config)
    assert result is not None
    assert "keytab_path" in result.metadata
    assert "in_vault" in result.metadata
    assert "in_expected_location" in result.metadata
    assert "account_is_critical" in result.metadata
