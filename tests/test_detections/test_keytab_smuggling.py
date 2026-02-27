"""Unit tests for Detection D — Keytab Smuggling."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from privesc_detector.config import KeytabSmugglingConfig
from privesc_detector.detections import keytab_smuggling
from privesc_detector.enrichment.cache import AllEnrichments
from privesc_detector.model.event import AuthenticationEvent


def _make_kinit_edge(**kwargs: Any) -> AuthenticationEvent:
    defaults: dict[str, Any] = {
        "src_account_id": "account:alice",
        "src_host_id": "host:app-dev-02",
        "dst_account_id": "account:alice-admin",
        "dst_host_id": "host:app-dev-02",
        "mechanism": "kinit",
        "src_privilege": 0.1,
        "dst_privilege": 0.6,
        "host_id": "host:app-dev-02",
        "raw_source": "unix_auth",
        "timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        "keytab_path": "/tmp/smuggled.keytab",
    }
    defaults.update(kwargs)
    return AuthenticationEvent(**defaults)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_alert_on_non_kinit_event(all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig) -> None:
    event = _make_kinit_edge(mechanism="oidc")
    assert keytab_smuggling.detect(event, all_enrichments, keytab_config) is None


def test_no_alert_when_keytab_in_expected_location(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    # /etc/krb5.keytab IS expected on host:app-dev-02
    event = _make_kinit_edge(
        host_id="host:app-dev-02",
        keytab_path="/etc/krb5.keytab",
    )
    assert keytab_smuggling.detect(event, all_enrichments, keytab_config) is None


def test_alert_when_keytab_wrong_host(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    # /etc/http.keytab is in vault but only expected on host:web-prod-01
    event = _make_kinit_edge(
        host_id="host:bastion-01",
        keytab_path="/etc/http.keytab",
    )
    result = keytab_smuggling.detect(event, all_enrichments, keytab_config)
    assert result is not None
    assert result.detection_type == "keytab_smuggling"
    assert result.metadata["in_vault"] is True
    assert result.metadata["in_expected_location"] is False


def test_alert_when_keytab_not_in_vault(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    event = _make_kinit_edge()  # keytab_path="/tmp/smuggled.keytab" (not in vault)
    result = keytab_smuggling.detect(event, all_enrichments, keytab_config)
    assert result is not None
    assert result.detection_type == "keytab_smuggling"
    assert result.metadata["in_vault"] is False
    assert result.metadata["in_expected_location"] is False


def test_no_alert_when_no_keytab_path(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    event = _make_kinit_edge(keytab_path=None)
    assert keytab_smuggling.detect(event, all_enrichments, keytab_config) is None


def test_severity_critical_for_critical_account(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    # account:alice-admin is in the critical accounts cache
    event = _make_kinit_edge(src_account_id="account:alice-admin")
    result = keytab_smuggling.detect(event, all_enrichments, keytab_config)
    assert result is not None
    assert result.severity == "critical"
    assert result.metadata["account_is_critical"] is True


def test_severity_high_for_non_critical_account(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    # account:alice is NOT in the critical accounts cache
    event = _make_kinit_edge(src_account_id="account:alice")
    result = keytab_smuggling.detect(event, all_enrichments, keytab_config)
    assert result is not None
    assert result.severity == "high"
    assert result.metadata["account_is_critical"] is False


def test_disabled_detection_returns_none(
    all_enrichments: AllEnrichments,
) -> None:
    config = KeytabSmugglingConfig(enabled=False)
    event = _make_kinit_edge()
    assert keytab_smuggling.detect(event, all_enrichments, config) is None


def test_metadata_includes_vault_flags(
    all_enrichments: AllEnrichments, keytab_config: KeytabSmugglingConfig
) -> None:
    event = _make_kinit_edge()
    result = keytab_smuggling.detect(event, all_enrichments, keytab_config)
    assert result is not None
    assert "keytab_path" in result.metadata
    assert "in_vault" in result.metadata
    assert "in_expected_location" in result.metadata
    assert "account_is_critical" in result.metadata
