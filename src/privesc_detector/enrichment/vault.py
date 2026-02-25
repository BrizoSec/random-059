"""Vault enrichment — maps host_id → expected keytab paths."""

from __future__ import annotations

from dataclasses import dataclass

from privesc_detector.enrichment.base import EnrichmentStore


@dataclass
class VaultCache:
    """Typed wrapper around vault keytab data."""

    keytabs_by_host: dict[str, set[str]]

    def is_keytab_expected(self, host_id: str, keytab_path: str) -> bool:
        return keytab_path in self.keytabs_by_host.get(host_id, set())

    def is_keytab_in_vault(self, keytab_path: str) -> bool:
        return any(keytab_path in paths for paths in self.keytabs_by_host.values())


class VaultEnrichment(EnrichmentStore):
    """Stub — replace load() body with real vault API/DB query."""

    def load(self) -> dict:
        return {
            "host:web-prod-01": ["/etc/krb5.keytab", "/etc/http.keytab"],
            "host:db-prod-01": ["/etc/krb5.keytab", "/var/lib/postgresql/pg.keytab"],
            "host:bastion-01": ["/etc/krb5.keytab"],
            "host:app-dev-02": ["/etc/krb5.keytab"],
        }

    @staticmethod
    def to_cache(raw: dict) -> VaultCache:
        return VaultCache(keytabs_by_host={k: set(v) for k, v in raw.items()})
