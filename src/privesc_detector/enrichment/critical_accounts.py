"""Critical accounts enrichment — maps account_id → account attributes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from privesc_detector.enrichment.base import EnrichmentStore


@dataclass
class CriticalAccount:
    account_id: str
    account_type: Literal["human", "service", "root", "shared"]
    is_critical: bool
    allowed_hosts: list[str]  # empty = unrestricted
    sensitivity_score: float  # 0.0–1.0


@dataclass
class CriticalAccountsCache:
    accounts: dict[str, CriticalAccount]  # keyed by account_id

    def get(self, account_id: str) -> CriticalAccount | None:
        return self.accounts.get(account_id)

    def is_critical(self, account_id: str) -> bool:
        acct = self.accounts.get(account_id)
        return acct.is_critical if acct else False


class CriticalAccountsEnrichment(EnrichmentStore):
    """Stub — replace load() body with real query."""

    def load(self) -> dict:
        return {
            "account:svc-deploy": {
                "account_type": "service",
                "is_critical": True,
                "allowed_hosts": ["host:web-prod-01"],
                "sensitivity_score": 0.9,
            },
            "account:root": {
                "account_type": "root",
                "is_critical": True,
                "allowed_hosts": [],
                "sensitivity_score": 1.0,
            },
            "account:alice-admin": {
                "account_type": "human",
                "is_critical": True,
                "allowed_hosts": ["host:bastion-01", "host:app-dev-02"],
                "sensitivity_score": 0.7,
            },
        }

    @staticmethod
    def to_cache(raw: dict) -> CriticalAccountsCache:
        accounts = {
            aid: CriticalAccount(account_id=aid, **attrs) for aid, attrs in raw.items()
        }
        return CriticalAccountsCache(accounts=accounts)
