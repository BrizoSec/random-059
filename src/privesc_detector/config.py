"""PyYAML loader → typed config dataclasses."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class BurstConfig:
    window_seconds: int = 60
    distinct_account_threshold: int = 5
    max_events_tracked: int = 1000


@dataclass
class ChainConfig:
    max_chain_length: int = 4
    max_graph_nodes: int = 50_000
    cycle_detection: bool = True


@dataclass
class PrivEscConfig:
    enabled: bool = True


@dataclass
class KeytabSmugglingConfig:
    enabled: bool = True


@dataclass
class EnrichmentConfig:
    refresh_interval_seconds: int = 300


@dataclass
class AppConfig:
    auth_burst: BurstConfig = field(default_factory=BurstConfig)
    auth_chain: ChainConfig = field(default_factory=ChainConfig)
    privilege_escalation: PrivEscConfig = field(default_factory=PrivEscConfig)
    keytab_smuggling: KeytabSmugglingConfig = field(default_factory=KeytabSmugglingConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "privesc_detector"


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load thresholds.yaml and return a typed AppConfig.

    Falls back to defaults if the file is absent or a section is missing.
    Environment variables MONGO_URI and MONGO_DB override the defaults.
    """
    raw: dict = {}
    if path is None:
        path = Path(__file__).parent.parent.parent / "config" / "thresholds.yaml"

    resolved = Path(path)
    if resolved.exists():
        with resolved.open() as f:
            raw = yaml.safe_load(f) or {}

    burst_raw = raw.get("auth_burst", {})
    chain_raw = raw.get("auth_chain", {})
    privesc_raw = raw.get("privilege_escalation", {})
    keytab_raw = raw.get("keytab_smuggling", {})
    enrichment_raw = raw.get("enrichment", {})

    return AppConfig(
        auth_burst=BurstConfig(
            window_seconds=burst_raw.get("window_seconds", 60),
            distinct_account_threshold=burst_raw.get("distinct_account_threshold", 5),
            max_events_tracked=burst_raw.get("max_events_tracked", 1000),
        ),
        auth_chain=ChainConfig(
            max_chain_length=chain_raw.get("max_chain_length", 4),
            max_graph_nodes=chain_raw.get("max_graph_nodes", 50_000),
            cycle_detection=chain_raw.get("cycle_detection", True),
        ),
        privilege_escalation=PrivEscConfig(
            enabled=privesc_raw.get("enabled", True),
        ),
        keytab_smuggling=KeytabSmugglingConfig(
            enabled=keytab_raw.get("enabled", True),
        ),
        enrichment=EnrichmentConfig(
            refresh_interval_seconds=enrichment_raw.get("refresh_interval_seconds", 300),
        ),
        mongo_uri=os.getenv("MONGO_URI", "mongodb://localhost:27017"),
        mongo_db=os.getenv("MONGO_DB", "privesc_detector"),
    )
