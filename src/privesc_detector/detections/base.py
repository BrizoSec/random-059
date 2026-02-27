"""Shared DetectionResult dataclass — the internal output of every detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from privesc_detector.model.alert import DetectionType, Severity


@dataclass
class DetectionResult:
    detection_type: DetectionType
    severity: Severity
    edge_ids: list[str]
    node_ids: list[str]
    host_id: str
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)
