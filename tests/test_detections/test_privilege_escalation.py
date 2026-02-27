"""Unit tests for Detection A — Privilege Escalation."""

from __future__ import annotations

from typing import Callable

import pytest

from privesc_detector.config import PrivEscConfig
from privesc_detector.detections import privilege_escalation
from privesc_detector.models.events import AuthEvent


def test_no_alert_when_equal_privilege(
    make_edge: Callable[..., AuthEvent],
    privesc_config: PrivEscConfig,
) -> None:
    edge = make_edge(src_privilege=0.5, dst_privilege=0.5)
    assert privilege_escalation.detect(edge, privesc_config) is None


def test_no_alert_when_dst_lower(
    make_edge: Callable[..., AuthEvent],
    privesc_config: PrivEscConfig,
) -> None:
    edge = make_edge(src_privilege=0.8, dst_privilege=0.3)
    assert privilege_escalation.detect(edge, privesc_config) is None


def test_alert_on_higher_dst_privilege(
    make_edge: Callable[..., AuthEvent],
    privesc_config: PrivEscConfig,
) -> None:
    edge = make_edge(src_privilege=0.2, dst_privilege=0.7)
    result = privilege_escalation.detect(edge, privesc_config)
    assert result is not None
    assert result.detection_type == "privilege_escalation"
    assert result.edge_ids == [edge.id]
    assert edge.src_node_id in result.node_ids
    assert edge.dst_node_id in result.node_ids


def test_disabled_detection_returns_none(
    make_edge: Callable[..., AuthEvent],
) -> None:
    edge = make_edge(src_privilege=0.1, dst_privilege=0.9)
    config = PrivEscConfig(enabled=False)
    assert privilege_escalation.detect(edge, config) is None


@pytest.mark.parametrize(
    ("src", "dst", "expected_severity"),
    [
        (0.0, 0.1, "low"),       # delta=0.1 < 0.2
        (0.0, 0.3, "medium"),    # delta=0.3
        (0.0, 0.6, "high"),      # delta=0.6
        (0.0, 0.9, "critical"),  # delta=0.9 > 0.8
    ],
)
def test_severity_mapping(
    make_edge: Callable[..., AuthEvent],
    privesc_config: PrivEscConfig,
    src: float,
    dst: float,
    expected_severity: str,
) -> None:
    edge = make_edge(src_privilege=src, dst_privilege=dst)
    result = privilege_escalation.detect(edge, privesc_config)
    assert result is not None
    assert result.severity == expected_severity


def test_metadata_contains_delta(
    make_edge: Callable[..., AuthEvent],
    privesc_config: PrivEscConfig,
) -> None:
    edge = make_edge(src_privilege=0.2, dst_privilege=0.5)
    result = privilege_escalation.detect(edge, privesc_config)
    assert result is not None
    assert abs(result.metadata["delta"] - 0.3) < 1e-6


def test_description_includes_host_and_values(
    make_edge: Callable[..., AuthEvent],
    privesc_config: PrivEscConfig,
) -> None:
    edge = make_edge(src_privilege=0.1, dst_privilege=0.9, host_id="host:prod-01")
    result = privilege_escalation.detect(edge, privesc_config)
    assert result is not None
    assert "host:prod-01" in result.description
    assert "0.10" in result.description
    assert "0.90" in result.description
