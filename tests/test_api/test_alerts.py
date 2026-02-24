"""Unit tests for alert API routes — store layer fully mocked."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from privesc_detector.models.alert import Alert
from privesc_detector.store.alerts import AlertStore


def _make_app(alert_store: AlertStore) -> FastAPI:
    """Build a minimal FastAPI app with only the alerts router and a mocked store."""
    from privesc_detector.api.routes import alerts

    app = FastAPI()
    app.include_router(alerts.router)

    # Inject the mock store via app.state so the dependency provider resolves it
    app.state.alert_store = alert_store
    return app


def _sample_alert(**kwargs) -> Alert:  # type: ignore[type-arg]
    defaults = dict(
        detection_type="privilege_escalation",
        severity="high",
        host_id="host:web-01",
        description="Test alert",
        edge_ids=["edge-1"],
        node_ids=["account:alice"],
    )
    defaults.update(kwargs)
    return Alert(**defaults)


@pytest.fixture
def mock_alert_store() -> AlertStore:
    store = MagicMock(spec=AlertStore)
    store.list_alerts = AsyncMock(return_value=[])
    store.get_by_id = AsyncMock(return_value=None)
    store.acknowledge = AsyncMock(return_value=False)
    return store  # type: ignore[return-value]


@pytest.fixture
def app(mock_alert_store: AlertStore) -> FastAPI:
    return _make_app(mock_alert_store)


@pytest.fixture
async def client(app: FastAPI) -> AsyncClient:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# GET /alerts
# ---------------------------------------------------------------------------


async def test_list_alerts_empty(client: AsyncClient, mock_alert_store: AlertStore) -> None:
    mock_alert_store.list_alerts = AsyncMock(return_value=[])  # type: ignore[method-assign]
    response = await client.get("/alerts")
    assert response.status_code == 200
    assert response.json() == []


async def test_list_alerts_returns_results(
    client: AsyncClient, mock_alert_store: AlertStore
) -> None:
    alert = _sample_alert()
    mock_alert_store.list_alerts = AsyncMock(return_value=[alert])  # type: ignore[method-assign]
    response = await client.get("/alerts")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["detection_type"] == "privilege_escalation"
    assert data[0]["severity"] == "high"


async def test_list_alerts_passes_query_params(
    client: AsyncClient, mock_alert_store: AlertStore
) -> None:
    mock_alert_store.list_alerts = AsyncMock(return_value=[])  # type: ignore[method-assign]
    await client.get("/alerts?skip=10&limit=5&detection_type=auth_burst")
    mock_alert_store.list_alerts.assert_awaited_once_with(
        skip=10,
        limit=5,
        detection_type="auth_burst",
        since=None,
    )


# ---------------------------------------------------------------------------
# GET /alerts/{alert_id}
# ---------------------------------------------------------------------------


async def test_get_alert_not_found(client: AsyncClient, mock_alert_store: AlertStore) -> None:
    mock_alert_store.get_by_id = AsyncMock(return_value=None)  # type: ignore[method-assign]
    response = await client.get("/alerts/missing-id")
    assert response.status_code == 404


async def test_get_alert_found(client: AsyncClient, mock_alert_store: AlertStore) -> None:
    alert = _sample_alert()
    mock_alert_store.get_by_id = AsyncMock(return_value=alert)  # type: ignore[method-assign]
    response = await client.get(f"/alerts/{alert.id}")
    assert response.status_code == 200
    assert response.json()["id"] == alert.id


# ---------------------------------------------------------------------------
# PATCH /alerts/{alert_id}/acknowledge
# ---------------------------------------------------------------------------


async def test_acknowledge_alert_success(
    client: AsyncClient, mock_alert_store: AlertStore
) -> None:
    alert = _sample_alert()
    mock_alert_store.acknowledge = AsyncMock(return_value=True)  # type: ignore[method-assign]
    response = await client.patch(f"/alerts/{alert.id}/acknowledge")
    assert response.status_code == 200
    assert response.json()["acknowledged"] is True


async def test_acknowledge_alert_not_found(
    client: AsyncClient, mock_alert_store: AlertStore
) -> None:
    mock_alert_store.acknowledge = AsyncMock(return_value=False)  # type: ignore[method-assign]
    response = await client.patch("/alerts/ghost-id/acknowledge")
    assert response.status_code == 404
