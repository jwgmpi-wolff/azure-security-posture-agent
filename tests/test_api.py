from __future__ import annotations

import base64
import json

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.auth import SESSION_STORE
from app.config import settings
from app.main import app
from app.models import Subscription, Tenant
from tests._helpers import build_sample_assessment, build_session


def bearer_for_tenant(tenant_id: str) -> dict[str, str]:
    payload = base64.urlsafe_b64encode(json.dumps({"tid": tenant_id}).encode()).decode().rstrip("=")
    return {"Authorization": f"Bearer header.{payload}.signature"}


def test_health_and_auth_context_contract() -> None:
    client = TestClient(app)

    health = client.get("/api/health")
    assert health.status_code == 200
    assert set(health.json()) == {"status", "version", "build", "authMode"}

    context = client.get("/api/auth/context")
    assert context.status_code == 200
    assert context.json()["authenticated"] is False


def test_health_and_auth_context_serialize_authenticated_cli_session() -> None:
    SESSION_STORE.clear()
    SESSION_STORE["session-1"] = build_session()
    client = TestClient(app)
    client.cookies.set(settings.session_cookie_name, "session-1")

    health = client.get("/api/health")
    context = client.get("/api/auth/session")

    assert health.status_code == 200
    assert health.json()["authMode"] == "cli"
    assert context.status_code == 200
    assert context.json()["authenticated"] is True
    assert context.json()["authMode"] == "cli"


def test_export_returns_404_before_assessment_run() -> None:
    SESSION_STORE.clear()
    SESSION_STORE["session-1"] = build_session(latest_assessment=None)
    client = TestClient(app)
    client.cookies.set(settings.session_cookie_name, "session-1")

    response = client.get("/api/export/csv")

    assert response.status_code == 404
    assert response.json()["error"]["category"] == "not_found"


def test_latest_metadata_and_copilot_endpoints_work_from_session(monkeypatch) -> None:
    assessment = build_sample_assessment()
    SESSION_STORE.clear()
    SESSION_STORE["session-1"] = build_session(latest_assessment=assessment)
    client = TestClient(app)
    client.cookies.set(settings.session_cookie_name, "session-1")

    latest = client.get("/api/assessment/latest")
    assert latest.status_code == 200
    assert latest.json()["runId"] == "run-1"
    assert "findings" not in latest.json()

    summary = client.get("/api/copilot/assessment-summary", params={"tenantId": "tenant-1", "subscriptionIds": ["sub-1"]})
    assert summary.status_code == 200
    assert summary.json()["runId"] == "run-1"

    findings = client.get("/api/copilot/security-findings", params={"tenantId": "tenant-1", "subscriptionIds": ["sub-1"]})
    assert findings.status_code == 200
    assert findings.json()["count"] == 1

    recommendations = client.get("/api/copilot/recommendations", params={"tenantId": "tenant-1", "subscriptionIds": ["sub-1"]})
    assert recommendations.status_code == 200
    assert recommendations.json()["count"] == 1


def test_assessment_run_contract(monkeypatch) -> None:
    assessment = build_sample_assessment()
    SESSION_STORE.clear()
    SESSION_STORE["session-1"] = build_session(latest_assessment=None)

    async def fake_validate_scope(session, tenant_id, subscription_ids):
        return []

    async def fake_run_live_assessment(session, payload):
        return assessment

    monkeypatch.setattr("app.main.validate_scope", fake_validate_scope)
    monkeypatch.setattr("app.main.run_live_assessment", fake_run_live_assessment)

    client = TestClient(app)
    client.cookies.set(settings.session_cookie_name, "session-1")
    response = client.post(
        "/api/assessment/run",
        json={"tenantId": "tenant-1", "subscriptionIds": ["sub-1"], "domains": ["security_overview"], "strictValidation": True},
    )

    assert response.status_code == 200
    assert response.json()["metadata"]["runId"] == "run-1"


def test_copilot_auth_context_discovers_token_tenant_scope(monkeypatch) -> None:
    principal = build_session().principal
    tenant = Tenant(tenantId="tenant-1", tenantName="Tenant One", sourceSystem="azure", sourceApi="/tenants")
    subscription = Subscription(
        subscriptionId="sub-1",
        subscriptionName="Subscription One",
        tenantId="tenant-1",
        state="Enabled",
        sourceSystem="azure",
        sourceApi="/subscriptions",
    )

    async def fake_acquire(tenant_id, bearer):
        assert tenant_id == "tenant-1"
        return principal

    async def fake_tenants(session):
        return [tenant], "https://management.azure.com/tenants"

    async def fake_subscriptions(session, tenant_id):
        return [subscription], "https://management.azure.com/subscriptions"

    monkeypatch.setattr("app.main.acquire_copilot_principal", fake_acquire)
    monkeypatch.setattr("app.main.get_tenants", fake_tenants)
    monkeypatch.setattr("app.main.get_subscriptions", fake_subscriptions)

    response = TestClient(app).get("/api/copilot/auth-context", headers=bearer_for_tenant("tenant-1"))

    assert response.status_code == 200
    assert response.json()["tokenTenantId"] == "tenant-1"
    assert response.json()["availableSubscriptions"][0]["subscriptionId"] == "sub-1"


def test_copilot_context_rejects_token_tenant_relabeling(monkeypatch) -> None:
    response = TestClient(app).post(
        "/api/copilot/auth-context",
        headers=bearer_for_tenant("tenant-1"),
        json={"tenantId": "tenant-2", "subscriptionIds": ["sub-2"]},
    )

    assert response.status_code == 403
    assert "Reconnect" in response.json()["error"]["message"]
    assert "tenant-1" in response.json()["error"]["message"]
    assert "tenant-2" in response.json()["error"]["message"]


def test_copilot_context_rejects_subscription_outside_delegated_access(monkeypatch) -> None:
    principal = build_session().principal

    async def fake_acquire(tenant_id, bearer):
        return principal

    async def fake_validate(session, tenant_id, subscription_ids):
        raise HTTPException(status_code=403, detail="The authenticated identity does not have access to subscriptions: sub-denied")

    monkeypatch.setattr("app.main.acquire_copilot_principal", fake_acquire)
    monkeypatch.setattr("app.main.validate_scope", fake_validate)

    response = TestClient(app).post(
        "/api/copilot/auth-context",
        headers=bearer_for_tenant("tenant-1"),
        json={"tenantId": "tenant-1", "subscriptionIds": ["sub-denied"]},
    )

    assert response.status_code == 403
    assert "sub-denied" in response.json()["error"]["message"]


def test_assessment_run_accepts_validated_copilot_bearer(monkeypatch) -> None:
    assessment = build_sample_assessment()
    principal = build_session().principal
    subscription = Subscription(
        subscriptionId="sub-1",
        subscriptionName="Subscription One",
        tenantId="tenant-1",
        state="Enabled",
        sourceSystem="azure",
        sourceApi="/subscriptions",
    )

    async def fake_acquire(tenant_id, bearer):
        return principal

    async def fake_validate(session, tenant_id, subscription_ids):
        return [subscription]

    async def fake_run(session, payload):
        return assessment

    monkeypatch.setattr("app.main.acquire_copilot_principal", fake_acquire)
    monkeypatch.setattr("app.main.validate_scope", fake_validate)
    monkeypatch.setattr("app.main.run_live_assessment", fake_run)

    response = TestClient(app).post(
        "/api/assessment/run",
        headers=bearer_for_tenant("tenant-1"),
        json={"tenantId": "tenant-1", "subscriptionIds": ["sub-1"], "domains": [], "strictValidation": True},
    )

    assert response.status_code == 200
    assert response.json()["metadata"]["runId"] == "run-1"