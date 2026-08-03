from __future__ import annotations

import pytest

from app.models import AssessmentRequest, Confidence, Evidence, Finding, SecurityDomain, Severity


def test_assessment_request_aliases_and_exact_domain_list() -> None:
    request = AssessmentRequest.model_validate({"tenantId": "tenant-1", "subscriptionIds": ["sub-1"], "domains": ["security_overview"], "strictValidation": True})
    assert request.tenant_id == "tenant-1"
    assert request.model_dump(by_alias=True)["tenantId"] == "tenant-1"
    assert [domain.value for domain in SecurityDomain] == [
        "security_overview",
        "defender_for_cloud_posture",
        "azure_policy_and_compliance",
        "identity_and_access_posture",
        "management_group_and_subscription_governance",
        "network_security",
        "storage_security",
        "key_vault_security",
        "compute_and_vm_security",
        "aks_and_container_security",
        "logging_monitoring_and_evidence_retention",
        "security_recommendations_register",
    ]


def test_finding_requires_evidence_and_serializes_all_required_fields() -> None:
    evidence = Evidence(
        evidence_id="ev-1",
        finding_id="fd-1",
        source_system="azure",
        source_api="defender",
        observed_at_utc="2026-08-02T00:00:00Z",
        record_type="security_overview",
        summary="Grounding evidence",
        details={"endpoint": "https://management.azure.com"},
        data_quality_notes=[],
    )
    finding = Finding(
        finding_id="fd-1",
        run_id="run-1",
        tenant_id="tenant-1",
        tenant_name="Contoso",
        subscription_id="sub-1",
        subscription_name="Primary",
        domain=SecurityDomain.security_overview,
        severity=Severity.medium,
        title="Example finding",
        description="Example description",
        affected_resource_id="/subscriptions/sub-1",
        affected_resource_name="Primary",
        affected_resource_type="Microsoft.Resources/subscriptions",
        resource_group=None,
        region=None,
        source_system="azure",
        source_api="defender",
        evidence_id="ev-1",
        observed_at_utc="2026-08-02T00:00:00Z",
        recommendation="Do the thing",
        remediation_text="Review the configuration.",
        remediation_command_text=None,
        confidence=Confidence.high,
        data_quality_notes=[],
        evidence=[evidence],
    )
    payload = finding.model_dump(by_alias=True, mode="json")
    assert set(payload) >= {
        "findingId",
        "runId",
        "tenantId",
        "tenantName",
        "subscriptionId",
        "subscriptionName",
        "domain",
        "severity",
        "title",
        "description",
        "affectedResourceId",
        "affectedResourceName",
        "affectedResourceType",
        "resourceGroup",
        "region",
        "sourceSystem",
        "sourceApi",
        "evidenceId",
        "observedAtUtc",
        "recommendation",
        "remediationText",
        "remediationCommandText",
        "confidence",
        "dataQualityNotes",
        "evidence",
    }

    with pytest.raises(ValueError):
        Finding(
            finding_id="fd-2",
            run_id="run-1",
            tenant_id="tenant-1",
            subscription_id="sub-1",
            domain=SecurityDomain.security_overview,
            severity=Severity.medium,
            title="Bad finding",
            description="Missing evidence",
            affected_resource_id="/subscriptions/sub-1",
            source_system="azure",
            source_api="defender",
            evidence_id="ev-none",
            observed_at_utc="2026-08-02T00:00:00Z",
            recommendation="None",
            remediation_text="None",
            confidence=Confidence.low,
            evidence=[],
        )