from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models import (
    AssessmentResult,
    AssessmentRunMetadata,
    AssessmentSummary,
    AuthMode,
    Confidence,
    Evidence,
    Finding,
    Recommendation,
    SecurityDomain,
    SessionPrincipal,
    SessionState,
    Severity,
)


def build_sample_finding() -> Finding:
    evidence = Evidence(
        evidence_id="ev-1",
        finding_id="fd-1",
        source_system="azure",
        source_api="resource_graph",
        observed_at_utc=datetime.now(UTC),
        record_type="security_overview",
        summary="Secure score below maximum",
        details={"endpoint": "https://management.azure.com/providers/Microsoft.ResourceGraph/resources", "statusCode": 200},
        data_quality_notes=[],
    )
    return Finding(
        finding_id="fd-1",
        run_id="run-1",
        tenant_id="tenant-1",
        tenant_name="Contoso",
        subscription_id="sub-1",
        subscription_name="Primary",
        domain=SecurityDomain.security_overview,
        severity=Severity.medium,
        title="Secure score below maximum",
        description="Defender for Cloud returned a secure score below the maximum available score.",
        affected_resource_id="/subscriptions/sub-1",
        affected_resource_name="Primary",
        affected_resource_type="Microsoft.Resources/subscriptions",
        resource_group=None,
        region=None,
        source_system="azure",
        source_api="defender",
        evidence_id="ev-1",
        observed_at_utc=datetime.now(UTC),
        recommendation="Review the highest-impact secure score controls.",
        remediation_text="Use Defender for Cloud recommendations to remediate the highest value controls.",
        remediation_command_text=None,
        confidence=Confidence.high,
        data_quality_notes=[],
        evidence=[evidence],
    )


def build_sample_recommendation() -> Recommendation:
    return Recommendation(
        recommendation_id="rc-1",
        finding_id="fd-1",
        title="Review the highest-impact secure score controls",
        priority=Severity.medium,
        recommendation="Review the highest-impact secure score controls.",
        remediation_text="Use Defender for Cloud recommendations to remediate the highest value controls.",
        remediation_command_text=None,
        source_system="azure",
        source_api="defender",
        evidence_id="ev-1",
        confidence=Confidence.high,
        data_quality_notes=[],
    )


def build_sample_assessment() -> AssessmentResult:
    finding = build_sample_finding()
    recommendation = build_sample_recommendation()
    metadata = AssessmentRunMetadata(
        run_id="run-1",
        tenant_id="tenant-1",
        tenant_name="Contoso",
        subscription_ids=["sub-1"],
        subscription_names=["Primary"],
        domains=[SecurityDomain.security_overview, SecurityDomain.security_recommendations_register],
        strict_validation=True,
        started_at_utc=datetime.now(UTC),
        completed_at_utc=datetime.now(UTC),
        finding_count=1,
        recommendation_count=1,
        partial_failure_count=0,
        grounded=True,
    )
    summary = AssessmentSummary(
        run_id="run-1",
        tenant_id="tenant-1",
        tenant_name="Contoso",
        subscription_ids=["sub-1"],
        subscription_names=["Primary"],
        domains=[SecurityDomain.security_overview, SecurityDomain.security_recommendations_register],
        total_findings=1,
        total_recommendations=1,
        partial_failure_count=0,
        strict_validation=True,
        grounded=True,
        observed_at_utc=datetime.now(UTC),
        completed_at_utc=datetime.now(UTC),
        findings_by_domain={SecurityDomain.security_overview.value: 1},
        findings_by_severity={Severity.medium.value: 1},
    )
    return AssessmentResult(metadata=metadata, summary=summary, findings=[finding], recommendations=[recommendation], partial_failures=[])


def build_session(latest_assessment: AssessmentResult | None = None) -> SessionState:
    return SessionState(
        session_id="session-1",
        principal=SessionPrincipal(
            auth_mode=AuthMode.cli,
            tenant_id="tenant-1",
            subscription_ids=["sub-1"],
            access_token="token",
            expires_on_utc=datetime.now(UTC) + timedelta(hours=1),
            token_claims={"tid": "tenant-1"},
        ),
        selected_tenant_id="tenant-1",
        selected_subscription_ids=["sub-1"],
        latest_assessment=latest_assessment,
        created_at_utc=datetime.now(UTC),
        updated_at_utc=datetime.now(UTC),
    )