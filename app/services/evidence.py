from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from app.models import Confidence, ErrorCategory, Evidence, Finding, PartialFailure, Recommendation, SecurityDomain, Severity
from app.services.azure_clients import AzureApiError, AzureApiResponse


def stable_identifier(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:20]


def normalize_text(value: Any) -> str:
    if value is None or value == "":
        return "Not returned by source API"
    return str(value)


def build_evidence(
    *,
    run_id: str,
    finding_id: str,
    response: AzureApiResponse,
    record_type: str,
    summary: str,
    details: dict[str, Any],
    data_quality_notes: list[str] | None = None,
) -> Evidence:
    evidence_id = f"ev-{stable_identifier(run_id, finding_id, response.source_api, record_type, summary)}"
    return Evidence(
        evidence_id=evidence_id,
        finding_id=finding_id,
        source_system="azure",
        source_api=response.source_api,
        observed_at_utc=response.executed_at_utc,
        record_type=record_type,
        summary=summary,
        details={
            **details,
            "endpoint": response.endpoint,
            "query": response.query,
            "apiVersion": response.api_version,
            "statusCode": response.status_code,
            "durationMs": response.duration_ms,
        },
        data_quality_notes=data_quality_notes or [],
    )


def build_finding(
    *,
    run_id: str,
    domain: SecurityDomain,
    severity: Severity,
    confidence: Confidence,
    tenant_id: str,
    subscription_id: str,
    title: str,
    description: str,
    affected_resource_id: str,
    source_api: str,
    response: AzureApiResponse,
    recommendation: str,
    remediation_text: str,
    evidence_details: dict[str, Any],
    tenant_name: str | None = None,
    subscription_name: str | None = None,
    affected_resource_name: str | None = None,
    affected_resource_type: str | None = None,
    resource_group: str | None = None,
    region: str | None = None,
    remediation_command_text: str | None = None,
    data_quality_notes: list[str] | None = None,
) -> Finding:
    resource_key = affected_resource_id or title
    finding_id = f"fd-{stable_identifier(run_id, domain.value, resource_key, title)}"
    evidence = build_evidence(
        run_id=run_id,
        finding_id=finding_id,
        response=response,
        record_type=domain.value,
        summary=title,
        details=evidence_details,
        data_quality_notes=data_quality_notes,
    )
    return Finding(
        finding_id=finding_id,
        run_id=run_id,
        tenant_id=tenant_id,
        tenant_name=tenant_name,
        subscription_id=subscription_id,
        subscription_name=subscription_name,
        domain=domain,
        severity=severity,
        title=title,
        description=description,
        affected_resource_id=affected_resource_id,
        affected_resource_name=affected_resource_name,
        affected_resource_type=affected_resource_type,
        resource_group=resource_group,
        region=region,
        source_system="azure",
        source_api=source_api,
        evidence_id=evidence.evidence_id,
        observed_at_utc=datetime.now(UTC),
        recommendation=recommendation,
        remediation_text=remediation_text,
        remediation_command_text=remediation_command_text,
        confidence=confidence,
        data_quality_notes=data_quality_notes or [],
        evidence=[evidence],
    )


def build_recommendation(*, finding: Finding, priority: Severity | None = None) -> Recommendation:
    return Recommendation(
        recommendation_id=f"rc-{stable_identifier(finding.run_id, finding.finding_id, finding.title)}",
        finding_id=finding.finding_id,
        title=finding.title,
        priority=priority or finding.severity,
        recommendation=finding.recommendation,
        remediation_text=finding.remediation_text,
        remediation_command_text=finding.remediation_command_text,
        source_system=finding.source_system,
        source_api=finding.source_api,
        evidence_id=finding.evidence_id,
        confidence=finding.confidence,
        data_quality_notes=list(finding.data_quality_notes),
    )


def partial_failure(
    domain: SecurityDomain,
    error: AzureApiError,
    *,
    api_route: str,
    tenant_id: str,
    subscription_id: str | None,
    remediation_guidance: str,
) -> PartialFailure:
    return PartialFailure(
        category=ErrorCategory.partial_failure,
        api_route=api_route,
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        domain=domain,
        source_system="azure",
        source_api=error.source_api,
        message=error.message,
        status_code=error.status_code,
        retryable=error.retryable,
        remediation_guidance=remediation_guidance,
        observed_at_utc=datetime.now(UTC),
    )
