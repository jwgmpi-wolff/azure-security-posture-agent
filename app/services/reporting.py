from __future__ import annotations

import secrets
from collections import Counter
from datetime import UTC, datetime

from app.models import AssessmentRequest, AssessmentResult, AssessmentRunMetadata, AssessmentSummary, SessionState
from app.services.azure_clients import AzureReadOnlyClient
from app.services.collectors import collect_domains
from app.services.enrichment import subscription_name_map, tenant_name
from app.services.recommendations import build_recommendations_register
from app.services.scope import validate_scope
from app.services.tenant_discovery import list_tenants


async def run_assessment(session: SessionState, request: AssessmentRequest) -> AssessmentResult:
    validated_subscriptions = await validate_scope(session, request.tenant_id, request.subscription_ids)
    subscription_ids = [subscription.subscription_id for subscription in validated_subscriptions]
    subscription_names = subscription_name_map(validated_subscriptions)
    tenants, _ = await list_tenants(session)
    resolved_tenant_name = tenant_name(tenants, request.tenant_id)

    started = datetime.now(UTC)
    run_id = secrets.token_hex(12)
    client = AzureReadOnlyClient(session.principal.access_token)
    findings, partial_failures = await collect_domains(
        client=client,
        run_id=run_id,
        tenant_id=request.tenant_id,
        tenant_name=resolved_tenant_name,
        subscriptions=validated_subscriptions,
        requested_domains=request.domains,
    )
    recommendations = build_recommendations_register(findings)
    completed = datetime.now(UTC)

    severity_counter = Counter(finding.severity for finding in findings)
    domain_counter = Counter(finding.domain for finding in findings)

    metadata = AssessmentRunMetadata(
        run_id=run_id,
        tenant_id=request.tenant_id,
        tenant_name=resolved_tenant_name,
        subscription_ids=subscription_ids,
        subscription_names=[subscription_names[item] for item in subscription_ids],
        domains=request.domains or list(domain_counter.keys()),
        strict_validation=request.strict_validation,
        started_at_utc=started,
        completed_at_utc=completed,
        finding_count=len(findings),
        recommendation_count=len(recommendations),
        partial_failure_count=len(partial_failures),
        grounded=request.strict_validation,
    )

    summary = AssessmentSummary(
        run_id=run_id,
        tenant_id=request.tenant_id,
        tenant_name=resolved_tenant_name,
        subscription_ids=subscription_ids,
        subscription_names=[subscription_names[item] for item in subscription_ids],
        domains=request.domains or list(domain_counter.keys()),
        total_findings=len(findings),
        total_recommendations=len(recommendations),
        partial_failure_count=len(partial_failures),
        strict_validation=request.strict_validation,
        grounded=request.strict_validation,
        observed_at_utc=started,
        completed_at_utc=completed,
        findings_by_domain={str(key): value for key, value in domain_counter.items()},
        findings_by_severity={str(key): value for key, value in severity_counter.items()},
    )
    return AssessmentResult(
        metadata=metadata,
        summary=summary,
        findings=findings,
        recommendations=recommendations,
        partial_failures=partial_failures,
    )
