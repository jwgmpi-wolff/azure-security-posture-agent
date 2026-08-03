from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureReadOnlyClient
from app.services.azure_policy import collect_azure_policy_and_compliance
from app.services.azure_rbac import collect_subscription_governance
from app.services.compute_security import collect_aks_and_container_security, collect_compute_and_vm_security
from app.services.defender_for_cloud import collect_defender_for_cloud_posture, collect_security_overview
from app.services.evidence import build_finding
from app.services.identity_security import collect_identity_and_access_posture
from app.services.key_vault_security import collect_key_vault_security
from app.services.monitor_logging import collect_logging_monitoring_and_evidence_retention
from app.services.network_security import collect_network_security
from app.services.recommendations import build_recommendations_register
from app.services.storage_security import collect_storage_security


CollectorHandler = Callable[..., Awaitable[tuple[list[Finding], list[PartialFailure]]]]


COLLECTORS: dict[SecurityDomain, CollectorHandler] = {
    SecurityDomain.security_overview: collect_security_overview,
    SecurityDomain.defender_for_cloud_posture: collect_defender_for_cloud_posture,
    SecurityDomain.azure_policy_and_compliance: collect_azure_policy_and_compliance,
    SecurityDomain.identity_and_access_posture: collect_identity_and_access_posture,
    SecurityDomain.management_group_and_subscription_governance: collect_subscription_governance,
    SecurityDomain.network_security: collect_network_security,
    SecurityDomain.storage_security: collect_storage_security,
    SecurityDomain.key_vault_security: collect_key_vault_security,
    SecurityDomain.compute_and_vm_security: collect_compute_and_vm_security,
    SecurityDomain.aks_and_container_security: collect_aks_and_container_security,
    SecurityDomain.logging_monitoring_and_evidence_retention: collect_logging_monitoring_and_evidence_retention,
}


async def collect_domains(
    *,
    client: AzureReadOnlyClient,
    run_id: str,
    tenant_id: str,
    tenant_name: str | None,
    subscriptions: list[Subscription],
    requested_domains: list[SecurityDomain],
) -> tuple[list[Finding], list[PartialFailure]]:
    domains = requested_domains or list(SecurityDomain)
    requested_live_domains = [domain for domain in domains if domain != SecurityDomain.security_recommendations_register]
    all_findings: list[Finding] = []
    all_failures: list[PartialFailure] = []

    for domain in requested_live_domains:
        collector = COLLECTORS[domain]
        findings, failures = await collector(
            client=client,
            run_id=run_id,
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            subscriptions=subscriptions,
        )
        all_findings.extend(findings)
        all_failures.extend(failures)

    if SecurityDomain.security_recommendations_register in domains:
        recommendations = build_recommendations_register(all_findings)
        for item in recommendations:
            source_finding = next((finding for finding in all_findings if finding.finding_id == item.finding_id), None)
            if source_finding is None:
                continue
            all_findings.append(
                build_finding(
                    run_id=run_id,
                    domain=SecurityDomain.security_recommendations_register,
                    severity=item.priority,
                    confidence=source_finding.confidence,
                    tenant_id=source_finding.tenant_id,
                    subscription_id=source_finding.subscription_id,
                    title=f"Recommendation register entry: {item.title}",
                    description=source_finding.recommendation,
                    affected_resource_id=source_finding.affected_resource_id,
                    affected_resource_name=source_finding.affected_resource_name,
                    affected_resource_type=source_finding.affected_resource_type,
                    resource_group=source_finding.resource_group,
                    region=source_finding.region,
                    source_api=source_finding.source_api,
                    response=client.query_log[-1],
                    recommendation=source_finding.recommendation,
                    remediation_text=source_finding.remediation_text,
                    remediation_command_text=source_finding.remediation_command_text,
                    evidence_details={"recommendationId": item.recommendation_id, "sourceFindingId": item.finding_id},
                    tenant_name=source_finding.tenant_name,
                    subscription_name=source_finding.subscription_name,
                    data_quality_notes=["Derived from grounded live findings and emitted as a recommendation register wrapper."],
                )
            )
    return all_findings, all_failures
