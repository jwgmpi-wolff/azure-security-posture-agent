from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.enrichment import resource_group_from_resource_id
from app.services.evidence import build_finding, partial_failure


async def collect_azure_policy_and_compliance(
    *,
    client: AzureReadOnlyClient,
    run_id: str,
    tenant_id: str,
    tenant_name: str | None,
    subscriptions: list[Subscription],
) -> tuple[list[Finding], list[PartialFailure]]:
    findings: list[Finding] = []
    failures: list[PartialFailure] = []
    for subscription in subscriptions:
        try:
            response = await client.get_policy_states(subscription.subscription_id)
            for row in response.payload.get("value", []):
                resource_id = row.get("resourceId") or f"/subscriptions/{subscription.subscription_id}"
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.azure_policy_and_compliance,
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Azure Policy non-compliance observed",
                        description="Policy Insights returned a non-compliant resource record for the selected subscription.",
                        affected_resource_id=resource_id,
                        affected_resource_name=(resource_id.split("/")[-1] if resource_id else subscription.subscription_id),
                        affected_resource_type=row.get("resourceType"),
                        resource_group=resource_group_from_resource_id(resource_id),
                        region=row.get("resourceLocation"),
                        source_api=response.source_api,
                        response=response,
                        recommendation=f"Review policy assignment {row.get('policyAssignmentName') or 'Not returned by source API'} and remediate the non-compliant configuration outside this service.",
                        remediation_text="Use the Azure Policy compliance view to inspect the assignment, scope, and resource state, then remediate in the owning workload pipeline.",
                        remediation_command_text=None,
                        evidence_details={
                            "policyAssignmentName": row.get("policyAssignmentName"),
                            "policyDefinitionName": row.get("policyDefinitionName"),
                            "complianceState": row.get("complianceState"),
                        },
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.azure_policy_and_compliance,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Microsoft.PolicyInsights read access on the selected subscription and rerun the assessment.",
                )
            )
    return findings, failures