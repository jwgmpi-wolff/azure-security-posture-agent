from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.evidence import build_finding, partial_failure


async def collect_subscription_governance(
    *,
    client: AzureReadOnlyClient,
    run_id: str,
    tenant_id: str,
    tenant_name: str | None,
    subscriptions: list[Subscription],
) -> tuple[list[Finding], list[PartialFailure]]:
    findings: list[Finding] = []
    failures: list[PartialFailure] = []
    try:
        management_groups = await client.list_management_groups()
        if not management_groups.payload.get("value"):
            findings.append(
                build_finding(
                    run_id=run_id,
                    domain=SecurityDomain.management_group_and_subscription_governance,
                    severity=Severity.low,
                    confidence=Confidence.medium,
                    tenant_id=tenant_id,
                    subscription_id=subscriptions[0].subscription_id if subscriptions else "tenant-scope",
                    title="No management groups returned",
                    description="The management group list call returned no management group hierarchy for the selected tenant.",
                    affected_resource_id=f"/providers/Microsoft.Management/managementGroups/{tenant_id}",
                    affected_resource_name=tenant_name or tenant_id,
                    affected_resource_type="Microsoft.Management/managementGroups",
                    source_api=management_groups.source_api,
                    response=management_groups,
                    recommendation="Confirm whether the tenant intentionally operates without management groups or whether the delegated identity lacks Microsoft.Management read access.",
                    remediation_text="Use Azure Portal or management group APIs to validate governance hierarchy coverage across the target subscriptions.",
                    evidence_details={"managementGroupCount": 0},
                    tenant_name=tenant_name,
                    subscription_name=subscriptions[0].subscription_name if subscriptions else None,
                )
            )
    except AzureApiError as error:
        failures.append(
            partial_failure(
                SecurityDomain.management_group_and_subscription_governance,
                error,
                api_route="/api/assessment/run",
                tenant_id=tenant_id,
                subscription_id=None,
                remediation_guidance="Confirm Microsoft.Management read access for the delegated identity.",
            )
        )

    for subscription in subscriptions:
        try:
            assignments = await client.get_role_assignments(subscription.subscription_id)
            broad_assignments = [row for row in assignments.payload.get("value", []) if row.get("properties", {}).get("scope", "").lower().endswith(subscription.subscription_id.lower())]
            if len(broad_assignments) < 20:
                continue
            findings.append(
                build_finding(
                    run_id=run_id,
                    domain=SecurityDomain.management_group_and_subscription_governance,
                    severity=Severity.medium,
                    confidence=Confidence.medium,
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    title="High volume of subscription-scope role assignments observed",
                    description="Azure RBAC returned a large number of role assignments directly at subscription scope.",
                    affected_resource_id=f"/subscriptions/{subscription.subscription_id}",
                    affected_resource_name=subscription.subscription_name,
                    affected_resource_type="Microsoft.Resources/subscriptions",
                    source_api=assignments.source_api,
                    response=assignments,
                    recommendation="Review subscription-scope assignments for opportunities to move access to narrower scopes or group-based role assignment.",
                    remediation_text="Audit broad role assignments and use least-privilege scoping where operationally feasible.",
                    evidence_details={"subscriptionScopeAssignmentCount": len(broad_assignments)},
                    tenant_name=tenant_name,
                    subscription_name=subscription.subscription_name,
                )
            )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.management_group_and_subscription_governance,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Microsoft.Authorization/roleAssignments/read permission on the subscription.",
                )
            )
    return findings, failures