from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.evidence import build_finding, partial_failure


async def collect_identity_and_access_posture(
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
            response = await client.get_classic_administrators(subscription.subscription_id)
            for row in response.payload.get("value", []):
                properties = row.get("properties", {})
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.identity_and_access_posture,
                        severity=Severity.high,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Classic administrator assignment observed",
                        description="A legacy classic administrator assignment is still present on the subscription.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=properties.get("emailAddress") or subscription.subscription_name,
                        affected_resource_type=row.get("type") or "Microsoft.Authorization/classicAdministrators",
                        source_api=response.source_api,
                        response=response,
                        recommendation="Replace classic administrator access with modern Azure RBAC role assignments where feasible.",
                        remediation_text="Inventory the classic administrator assignment and migrate the identity to an Azure RBAC role with narrower scope.",
                        evidence_details={
                            "emailAddress": properties.get("emailAddress"),
                            "role": properties.get("role"),
                        },
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.identity_and_access_posture,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm classic administrator read access or note that the provider may not return data for the selected scope.",
                )
            )
    return findings, failures