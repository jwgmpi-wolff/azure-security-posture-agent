from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.enrichment import resource_group_from_resource_id
from app.services.evidence import build_finding, partial_failure


async def collect_key_vault_security(
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
            response = await client.list_key_vaults(subscription.subscription_id)
            for row in response.payload.get("value", []):
                properties = row.get("properties", {})
                if properties.get("enablePurgeProtection") is True and properties.get("publicNetworkAccess") != "Enabled":
                    continue
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.key_vault_security,
                        severity=Severity.high,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Key Vault returned reviewable protection settings",
                        description="The Key Vault metadata indicates missing purge protection or public network access exposure.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=row.get("name"),
                        affected_resource_type=row.get("type"),
                        resource_group=resource_group_from_resource_id(row.get("id")),
                        region=row.get("location"),
                        source_api=response.source_api,
                        response=response,
                        recommendation="Review Key Vault purge protection, RBAC authorization mode, and public network access settings.",
                        remediation_text="Enable purge protection where policy requires it and reduce public network exposure when Private Link or firewall controls are available.",
                        evidence_details={
                            "enablePurgeProtection": properties.get("enablePurgeProtection"),
                            "publicNetworkAccess": properties.get("publicNetworkAccess"),
                            "enableRbacAuthorization": properties.get("enableRbacAuthorization"),
                        },
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.key_vault_security,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Key Vault metadata read access for the selected subscription.",
                )
            )
    return findings, failures