from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.enrichment import resource_group_from_resource_id
from app.services.evidence import build_finding, partial_failure
from app.services.resource_graph import query_resource_graph, rows_from_arg


STORAGE_QUERY = """
resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend publicNetworkAccess=tostring(properties.publicNetworkAccess), minimumTls=tostring(properties.minimumTlsVersion), supportsHttps=tostring(properties.supportsHttpsTrafficOnly)
| where publicNetworkAccess =~ 'Enabled' or supportsHttps != 'true' or minimumTls !in~ ('TLS1_2', 'TLS1_3')
| project id, name, type, location, publicNetworkAccess, minimumTls, supportsHttps
"""


async def collect_storage_security(
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
            response = await query_resource_graph(client, [subscription.subscription_id], STORAGE_QUERY)
            for row in rows_from_arg(response):
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.storage_security,
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Storage account returned insecure transport or network settings",
                        description="Resource Graph returned a storage account with public network access enabled, HTTPS-only disabled, or a weak TLS minimum version.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=row.get("name"),
                        affected_resource_type=row.get("type"),
                        resource_group=resource_group_from_resource_id(row.get("id")),
                        region=row.get("location"),
                        source_api=response.source_api,
                        response=response,
                        recommendation="Review storage account network and transport settings against the organization’s data protection baseline.",
                        remediation_text="Require HTTPS-only, set minimum TLS to 1.2 or higher, and limit public network exposure where possible.",
                        evidence_details={
                            "publicNetworkAccess": row.get("publicNetworkAccess"),
                            "minimumTls": row.get("minimumTls"),
                            "supportsHttps": row.get("supportsHttps"),
                        },
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.storage_security,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Resource Graph read access for storage account metadata.",
                )
            )
    return findings, failures