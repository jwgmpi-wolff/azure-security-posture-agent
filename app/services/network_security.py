from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.enrichment import resource_group_from_resource_id
from app.services.evidence import build_finding, partial_failure
from app.services.resource_graph import query_resource_graph, rows_from_arg


NETWORK_QUERY = """
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule=properties.securityRules
| extend direction=tostring(rule.properties.direction), access=tostring(rule.properties.access), source=tostring(rule.properties.sourceAddressPrefix), destinationPort=tostring(rule.properties.destinationPortRange)
| where direction =~ 'Inbound' and access =~ 'Allow' and (source == '*' or source =~ 'Internet') and destinationPort in ('22', '3389', '*')
| project id, name, location, type, source, destinationPort
"""


async def collect_network_security(
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
            response = await query_resource_graph(client, [subscription.subscription_id], NETWORK_QUERY)
            for row in rows_from_arg(response):
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.network_security,
                        severity=Severity.high,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Internet-exposed inbound network rule observed",
                        description="Azure Resource Graph returned an inbound allow rule from any source to a sensitive management port or wildcard destination.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=row.get("name"),
                        affected_resource_type=row.get("type"),
                        resource_group=resource_group_from_resource_id(row.get("id")),
                        region=row.get("location"),
                        source_api=response.source_api,
                        response=response,
                        recommendation="Review the NSG rule and restrict source ranges or destination ports wherever public management access is not required.",
                        remediation_text="Use NSG rule review to remove wildcard Internet access to management ports or place the workload behind a controlled access path.",
                        evidence_details={"source": row.get("source"), "destinationPort": row.get("destinationPort")},
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.network_security,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Microsoft.ResourceGraph/resources/read permission for the selected subscription.",
                )
            )
    return findings, failures