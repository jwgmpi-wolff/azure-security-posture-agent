from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.enrichment import resource_group_from_resource_id
from app.services.evidence import build_finding, partial_failure
from app.services.resource_graph import query_resource_graph, rows_from_arg


DIAGNOSTIC_QUERY = """
resources
| where type =~ 'microsoft.insights/diagnosticsettings'
| extend logs=tostring(properties.logs), metrics=tostring(properties.metrics), workspaceId=tostring(properties.workspaceId)
| where isempty(workspaceId)
| project id, name, type, location, logs, metrics, workspaceId
"""


async def collect_logging_monitoring_and_evidence_retention(
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
            activity = await client.get_activity_logs(subscription.subscription_id)
            if not activity.payload.get("value"):
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.logging_monitoring_and_evidence_retention,
                        severity=Severity.low,
                        confidence=Confidence.medium,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="No recent activity log records returned",
                        description="The management activity log query returned no records in the recent lookback window.",
                        affected_resource_id=f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=subscription.subscription_name,
                        affected_resource_type="microsoft.insights/eventtypes/management",
                        source_api=activity.source_api,
                        response=activity,
                        recommendation="Confirm activity log retention, export, and read access if no recent records were expected.",
                        remediation_text="Validate activity log retention configuration and ensure monitoring readers can access the management log stream.",
                        evidence_details={"recordCount": 0},
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
            response = await query_resource_graph(client, [subscription.subscription_id], DIAGNOSTIC_QUERY)
            for row in rows_from_arg(response):
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.logging_monitoring_and_evidence_retention,
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Diagnostic setting without Log Analytics workspace observed",
                        description="A diagnostic setting record was returned without a workspace target, which can weaken evidence retention and investigation coverage.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=row.get("name"),
                        affected_resource_type=row.get("type"),
                        resource_group=resource_group_from_resource_id(row.get("id")),
                        region=row.get("location"),
                        source_api=response.source_api,
                        response=response,
                        recommendation="Review diagnostic routing so required logs and metrics are retained in an approved evidence store.",
                        remediation_text="Configure diagnostic settings to send the required categories to Log Analytics, archive storage, or another approved evidence retention target.",
                        evidence_details={"workspaceId": row.get("workspaceId"), "logs": row.get("logs"), "metrics": row.get("metrics")},
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.logging_monitoring_and_evidence_retention,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Monitor and Resource Graph read permissions for activity logs and diagnostic settings.",
                )
            )
    return findings, failures