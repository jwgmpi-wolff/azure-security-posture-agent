from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.enrichment import resource_group_from_resource_id
from app.services.evidence import build_finding, partial_failure
from app.services.resource_graph import query_resource_graph, rows_from_arg


COMPUTE_QUERY = """
resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend encryptionAtHost=tostring(properties.securityProfile.encryptionAtHost), identityType=tostring(identity.type)
| where encryptionAtHost != 'true' or isempty(identityType)
| project id, name, type, location, encryptionAtHost, identityType
"""

AKS_QUERY = """
resources
| where type =~ 'microsoft.containerservice/managedclusters'
| extend privateCluster=tostring(properties.apiServerAccessProfile.enablePrivateCluster), aadManaged=tostring(properties.aadProfile.managed)
| where privateCluster != 'true' or aadManaged != 'true'
| project id, name, type, location, privateCluster, aadManaged
"""


async def collect_compute_and_vm_security(
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
            response = await query_resource_graph(client, [subscription.subscription_id], COMPUTE_QUERY)
            for row in rows_from_arg(response):
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.compute_and_vm_security,
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Virtual machine returned reviewable security settings",
                        description="Resource Graph returned a VM without encryption at host enabled or without a managed identity assigned.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=row.get("name"),
                        affected_resource_type=row.get("type"),
                        resource_group=resource_group_from_resource_id(row.get("id")),
                        region=row.get("location"),
                        source_api=response.source_api,
                        response=response,
                        recommendation="Review host encryption and managed identity posture for the VM against the compute security baseline.",
                        remediation_text="Enable encryption at host where supported and assign a managed identity if the workload requires Azure resource access.",
                        evidence_details={"encryptionAtHost": row.get("encryptionAtHost"), "identityType": row.get("identityType")},
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.compute_and_vm_security,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Resource Graph read access for Microsoft.Compute resource metadata.",
                )
            )
    return findings, failures


async def collect_aks_and_container_security(
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
            response = await query_resource_graph(client, [subscription.subscription_id], AKS_QUERY)
            for row in rows_from_arg(response):
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.aks_and_container_security,
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="AKS cluster returned reviewable control-plane settings",
                        description="Resource Graph returned an AKS cluster without private API server enabled or without managed AAD integration enabled.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=row.get("name"),
                        affected_resource_type=row.get("type"),
                        resource_group=resource_group_from_resource_id(row.get("id")),
                        region=row.get("location"),
                        source_api=response.source_api,
                        response=response,
                        recommendation="Review AKS private cluster and Entra integration settings against the container platform baseline.",
                        remediation_text="Enable private API server access and managed Entra integration if required by the platform security standard.",
                        evidence_details={"privateCluster": row.get("privateCluster"), "aadManaged": row.get("aadManaged")},
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.aks_and_container_security,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Resource Graph read access for Microsoft.ContainerService resources.",
                )
            )
    return findings, failures