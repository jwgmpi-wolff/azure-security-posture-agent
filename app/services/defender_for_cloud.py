from __future__ import annotations

from app.models import Confidence, Finding, PartialFailure, SecurityDomain, Severity, Subscription
from app.services.azure_clients import AzureApiError, AzureReadOnlyClient
from app.services.evidence import build_finding, partial_failure


async def collect_security_overview(
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
            score_response = await client.get_secure_scores(subscription.subscription_id)
            for row in score_response.payload.get("value", []):
                properties = row.get("properties", {})
                current_score = float(properties.get("score", {}).get("current", 0) or 0)
                max_score = float(properties.get("score", {}).get("max", 0) or 0)
                if max_score <= 0 or current_score >= max_score:
                    continue
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.security_overview,
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Secure score below maximum",
                        description="Defender for Cloud returned a secure score below the available maximum for the subscription.",
                        affected_resource_id=f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=subscription.subscription_name,
                        affected_resource_type="Microsoft.Security/secureScores",
                        source_api=score_response.source_api,
                        response=score_response,
                        recommendation="Use Defender for Cloud secure score actions to prioritize the highest-impact security controls.",
                        remediation_text="Review secure score recommendations and remediate in the workload’s native control plane.",
                        evidence_details={
                            "currentScore": current_score,
                            "maxScore": max_score,
                        },
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.security_overview,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Defender for Cloud secure score read permissions for the subscription.",
                )
            )
    return findings, failures


async def collect_defender_for_cloud_posture(
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
            pricing_response = await client.get_defender_pricings(subscription.subscription_id)
            for row in pricing_response.payload.get("value", []):
                properties = row.get("properties", {})
                if properties.get("pricingTier") == "Standard":
                    continue
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.defender_for_cloud_posture,
                        severity=Severity.medium,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Defender plan not at Standard tier",
                        description="Defender for Cloud pricing returned a non-Standard plan for a workload surface.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=row.get("name"),
                        affected_resource_type=row.get("type"),
                        source_api=pricing_response.source_api,
                        response=pricing_response,
                        recommendation="Review whether the workload should be covered by the Standard Defender plan based on risk and compliance requirements.",
                        remediation_text="Assess Defender plan coverage and enable the required tier outside this service if approved.",
                        evidence_details={
                            "pricingTier": properties.get("pricingTier"),
                            "subPlan": properties.get("subPlan"),
                        },
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
            assessment_response = await client.get_security_assessments(subscription.subscription_id)
            for row in assessment_response.payload.get("value", []):
                properties = row.get("properties", {})
                status_code = properties.get("status", {}).get("code")
                if status_code != "Unhealthy":
                    continue
                findings.append(
                    build_finding(
                        run_id=run_id,
                        domain=SecurityDomain.defender_for_cloud_posture,
                        severity=Severity.high,
                        confidence=Confidence.high,
                        tenant_id=tenant_id,
                        subscription_id=subscription.subscription_id,
                        title="Unhealthy Defender assessment observed",
                        description="Defender for Cloud returned an unhealthy assessment result for the selected subscription.",
                        affected_resource_id=row.get("id") or f"/subscriptions/{subscription.subscription_id}",
                        affected_resource_name=properties.get("displayName") or row.get("name"),
                        affected_resource_type=row.get("type"),
                        source_api=assessment_response.source_api,
                        response=assessment_response,
                        recommendation="Review the assessment recommendation and remediate the underlying control gap in the owning Azure service.",
                        remediation_text="Open the corresponding Defender assessment and follow the product-specific remediation workflow.",
                        evidence_details={
                            "statusCode": status_code,
                            "displayName": properties.get("displayName"),
                        },
                        tenant_name=tenant_name,
                        subscription_name=subscription.subscription_name,
                    )
                )
        except AzureApiError as error:
            failures.append(
                partial_failure(
                    SecurityDomain.defender_for_cloud_posture,
                    error,
                    api_route="/api/assessment/run",
                    tenant_id=tenant_id,
                    subscription_id=subscription.subscription_id,
                    remediation_guidance="Confirm Microsoft.Security read permissions and Defender for Cloud plan availability on the subscription.",
                )
            )
    return findings, failures