from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def to_camel(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


class CamelModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, alias_generator=to_camel, use_enum_values=True)


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class Confidence(str, Enum):
    high = "High"
    medium = "Medium"
    low = "Low"


class AuthMode(str, Enum):
    cli = "cli"
    browser = "browser"
    delegated = "delegated"


class ErrorCategory(str, Enum):
    auth_required = "AuthRequired"
    tenant_not_selected = "TenantNotSelected"
    subscription_not_selected = "SubscriptionNotSelected"
    permission_denied = "PermissionDenied"
    api_unavailable = "ApiUnavailable"
    resource_graph_query_failed = "ResourceGraphQueryFailed"
    defender_query_failed = "DefenderQueryFailed"
    policy_query_failed = "PolicyQueryFailed"
    graph_enrichment_failed = "GraphEnrichmentFailed"
    export_failed = "ExportFailed"
    validation_failed = "ValidationFailed"
    authentication = "authentication"
    authorization = "authorization"
    validation = "validation"
    configuration = "configuration"
    upstream_api = "upstream_api"
    partial_failure = "partial_failure"
    export = "export"
    persistence = "persistence"
    not_found = "not_found"
    internal = "internal"


class SecurityDomain(str, Enum):
    security_overview = "security_overview"
    defender_for_cloud_posture = "defender_for_cloud_posture"
    azure_policy_and_compliance = "azure_policy_and_compliance"
    identity_and_access_posture = "identity_and_access_posture"
    management_group_and_subscription_governance = "management_group_and_subscription_governance"
    network_security = "network_security"
    storage_security = "storage_security"
    key_vault_security = "key_vault_security"
    compute_and_vm_security = "compute_and_vm_security"
    aks_and_container_security = "aks_and_container_security"
    logging_monitoring_and_evidence_retention = "logging_monitoring_and_evidence_retention"
    security_recommendations_register = "security_recommendations_register"


class Tenant(CamelModel):
    tenant_id: str
    tenant_name: str | None = None
    default_domain: str | None = None
    source_system: str
    source_api: str


class Subscription(CamelModel):
    subscription_id: str
    subscription_name: str | None = None
    tenant_id: str
    state: str
    source_system: str
    source_api: str


class AssessmentRequest(CamelModel):
    tenant_id: str = Field(alias="tenantId")
    subscription_ids: list[str] = Field(default_factory=list, alias="subscriptionIds")
    domains: list[SecurityDomain] = Field(default_factory=list, alias="domains")
    strict_validation: bool = Field(default=True, alias="strictValidation")


class Recommendation(CamelModel):
    recommendation_id: str
    finding_id: str
    title: str
    priority: Severity
    recommendation: str
    remediation_text: str
    remediation_command_text: str | None = None
    source_system: str
    source_api: str
    evidence_id: str
    confidence: Confidence
    data_quality_notes: list[str] = Field(default_factory=list)


class Evidence(CamelModel):
    evidence_id: str
    finding_id: str
    source_system: str
    source_api: str
    observed_at_utc: datetime
    record_type: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    data_quality_notes: list[str] = Field(default_factory=list)


class Finding(CamelModel):
    finding_id: str
    run_id: str
    tenant_id: str
    tenant_name: str | None = None
    subscription_id: str
    subscription_name: str | None = None
    domain: SecurityDomain
    severity: Severity
    title: str
    description: str
    affected_resource_id: str
    affected_resource_name: str | None = None
    affected_resource_type: str | None = None
    resource_group: str | None = None
    region: str | None = None
    source_system: str
    source_api: str
    evidence_id: str
    observed_at_utc: datetime
    recommendation: str
    remediation_text: str
    remediation_command_text: str | None = None
    confidence: Confidence
    data_quality_notes: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    @field_validator(
        "finding_id",
        "run_id",
        "tenant_id",
        "subscription_id",
        "title",
        "description",
        "affected_resource_id",
        "source_system",
        "source_api",
        "evidence_id",
        "recommendation",
        "remediation_text",
    )
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Required fields must be non-empty.")
        return value.strip()

    @model_validator(mode="after")
    def validate_evidence(self) -> Finding:
        if not self.evidence:
            raise ValueError("Every finding requires evidence.")
        if self.evidence_id not in {item.evidence_id for item in self.evidence}:
            raise ValueError("Finding evidenceId must reference one of the embedded evidence items.")
        return self


class PartialFailure(CamelModel):
    category: ErrorCategory = ErrorCategory.partial_failure
    api_route: str
    tenant_id: str
    subscription_id: str | None = None
    domain: SecurityDomain
    source_system: str
    source_api: str
    message: str
    status_code: int | None = None
    retryable: bool = False
    remediation_guidance: str
    observed_at_utc: datetime


class AssessmentSummary(CamelModel):
    run_id: str
    tenant_id: str
    tenant_name: str | None = None
    subscription_ids: list[str] = Field(default_factory=list)
    subscription_names: list[str] = Field(default_factory=list)
    domains: list[SecurityDomain] = Field(default_factory=list)
    total_findings: int
    total_recommendations: int
    partial_failure_count: int
    strict_validation: bool
    grounded: bool
    observed_at_utc: datetime
    completed_at_utc: datetime
    findings_by_domain: dict[str, int] = Field(default_factory=dict)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)


class AssessmentRunMetadata(CamelModel):
    run_id: str
    tenant_id: str
    tenant_name: str | None = None
    subscription_ids: list[str] = Field(default_factory=list)
    subscription_names: list[str] = Field(default_factory=list)
    domains: list[SecurityDomain] = Field(default_factory=list)
    strict_validation: bool
    started_at_utc: datetime
    completed_at_utc: datetime | None = None
    finding_count: int = 0
    recommendation_count: int = 0
    partial_failure_count: int = 0
    grounded: bool = False


class AssessmentResult(CamelModel):
    metadata: AssessmentRunMetadata
    summary: AssessmentSummary
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    partial_failures: list[PartialFailure] = Field(default_factory=list)


class ExportMetadata(CamelModel):
    export_id: str
    run_id: str
    format: str
    file_name: str
    generated_at_utc: datetime
    record_count: int


class ApiErrorDetail(CamelModel):
    category: ErrorCategory
    api_route: str
    message: str
    tenant_id: str | None = None
    subscription_id: str | None = None
    source_system: str | None = None
    source_api: str | None = None
    remediation_guidance: str | None = None
    status_code: int | None = None
    run_id: str | None = None


class ApiErrorResponse(CamelModel):
    error: ApiErrorDetail


class SessionPrincipal(CamelModel):
    auth_mode: AuthMode
    tenant_id: str
    subscription_ids: list[str] = Field(default_factory=list)
    access_token: str
    expires_on_utc: datetime
    user_object_id: str | None = None
    username: str | None = None
    audience: str | None = None
    issuer: str | None = None
    token_claims: dict[str, Any] = Field(default_factory=dict)


class SessionState(CamelModel):
    session_id: str
    principal: SessionPrincipal
    selected_tenant_id: str
    selected_subscription_ids: list[str] = Field(default_factory=list)
    latest_assessment: AssessmentResult | None = None
    created_at_utc: datetime
    updated_at_utc: datetime


class HealthResponse(CamelModel):
    status: str
    version: str
    build: str
    auth_mode: str


class AuthContextResponse(CamelModel):
    authenticated: bool
    auth_mode: str | None = None
    tenant_id: str | None = None
    subscription_ids: list[str] = Field(default_factory=list)
    expires_on_utc: datetime | None = None


class CopilotAuthContextResponse(CamelModel):
    authenticated: bool
    token_tenant_id: str
    selected_tenant_id: str
    subscription_ids: list[str] = Field(default_factory=list)
    available_tenants: list[Tenant] = Field(default_factory=list)
    available_subscriptions: list[Subscription] = Field(default_factory=list)
    source_endpoints: list[str] = Field(default_factory=list)
    authentication_guidance: str | None = None


class RootResponse(CamelModel):
    service: str
    version: str
    status: str


class TenantSelectionRequest(CamelModel):
    tenant_id: str = Field(alias="tenantId")


class ScopeSelection(CamelModel):
    tenant_id: str = Field(alias="tenantId")
    subscription_ids: list[str] = Field(default_factory=list, alias="subscriptionIds")


class BrowserStartResponse(CamelModel):
    authorization_url: str
    state: str


class CliLoginRequest(CamelModel):
    tenant_id: str = Field(alias="tenantId")
    subscription_ids: list[str] = Field(default_factory=list, alias="subscriptionIds")


class CopilotSessionRequest(CamelModel):
    tenant_id: str = Field(alias="tenantId")
    subscription_ids: list[str] = Field(default_factory=list, alias="subscriptionIds")


class ExportFormat(str, Enum):
    csv = "csv"
    pdf = "pdf"
    pptx = "pptx"
    sqlite = "sqlite"
