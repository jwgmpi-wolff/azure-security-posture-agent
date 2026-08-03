from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.auth import (
    clear_session_cookie,
    create_session,
    delete_session,
    get_session,
    pop_pkce_state,
    register_pkce_state,
    require_session,
    safe_auth_context,
    set_session_cookie,
)
from app.config import settings
from app.logging_config import configure_logging
from app.models import (
    ApiErrorDetail,
    ApiErrorResponse,
    AssessmentRequest,
    AssessmentResult,
    AssessmentSummary,
    AuthContextResponse,
    BrowserStartResponse,
    CliLoginRequest,
    CopilotAuthContextResponse,
    CopilotSessionRequest,
    ErrorCategory,
    ExportFormat,
    HealthResponse,
    ScopeSelection,
    SecurityDomain,
    SessionState,
    TenantSelectionRequest,
)
from app.services.azure_auth import (
    acquire_cli_principal,
    acquire_copilot_principal,
    build_authorization_url,
    exchange_browser_code,
    parse_bearer_token,
)
from app.services.exporters import export_assessment
from app.services.reporting import run_assessment as run_live_assessment
from app.services.scope import get_subscriptions, get_tenants, validate_scope


configure_logging()
app = FastAPI(title=settings.app_name)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


def classify_status(status_code: int) -> ErrorCategory:
    if status_code == 401:
        return ErrorCategory.auth_required
    if status_code == 403:
        return ErrorCategory.permission_denied
    if status_code == 404:
        return ErrorCategory.not_found
    if status_code == 422:
        return ErrorCategory.validation_failed
    if status_code >= 500:
        return ErrorCategory.api_unavailable
    return ErrorCategory.validation_failed


def build_error_response(
    *,
    request: Request,
    status_code: int,
    message: str,
    category: ErrorCategory | None = None,
    tenant_id: str | None = None,
    subscription_id: str | None = None,
    source_system: str | None = None,
    source_api: str | None = None,
    remediation_guidance: str | None = None,
    run_id: str | None = None,
) -> JSONResponse:
    payload = ApiErrorResponse(
        error=ApiErrorDetail(
            category=category or classify_status(status_code),
            api_route=request.url.path,
            message=message,
            tenant_id=tenant_id,
            subscription_id=subscription_id,
            source_system=source_system,
            source_api=source_api,
            remediation_guidance=remediation_guidance,
            status_code=status_code,
            run_id=run_id,
        )
    )
    return JSONResponse(status_code=status_code, content=payload.model_dump(by_alias=True, mode="json"))


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
    return build_error_response(request=request, status_code=exc.status_code, message=detail)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return build_error_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        message="Unhandled server error.",
        category=ErrorCategory.internal,
        remediation_guidance="Inspect server logs for the failing request and correct the local implementation defect before retrying.",
    )


def _get_optional_session(request: Request) -> SessionState | None:
    try:
        return get_session(request)
    except HTTPException:
        return None


def _copilot_token_tenant(authorization: str | None) -> tuple[str, str]:
    bearer = parse_bearer_token(authorization or "")
    from app.auth import decode_jwt_payload_unsafe

    token_tenant = str(decode_jwt_payload_unsafe(bearer).get("tid") or "")
    if not token_tenant:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bearer token does not contain a tenant claim.")
    return bearer, token_tenant


def _require_copilot_tenant(token_tenant: str, requested_tenant: str) -> None:
    if token_tenant != requested_tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"The Copilot OAuth token was issued for tenant {token_tenant}, not requested tenant {requested_tenant}. "
                "Reconnect the Azure Security Posture Agent OAuth connection while signed in to the requested tenant, then retry."
            ),
        )


async def _resolve_session_for_read(
    *,
    request: Request,
    authorization: str | None,
    tenant_id: str | None,
    subscription_ids: list[str] | None,
) -> SessionState:
    existing = _get_optional_session(request)
    if authorization:
        bearer, token_tenant = _copilot_token_tenant(authorization)
        selected_tenant = tenant_id or token_tenant
        _require_copilot_tenant(token_tenant, selected_tenant)
        principal = await acquire_copilot_principal(selected_tenant, bearer)
        session = SessionState(
            session_id=secrets.token_urlsafe(16),
            principal=principal,
            selected_tenant_id=selected_tenant,
            selected_subscription_ids=[],
            latest_assessment=None,
            created_at_utc=datetime.now(UTC),
            updated_at_utc=datetime.now(UTC),
        )
        validated = await validate_scope(session, selected_tenant, subscription_ids or [])
        session.selected_subscription_ids = [item.subscription_id for item in validated]
        return session
    if existing is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    return existing


async def _ensure_latest_assessment(
    *,
    request: Request,
    authorization: str | None,
    tenant_id: str,
    subscription_ids: list[str],
    domains: list[SecurityDomain] | None = None,
    strict_validation: bool = True,
) -> AssessmentResult:
    session = await _resolve_session_for_read(
        request=request,
        authorization=authorization,
        tenant_id=tenant_id,
        subscription_ids=subscription_ids,
    )
    selected_subscription_ids = session.selected_subscription_ids or subscription_ids
    latest = session.latest_assessment
    if latest and latest.metadata.tenant_id == tenant_id and set(latest.metadata.subscription_ids) == set(selected_subscription_ids or latest.metadata.subscription_ids):
        return latest
    assessment = await run_live_assessment(
        session,
        AssessmentRequest(
            tenantId=tenant_id,
            subscriptionIds=selected_subscription_ids,
            domains=domains or [],
            strictValidation=strict_validation,
        ),
    )
    persisted_session = _get_optional_session(request)
    if persisted_session is not None and persisted_session.session_id == session.session_id:
        from app.auth import save_session

        session.latest_assessment = assessment
        save_session(session)
    return assessment


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return Path("app/static/index.html").read_text(encoding="utf-8")


@app.get("/manifest.json")
async def manifest_template() -> Response:
    return Response(Path("m365-agent/manifest.template.json").read_text(encoding="utf-8"), media_type="application/json")


@app.get("/declarativeAgent.json")
async def declarative_agent_template() -> Response:
    return Response(Path("m365-agent/declarativeAgent.template.json").read_text(encoding="utf-8"), media_type="application/json")


@app.get("/apiPlugin.json")
async def api_plugin_template() -> Response:
    return Response(Path("m365-agent/apiPlugin.template.json").read_text(encoding="utf-8"), media_type="application/json")


@app.get("/openapi.yaml")
async def plugin_openapi_template() -> Response:
    return Response(Path("m365-agent/openapi.template.yaml").read_text(encoding="utf-8"), media_type="application/yaml")


@app.get("/color.png")
async def plugin_color_icon() -> FileResponse:
    return FileResponse("m365-agent/color.png", media_type="image/png")


@app.get("/outline.png")
async def plugin_outline_icon() -> FileResponse:
    return FileResponse("m365-agent/outline.png", media_type="image/png")


@app.get("/api/health", response_model=HealthResponse)
async def health_check(request: Request) -> HealthResponse:
    session = _get_optional_session(request)
    return HealthResponse(status="ok", version=settings.app_version, build=settings.build_id, auth_mode=session.principal.auth_mode.value if session else "unauthenticated")


@app.get("/api/auth/context", response_model=AuthContextResponse)
async def auth_context(request: Request) -> AuthContextResponse:
    return AuthContextResponse(**safe_auth_context(_get_optional_session(request)))


@app.get("/api/auth/session", response_model=AuthContextResponse)
async def auth_session_alias(request: Request) -> AuthContextResponse:
    return await auth_context(request)


@app.get("/api/config")
async def get_config() -> dict[str, object]:
    return {
        "appName": settings.app_name,
        "browserRedirectPath": settings.browser_redirect_path,
        "browserRedirectAllowlist": settings.browser_redirect_allowlist,
        "allowedOrigins": settings.allowed_origins,
        "containerAppName": settings.container_app_name,
    }


@app.get("/api/domains")
async def get_domains() -> list[dict[str, str]]:
    return [{"key": domain.value, "label": domain.value.replace("_", " ").title()} for domain in SecurityDomain]


@app.get("/api/auth/browser/start", response_model=BrowserStartResponse)
async def browser_auth_start(tenant_id: str = Query(..., min_length=1), redirect_uri: str = Query(..., min_length=1)) -> BrowserStartResponse:
    state, challenge = register_pkce_state(tenant_id, redirect_uri)
    return BrowserStartResponse(
        authorization_url=build_authorization_url(tenant_id, redirect_uri, state, challenge),
        state=state,
    )


@app.get("/api/auth/browser/callback")
async def browser_auth_callback(code: str, state: str, response: Response) -> dict[str, str]:
    state_entry = pop_pkce_state(state)
    principal = await exchange_browser_code(code, state_entry["tenant_id"], state_entry["redirect_uri"], state_entry["verifier"])
    session = create_session(
        SessionState(
            session_id=secrets.token_urlsafe(32),
            principal=principal,
            selected_tenant_id=principal.tenant_id,
            selected_subscription_ids=[],
            latest_assessment=None,
            created_at_utc=datetime.now(UTC),
            updated_at_utc=datetime.now(UTC),
        )
    )
    set_session_cookie(response, session.session_id)
    return {"status": "authenticated"}


@app.post("/api/auth/cli/session")
async def cli_auth_session(payload: CliLoginRequest, response: Response) -> dict[str, object]:
    principal = acquire_cli_principal(payload.tenant_id)
    session = create_session(
        SessionState(
            session_id=secrets.token_urlsafe(32),
            principal=principal,
            selected_tenant_id=payload.tenant_id,
            selected_subscription_ids=payload.subscription_ids,
            latest_assessment=None,
            created_at_utc=datetime.now(UTC),
            updated_at_utc=datetime.now(UTC),
        )
    )
    set_session_cookie(response, session.session_id)
    return {"status": "authenticated", "tenantId": payload.tenant_id, "subscriptionIds": payload.subscription_ids}


@app.post("/api/auth/copilot/session")
async def copilot_auth_session(
    payload: CopilotSessionRequest,
    response: Response,
    authorization: str = Header(default=""),
) -> dict[str, object]:
    principal = await acquire_copilot_principal(payload.tenant_id, parse_bearer_token(authorization))
    session = create_session(
        SessionState(
            session_id=secrets.token_urlsafe(32),
            principal=principal,
            selected_tenant_id=payload.tenant_id,
            selected_subscription_ids=payload.subscription_ids,
            latest_assessment=None,
            created_at_utc=datetime.now(UTC),
            updated_at_utc=datetime.now(UTC),
        )
    )
    set_session_cookie(response, session.session_id)
    return {"status": "authenticated", "tenantId": payload.tenant_id, "subscriptionIds": payload.subscription_ids}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response) -> dict[str, str]:
    session = get_session(request)
    delete_session(session.session_id)
    clear_session_cookie(response)
    return {"status": "signed_out"}


@app.get("/api/tenants")
async def list_tenants_route(request: Request) -> dict[str, object]:
    session = require_session(request)
    tenants, endpoint = await get_tenants(session)
    return {
        "items": [tenant.model_dump(by_alias=True, mode="json") for tenant in tenants],
        "sourceEndpoint": endpoint,
    }


@app.post("/api/tenant/select")
async def select_tenant(payload: TenantSelectionRequest, request: Request) -> dict[str, object]:
    session = require_session(request)
    tenants, _ = await get_tenants(session)
    if payload.tenant_id not in {tenant.tenant_id for tenant in tenants}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The authenticated identity does not have access to the selected tenant.")
    session.selected_tenant_id = payload.tenant_id
    session.selected_subscription_ids = []
    from app.auth import save_session

    save_session(session)
    return {"tenantId": session.selected_tenant_id, "subscriptionIds": session.selected_subscription_ids}


@app.get("/api/subscriptions")
async def list_subscriptions_route(request: Request, tenant_id: str | None = Query(default=None, alias="tenantId")) -> dict[str, object]:
    session = require_session(request)
    selected_tenant = tenant_id or session.selected_tenant_id
    subscriptions, endpoint = await get_subscriptions(session, selected_tenant)
    return {
        "items": [subscription.model_dump(by_alias=True, mode="json") for subscription in subscriptions],
        "sourceEndpoint": endpoint,
    }


@app.post("/api/assessment/run")
async def run_assessment(
    payload: AssessmentRequest,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    session = await _resolve_session_for_read(
        request=request,
        authorization=authorization,
        tenant_id=payload.tenant_id,
        subscription_ids=payload.subscription_ids,
    )
    if session.selected_tenant_id != payload.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Assessment tenant must match the authenticated session tenant.")
    validated = await validate_scope(session, payload.tenant_id, payload.subscription_ids)
    session.selected_subscription_ids = [item.subscription_id for item in validated]
    assessment = await run_live_assessment(session, payload)
    persisted_session = _get_optional_session(request)
    if persisted_session is not None and persisted_session.session_id == session.session_id:
        session.latest_assessment = assessment
        from app.auth import save_session

        save_session(session)
    return assessment.model_dump(by_alias=True, mode="json")


@app.post("/api/assessments")
async def run_assessment_alias(
    payload: AssessmentRequest,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    return await run_assessment(payload, request, authorization)


@app.get("/api/assessment/latest")
async def latest_assessment(request: Request) -> dict[str, object]:
    session = require_session(request)
    if not session.latest_assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No assessment has been run in this session.")
    return session.latest_assessment.metadata.model_dump(by_alias=True, mode="json")


@app.get("/api/assessments/latest")
async def latest_assessment_alias(request: Request) -> dict[str, object]:
    session = require_session(request)
    if not session.latest_assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No assessment has been run in this session.")
    return session.latest_assessment.model_dump(by_alias=True, mode="json")


async def _export_response(request: Request, export_format: ExportFormat) -> FileResponse:
    session = require_session(request)
    if not session.latest_assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run an assessment before exporting.")
    output_path = export_assessment(session.latest_assessment, export_format)
    media_type = {
        ExportFormat.csv: "text/csv",
        ExportFormat.pdf: "application/pdf",
        ExportFormat.pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ExportFormat.sqlite: "application/x-sqlite3",
    }[export_format]
    return FileResponse(path=output_path, media_type=media_type, filename=output_path.name)


@app.get("/api/export/csv")
async def export_csv(request: Request) -> FileResponse:
    return await _export_response(request, ExportFormat.csv)


@app.get("/api/export/pdf")
async def export_pdf(request: Request) -> FileResponse:
    return await _export_response(request, ExportFormat.pdf)


@app.get("/api/export/pptx")
async def export_pptx(request: Request) -> FileResponse:
    return await _export_response(request, ExportFormat.pptx)


@app.get("/api/export/sqlite")
async def export_sqlite(request: Request) -> FileResponse:
    return await _export_response(request, ExportFormat.sqlite)


@app.get("/api/exports/{export_format}")
async def export_alias(export_format: ExportFormat, request: Request) -> FileResponse:
    return await _export_response(request, export_format)


@app.get("/api/copilot/assessment-summary", response_model=AssessmentSummary)
async def copilot_assessment_summary(
    request: Request,
    tenant_id: str = Query(..., alias="tenantId"),
    subscription_ids: list[str] = Query(default_factory=list, alias="subscriptionIds"),
    authorization: str | None = Header(default=None),
) -> AssessmentSummary:
    assessment = await _ensure_latest_assessment(
        request=request,
        authorization=authorization,
        tenant_id=tenant_id,
        subscription_ids=subscription_ids,
        domains=[SecurityDomain.security_overview, SecurityDomain.security_recommendations_register],
    )
    return assessment.summary


@app.get("/api/copilot/auth-context", response_model=CopilotAuthContextResponse)
async def copilot_auth_context(authorization: str | None = Header(default=None)) -> CopilotAuthContextResponse:
    bearer, token_tenant = _copilot_token_tenant(authorization)
    principal = await acquire_copilot_principal(token_tenant, bearer)
    session = SessionState(
        session_id=secrets.token_urlsafe(16),
        principal=principal,
        selected_tenant_id=token_tenant,
        selected_subscription_ids=[],
        latest_assessment=None,
        created_at_utc=datetime.now(UTC),
        updated_at_utc=datetime.now(UTC),
    )
    tenants, tenants_endpoint = await get_tenants(session)
    subscriptions, subscriptions_endpoint = await get_subscriptions(session, token_tenant)
    return CopilotAuthContextResponse(
        authenticated=True,
        token_tenant_id=token_tenant,
        selected_tenant_id=token_tenant,
        available_tenants=tenants,
        available_subscriptions=subscriptions,
        source_endpoints=[tenants_endpoint, subscriptions_endpoint],
        authentication_guidance=(
            "Reconnect the plugin OAuth connection in a listed target tenant before setting that tenant's context."
            if any(item.tenant_id != token_tenant for item in tenants)
            else None
        ),
    )


@app.post("/api/copilot/auth-context", response_model=CopilotAuthContextResponse)
async def set_copilot_auth_context(
    payload: ScopeSelection,
    request: Request,
    authorization: str | None = Header(default=None),
) -> CopilotAuthContextResponse:
    session = await _resolve_session_for_read(
        request=request,
        authorization=authorization,
        tenant_id=payload.tenant_id,
        subscription_ids=payload.subscription_ids,
    )
    subscriptions, endpoint = await get_subscriptions(session, payload.tenant_id)
    selected = [item for item in subscriptions if item.subscription_id in set(session.selected_subscription_ids)]
    return CopilotAuthContextResponse(
        authenticated=True,
        token_tenant_id=session.principal.tenant_id,
        selected_tenant_id=payload.tenant_id,
        subscription_ids=session.selected_subscription_ids,
        available_subscriptions=selected,
        source_endpoints=[endpoint],
    )


@app.get("/api/copilot/security-findings")
async def copilot_security_findings(
    request: Request,
    tenant_id: str = Query(..., alias="tenantId"),
    subscription_ids: list[str] = Query(default_factory=list, alias="subscriptionIds"),
    domains: list[SecurityDomain] = Query(default_factory=list, alias="domains"),
    severities: list[str] = Query(default_factory=list, alias="severities"),
    domain: SecurityDomain | None = Query(default=None, alias="domain"),
    severity: str | None = Query(default=None, alias="severity"),
    subscription_id: str | None = Query(default=None, alias="subscriptionId"),
    resource_group: str | None = Query(default=None, alias="resourceGroup"),
    resource_type: str | None = Query(default=None, alias="resourceType"),
    limit: int = Query(default=100, ge=1, le=500),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    assessment = await _ensure_latest_assessment(
        request=request,
        authorization=authorization,
        tenant_id=tenant_id,
        subscription_ids=subscription_ids,
        domains=domains,
    )
    items = assessment.findings
    if domains:
        allowed_domains = {item.value for item in domains}
        items = [finding for finding in items if finding.domain in allowed_domains]
    if severities:
        allowed_severities = set(severities)
        items = [finding for finding in items if finding.severity in allowed_severities]
    if domain:
        items = [finding for finding in items if finding.domain == domain]
    if severity:
        items = [finding for finding in items if finding.severity == severity]
    if subscription_id:
        items = [finding for finding in items if finding.subscription_id == subscription_id]
    if resource_group:
        items = [finding for finding in items if finding.resource_group == resource_group]
    if resource_type:
        items = [finding for finding in items if finding.affected_resource_type == resource_type]
    return {"items": [finding.model_dump(by_alias=True, mode="json") for finding in items[:limit]], "count": len(items)}


@app.get("/api/copilot/recommendations")
async def copilot_recommendations(
    request: Request,
    tenant_id: str = Query(..., alias="tenantId"),
    subscription_ids: list[str] = Query(default_factory=list, alias="subscriptionIds"),
    limit: int = Query(default=100, ge=1, le=500),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    assessment = await _ensure_latest_assessment(
        request=request,
        authorization=authorization,
        tenant_id=tenant_id,
        subscription_ids=subscription_ids,
        domains=[SecurityDomain.security_recommendations_register],
    )
    return {
        "items": [item.model_dump(by_alias=True, mode="json") for item in assessment.recommendations[:limit]],
        "count": len(assessment.recommendations),
    }