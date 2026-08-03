from __future__ import annotations

from app.models import SessionState, Tenant
from app.services.azure_clients import AzureReadOnlyClient


async def list_tenants(session: SessionState) -> tuple[list[Tenant], str]:
    client = AzureReadOnlyClient(session.principal.access_token)
    response = await client.list_tenants()
    tenants = [
        Tenant(
            tenant_id=item.get("tenantId") or item.get("id") or "",
            tenant_name=item.get("displayName") or item.get("tenantId"),
            default_domain=item.get("defaultDomain"),
            source_system="azure",
            source_api=response.source_api,
        )
        for item in response.payload.get("value", [])
        if item.get("tenantId") or item.get("id")
    ]
    return tenants, response.endpoint