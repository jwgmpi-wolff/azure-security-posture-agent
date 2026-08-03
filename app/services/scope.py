from __future__ import annotations

from app.models import SessionState, Subscription, Tenant
from app.services.subscription_discovery import list_subscriptions, validate_selected_subscriptions
from app.services.tenant_discovery import list_tenants


async def get_tenants(session: SessionState) -> tuple[list[Tenant], str]:
    return await list_tenants(session)


async def get_subscriptions(session: SessionState, tenant_id: str) -> tuple[list[Subscription], str]:
    return await list_subscriptions(session, tenant_id)


async def validate_scope(session: SessionState, tenant_id: str, subscription_ids: list[str]) -> list[Subscription]:
    return await validate_selected_subscriptions(session, tenant_id, subscription_ids)
