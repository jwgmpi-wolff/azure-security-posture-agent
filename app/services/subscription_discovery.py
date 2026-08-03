from __future__ import annotations

from fastapi import HTTPException, status

from app.models import SessionState, Subscription
from app.services.azure_clients import AzureReadOnlyClient


async def list_subscriptions(session: SessionState, tenant_id: str) -> tuple[list[Subscription], str]:
    client = AzureReadOnlyClient(session.principal.access_token)
    response = await client.list_subscriptions()
    subscriptions: list[Subscription] = []
    for item in response.payload.get("value", []):
        if item.get("tenantId") != tenant_id:
            continue
        subscription_id = item.get("subscriptionId") or item.get("id")
        if not subscription_id:
            continue
        subscriptions.append(
            Subscription(
                subscription_id=subscription_id,
                subscription_name=item.get("displayName") or subscription_id,
                tenant_id=tenant_id,
                state=item.get("state") or "Unknown",
                source_system="azure",
                source_api=response.source_api,
            )
        )
    return subscriptions, response.endpoint


async def validate_selected_subscriptions(session: SessionState, tenant_id: str, subscription_ids: list[str]) -> list[Subscription]:
    if session.principal.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authenticated tenant does not match the selected tenant.")

    available_subscriptions, _ = await list_subscriptions(session, tenant_id)
    if not subscription_ids:
        return available_subscriptions

    by_id = {item.subscription_id: item for item in available_subscriptions}
    missing = [subscription_id for subscription_id in subscription_ids if subscription_id not in by_id]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"The authenticated identity does not have access to subscriptions: {', '.join(missing)}",
        )
    return [by_id[subscription_id] for subscription_id in subscription_ids]