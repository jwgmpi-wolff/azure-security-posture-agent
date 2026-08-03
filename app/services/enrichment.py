from __future__ import annotations

from typing import Iterable

from app.models import Finding, Subscription, Tenant


def subscription_name_map(subscriptions: Iterable[Subscription]) -> dict[str, str]:
    return {subscription.subscription_id: subscription.subscription_name or subscription.subscription_id for subscription in subscriptions}


def tenant_name(tenants: Iterable[Tenant], tenant_id: str) -> str | None:
    for tenant in tenants:
        if tenant.tenant_id == tenant_id:
            return tenant.tenant_name
    return None


def resource_group_from_resource_id(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    parts = resource_id.split("/")
    if "resourceGroups" not in parts:
        return None
    index = parts.index("resourceGroups")
    return parts[index + 1] if index + 1 < len(parts) else None


def add_data_quality_note(finding: Finding, note: str) -> Finding:
    notes = list(finding.data_quality_notes)
    if note not in notes:
        notes.append(note)
        finding.data_quality_notes = notes
    return finding