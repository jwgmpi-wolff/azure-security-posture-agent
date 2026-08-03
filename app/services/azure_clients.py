from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.config import settings


ARM_BASE_URL = "https://management.azure.com"
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


class AzureApiError(RuntimeError):
    def __init__(
        self,
        *,
        source_api: str,
        endpoint: str,
        message: str,
        status_code: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.source_api = source_api
        self.endpoint = endpoint
        self.message = message
        self.status_code = status_code
        self.retryable = retryable


@dataclass(slots=True)
class AzureApiResponse:
    source_api: str
    endpoint: str
    api_version: str | None
    executed_at_utc: datetime
    duration_ms: int
    status_code: int | None
    payload: dict[str, Any]
    query: str | None = None


class AzureReadOnlyClient:
    def __init__(self, access_token: str) -> None:
        self._access_token = access_token
        self.query_log: list[AzureApiResponse] = []
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": settings.user_agent,
        }

    async def _request_json(
        self,
        *,
        method: str,
        url: str,
        source_api: str,
        api_version: str | None = None,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        query: str | None = None,
    ) -> AzureApiResponse:
        if method.upper() not in {"GET", "POST"}:
            raise ValueError("AzureReadOnlyClient only permits read-only GET and POST queries.")

        started = time.perf_counter()
        async with httpx.AsyncClient(timeout=60.0, headers=self._headers) as client:
            response = await client.request(method=method.upper(), url=url, params=params, json=json_body)
        duration_ms = int((time.perf_counter() - started) * 1000)

        if response.status_code >= 400:
            raise AzureApiError(
                source_api=source_api,
                endpoint=url,
                message=response.text,
                status_code=response.status_code,
                retryable=response.status_code >= 500,
            )

        payload = response.json() if response.content else {}
        api_response = AzureApiResponse(
            source_api=source_api,
            endpoint=url,
            api_version=api_version,
            executed_at_utc=datetime.now(UTC),
            duration_ms=duration_ms,
            status_code=response.status_code,
            payload=payload,
            query=query,
        )
        self.query_log.append(api_response)
        return api_response

    async def list_tenants(self) -> AzureApiResponse:
        api_version = settings.tenant_discovery_api_version
        return await self._request_json(
            method="GET",
            url=f"{ARM_BASE_URL}/tenants",
            source_api="arm",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def list_subscriptions(self) -> AzureApiResponse:
        api_version = settings.subscription_api_version
        return await self._request_json(
            method="GET",
            url=f"{ARM_BASE_URL}/subscriptions",
            source_api="arm",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def list_management_groups(self) -> AzureApiResponse:
        api_version = "2023-04-01"
        return await self._request_json(
            method="GET",
            url=f"{ARM_BASE_URL}/providers/Microsoft.Management/managementGroups",
            source_api="arm",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def get_role_assignments(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2022-04-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="authorization",
            api_version=api_version,
            params={"api-version": api_version, "$filter": "atScope()"},
        )

    async def get_classic_administrators(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2015-06-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/classicAdministrators"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="authorization",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def get_policy_assignments(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2023-04-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyAssignments"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="policy",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def get_defender_pricings(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2024-01-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="defender",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def get_secure_scores(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2020-01-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Security/secureScores"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="defender",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def get_regulatory_compliance(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2024-01-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Security/regulatoryComplianceStandards"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="defender",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def get_policy_states(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2019-10-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
        body = {
            "queryResultsFormat": "Default",
            "top": 50,
            "filter": "ComplianceState eq 'NonCompliant'",
        }
        return await self._request_json(
            method="POST",
            url=endpoint,
            source_api="policy",
            api_version=api_version,
            params={"api-version": api_version},
            json_body=body,
            query=json.dumps(body),
        )

    async def get_activity_logs(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2015-04-01"
        since = (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/microsoft.insights/eventtypes/management/values"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="monitor",
            api_version=api_version,
            params={"api-version": api_version, "$top": 25, "$filter": f"eventTimestamp ge '{since}'"},
        )

    async def list_key_vaults(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2023-07-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="arm",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def list_storage_accounts(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2023-05-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="arm",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def list_virtual_machines(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2024-03-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="arm",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def get_security_assessments(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2020-01-01"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="defender",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def get_security_alerts(self, subscription_id: str) -> AzureApiResponse:
        api_version = "2022-01-01-preview"
        endpoint = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/providers/Microsoft.Security/alerts"
        return await self._request_json(
            method="GET",
            url=endpoint,
            source_api="defender",
            api_version=api_version,
            params={"api-version": api_version},
        )

    async def resource_graph(self, subscription_ids: list[str], query: str) -> AzureApiResponse:
        api_version = "2022-10-01"
        endpoint = f"{ARM_BASE_URL}/providers/Microsoft.ResourceGraph/resources"
        body = {"subscriptions": subscription_ids, "query": query, "options": {"$top": 100}}
        return await self._request_json(
            method="POST",
            url=endpoint,
            source_api="resource_graph",
            api_version=api_version,
            params={"api-version": api_version},
            json_body=body,
            query=query,
        )

    async def graph_profile(self) -> AzureApiResponse:
        return await self._request_json(
            method="GET",
            url=f"{GRAPH_BASE_URL}/organization?$select=id,displayName,verifiedDomains",
            source_api="graph",
        )

    async def safe_get(self, absolute_url: str, source_api: str, api_version: str | None = None) -> AzureApiResponse:
        params = {"api-version": api_version} if api_version else None
        return await self._request_json(
            method="GET",
            url=absolute_url,
            source_api=source_api,
            api_version=api_version,
            params=params,
        )
