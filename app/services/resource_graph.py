from __future__ import annotations

from app.services.azure_clients import AzureApiResponse, AzureReadOnlyClient


async def query_resource_graph(client: AzureReadOnlyClient, subscription_ids: list[str], query: str) -> AzureApiResponse:
    return await client.resource_graph(subscription_ids, query)


def rows_from_arg(response: AzureApiResponse) -> list[dict]:
    payload = response.payload
    data = payload.get("data", [])
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("rows", [])
    return []