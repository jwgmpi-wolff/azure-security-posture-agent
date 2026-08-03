from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

import yaml
from pptx import Presentation

from app.services.exporters import export_pptx, export_sqlite
from app.services.package_builder import build_m365_package
from tests._helpers import build_sample_assessment


def test_openapi_templates_package_and_export_contracts() -> None:
    openapi_path = Path("m365-agent/openapi.template.yaml")
    document = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))

    assert document["openapi"].startswith("3.")
    assert set(document["paths"]) >= {
        "/api/copilot/auth-context",
        "/api/copilot/assessment-summary",
        "/api/copilot/security-findings",
        "/api/copilot/recommendations",
    }
    assert "Tenant" in document["components"]["schemas"]
    assert "Subscription" in document["components"]["schemas"]
    assert "CopilotAuthContext" in document["components"]["schemas"]
    assert "ScopeSelection" in document["components"]["schemas"]
    assert "AssessmentSummary" in document["components"]["schemas"]
    assert "Finding" in document["components"]["schemas"]
    assert "Recommendation" in document["components"]["schemas"]
    assert "Evidence" in document["components"]["schemas"]
    assert "ExportMetadata" in document["components"]["schemas"]
    all_methods = {method for path_item in document["paths"].values() for method in path_item.keys()}
    assert "put" not in all_methods
    assert "patch" not in all_methods
    assert "delete" not in all_methods

    for template_name in [
        "manifest.template.json",
        "declarativeAgent.template.json",
        "apiPlugin.template.json",
        "openapi.template.yaml",
    ]:
        text = Path("m365-agent", template_name).read_text(encoding="utf-8").lower()
        assert "client_secret" not in text
        assert "secret-value" not in text

    package_path = build_m365_package(
        repo_root=Path("."),
        api_base_url="https://example.invalid",
        oauth_client_id="00000000-0000-0000-0000-000000000000",
        oauth_authority="https://login.microsoftonline.com/common",
    )
    assert package_path.name == "azure-security-posture-agent.zip"

    with zipfile.ZipFile(package_path, "r") as archive:
        names = set(archive.namelist())
        assert names >= {"manifest.json", "declarativeAgent.json", "apiPlugin.json", "openapi.yaml", "color.png", "outline.png"}
        manifest = json.loads(archive.read("manifest.json"))
        declarative_agent = json.loads(archive.read("declarativeAgent.json"))
        plugin_document = json.loads(archive.read("apiPlugin.json"))
        plugin = archive.read("apiPlugin.json").decode("utf-8")
        openapi = archive.read("openapi.yaml").decode("utf-8")
        assert manifest["accentColor"] == "#0078D4"
        assert manifest["copilotAgents"]["declarativeAgents"][0]["id"] == "azure-security-posture-agent"
        assert declarative_agent["version"] == "v1.0"
        assert "$schema" not in declarative_agent
        assert len(declarative_agent["conversation_starters"]) == 2
        assert "getAuthContext" in declarative_agent["instructions"]
        assert "setAuthContext" in declarative_agent["instructions"]
        assert "conversationStarters" not in declarative_agent
        assert plugin_document["schema_version"] == "v2.4"
        assert plugin_document["namespace"] == "azureSecurityPosture"
        assert plugin_document["runtimes"][0]["auth"] == {
            "type": "OAuthPluginVault",
            "reference_id": "azure-security-posture-oauth",
        }
        assert plugin_document["runtimes"][0]["spec"]["url"] == "openapi.yaml"
        assert len(plugin_document["name_for_human"]) <= 20
        operation_ids = {
            operation["operationId"]
            for path_item in document["paths"].values()
            for operation in path_item.values()
        }
        function_names = {function["name"] for function in plugin_document["functions"]}
        assert function_names == operation_ids
        assert set(plugin_document["runtimes"][0]["run_for_functions"]) == operation_ids
        assert "api://00000000-0000-0000-0000-000000000000/access_as_user" in openapi
        assert "api://azure-security-posture-agent" not in plugin

    assessment = build_sample_assessment()
    pptx_path = export_pptx(assessment)
    sqlite_path = export_sqlite(assessment)

    presentation = Presentation(pptx_path)
    assert len(presentation.slides) == 10

    connection = sqlite3.connect(sqlite_path)
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    connection.close()
    assert {
        "assessment_runs",
        "tenants",
        "subscriptions",
        "resources",
        "findings",
        "recommendations",
        "evidence",
        "api_query_log",
        "export_artifacts",
    }.issubset(tables)