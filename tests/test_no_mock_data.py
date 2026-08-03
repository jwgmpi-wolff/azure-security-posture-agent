from __future__ import annotations

from pathlib import Path


def test_required_modules_exist_and_runtime_has_no_mock_data() -> None:
    required_modules = [
        "tenant_discovery.py",
        "subscription_discovery.py",
        "resource_graph.py",
        "defender_for_cloud.py",
        "azure_policy.py",
        "azure_rbac.py",
        "network_security.py",
        "key_vault_security.py",
        "storage_security.py",
        "compute_security.py",
        "identity_security.py",
        "monitor_logging.py",
        "recommendations.py",
        "enrichment.py",
    ]
    base = Path("app/services")
    for module in required_modules:
        assert (base / module).exists(), module
        text = (base / module).read_text(encoding="utf-8").lower()
        for forbidden in ["faker", "lorem", "sample finding", "mock finding", "randint("]:
            assert forbidden not in text, f"Unexpected runtime test data marker found in {module}: {forbidden}"