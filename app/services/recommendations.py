from __future__ import annotations

from app.models import Finding, Recommendation
from app.services.evidence import build_recommendation


def build_recommendations_register(findings: list[Finding]) -> list[Recommendation]:
    recommendations_by_key: dict[str, Recommendation] = {}
    for finding in findings:
        recommendation = build_recommendation(finding=finding)
        recommendations_by_key.setdefault(recommendation.recommendation_id, recommendation)
    return sorted(recommendations_by_key.values(), key=lambda item: (item.priority, item.title))