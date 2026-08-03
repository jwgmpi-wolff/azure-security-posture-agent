from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

from app.auth import redact_payload


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, Mapping):
            record.args = redact_payload(dict(record.args))
        elif hasattr(record, "payload") and isinstance(record.payload, Mapping):
            record.payload = redact_payload(dict(record.payload))
        return True


def configure_logging() -> None:
    root_logger = logging.getLogger()
    if any(isinstance(existing_filter, RedactionFilter) for existing_filter in root_logger.filters):
        return

    root_logger.setLevel(logging.INFO)
    root_logger.addFilter(RedactionFilter())

    for handler in root_logger.handlers:
        handler.addFilter(RedactionFilter())

    if os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
        from azure.monitor.opentelemetry import configure_azure_monitor

        configure_azure_monitor(logger_name="azure_security_posture_agent")


def safe_log_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return redact_payload(payload)
