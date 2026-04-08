"""Automated alerts: structured logging and optional webhook."""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)


def send_alert(
    alert_type: str,
    severity: str,
    detail: dict[str, Any],
    webhook_url: str | None,
) -> None:
    payload = {
        "alert_type": alert_type,
        "severity": severity,
        "detail": detail,
    }
    logger.error(
        "DETECTION_ALERT %s",
        json.dumps(payload, default=str),
    )
    if not webhook_url:
        return
    try:
        r = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        r.raise_for_status()
    except Exception as e:
        logger.warning("Webhook delivery failed: %s", e)
