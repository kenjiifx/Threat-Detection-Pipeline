"""Threshold-based anomaly detection over recent security_events."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from threat_pipeline.alerts import send_alert
from threat_pipeline.config import Settings
from threat_pipeline.db import (
    count_brute_force_ips_over_threshold,
    fetch_credential_stuffing_candidates,
    fetch_recent_failed_ssh_by_ip,
    insert_detection_alert,
)
from threat_pipeline.metrics import inc_alert, set_brute_force_candidates

logger = logging.getLogger(__name__)


def _cooldown_ok(last_fire: dict[str, float], key: str, cooldown_sec: int) -> bool:
    now = time.monotonic()
    prev = last_fire.get(key)
    if prev is None or (now - prev) >= cooldown_sec:
        last_fire[key] = now
        return True
    return False


def run_detection_cycle(
    conn,
    settings: Settings,
    last_fire: dict[str, float],
) -> None:
    now = datetime.now(timezone.utc)
    since_bf = now - timedelta(minutes=settings.brute_force_window_minutes)
    since_cs = now - timedelta(minutes=settings.credential_stuffing_window_minutes)
    rows = fetch_recent_failed_ssh_by_ip(conn, since_bf)
    candidates = [r for r in rows if int(r["cnt"]) >= settings.brute_force_threshold]
    set_brute_force_candidates(
        float(
            count_brute_force_ips_over_threshold(
                conn,
                since_bf,
                settings.brute_force_threshold,
            )
        )
    )

    for r in candidates:
        ip = r["src_ip"]
        cnt = int(r["cnt"])
        key = f"brute_force:{ip}"
        if not _cooldown_ok(last_fire, key, settings.alert_cooldown_sec):
            continue
        detail: dict[str, Any] = {
            "reason": "failed_ssh_attempts_exceeded",
            "window_minutes": settings.brute_force_window_minutes,
            "threshold": settings.brute_force_threshold,
            "observed_count": cnt,
        }
        insert_detection_alert(
            conn,
            "brute_force",
            "high",
            detail,
            ip,
            None,
            cnt,
        )
        inc_alert("brute_force")
        send_alert("brute_force", "high", detail, settings.alert_webhook_url)
        logger.info("Brute-force alert for %s (%s failures)", ip, cnt)

    stuffing = fetch_credential_stuffing_candidates(
        conn,
        since_cs,
        settings.credential_stuffing_min_users,
    )
    for r in stuffing:
        ip = r["src_ip"]
        du = int(r["distinct_users"])
        key = f"credential_stuffing:{ip}"
        if not _cooldown_ok(last_fire, key, settings.alert_cooldown_sec):
            continue
        detail = {
            "reason": "many_distinct_users_failed_from_same_ip",
            "window_minutes": settings.credential_stuffing_window_minutes,
            "min_distinct_users": settings.credential_stuffing_min_users,
            "observed_distinct_users": du,
        }
        insert_detection_alert(
            conn,
            "suspicious_user_pattern",
            "medium",
            detail,
            ip,
            None,
            du,
        )
        inc_alert("suspicious_user_pattern")
        send_alert("suspicious_user_pattern", "medium", detail, settings.alert_webhook_url)
        logger.info(
            "Credential-stuffing pattern alert for %s (%s distinct users)",
            ip,
            du,
        )


def detection_loop(conn, settings: Settings, stop_event) -> None:
    last_fire: dict[str, float] = {}
    while True:
        try:
            run_detection_cycle(conn, settings, last_fire)
        except Exception as e:
            logger.exception("Detection cycle failed: %s", e)
        if stop_event.wait(settings.detection_interval_sec):
            break
