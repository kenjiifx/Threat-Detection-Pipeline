"""Environment-based configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _get_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return float(raw)


@dataclass(frozen=True)
class Settings:
    database_url: str
    system_log_path: str | None
    ssh_log_path: str | None
    ingest_batch_size: int
    ingest_flush_interval_sec: float
    detection_interval_sec: float
    brute_force_threshold: int
    brute_force_window_minutes: int
    credential_stuffing_min_users: int
    credential_stuffing_window_minutes: int
    alert_webhook_url: str | None
    metrics_host: str
    metrics_port: int
    alert_cooldown_sec: int


def load_settings() -> Settings:
    db = os.environ.get("DATABASE_URL", "").strip()
    if not db:
        raise RuntimeError("DATABASE_URL is required")

    sys_path = os.environ.get("SYSTEM_LOG_PATH", "").strip() or None
    ssh_path = os.environ.get("SSH_LOG_PATH", "").strip() or None
    if not sys_path and not ssh_path:
        raise RuntimeError("At least one of SYSTEM_LOG_PATH or SSH_LOG_PATH must be set")

    return Settings(
        database_url=db,
        system_log_path=sys_path,
        ssh_log_path=ssh_path,
        ingest_batch_size=max(1, _get_int("INGEST_BATCH_SIZE", 50)),
        ingest_flush_interval_sec=max(0.05, _get_float("INGEST_FLUSH_INTERVAL_SEC", 0.3)),
        detection_interval_sec=max(1.0, _get_float("DETECTION_INTERVAL_SEC", 10.0)),
        brute_force_threshold=max(1, _get_int("BRUTE_FORCE_THRESHOLD", 5)),
        brute_force_window_minutes=max(1, _get_int("BRUTE_FORCE_WINDOW_MINUTES", 5)),
        credential_stuffing_min_users=max(2, _get_int("CREDENTIAL_STUFFING_MIN_USERS", 3)),
        credential_stuffing_window_minutes=max(1, _get_int("CREDENTIAL_STUFFING_WINDOW_MINUTES", 5)),
        alert_webhook_url=(os.environ.get("ALERT_WEBHOOK_URL") or "").strip() or None,
        metrics_host=os.environ.get("METRICS_HOST", "0.0.0.0").strip() or "0.0.0.0",
        metrics_port=_get_int("METRICS_PORT", 8000),
        alert_cooldown_sec=max(0, _get_int("ALERT_COOLDOWN_SEC", 120)),
    )
