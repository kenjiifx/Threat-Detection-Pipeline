"""Prometheus metrics for the pipeline."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, start_http_server

_events_ingested = Counter(
    "pipeline_events_ingested_total",
    "Security events written to PostgreSQL",
    ["source"],
)
_ssh_failed = Counter(
    "ssh_failed_attempts_total",
    "SSH failed authentication attempts (parsed)",
    ["subtype"],
)
_alerts = Counter(
    "detection_alerts_total",
    "Detection alerts raised",
    ["alert_type"],
)
_brute_gauge = Gauge(
    "brute_force_candidates",
    "Distinct source IPs over brute-force threshold in lookback window",
)


def inc_ingested(source: str, n: int = 1) -> None:
    _events_ingested.labels(source=source).inc(n)


_ingest_dropped = Counter(
    "pipeline_ingest_events_dropped_total",
    "Events dropped after repeated DB insert failures",
)


def inc_ingest_dropped(n: int = 1) -> None:
    _ingest_dropped.inc(n)


def inc_ssh_failed(subtype: str, n: int = 1) -> None:
    _ssh_failed.labels(subtype=subtype).inc(n)


def inc_alert(alert_type: str, n: int = 1) -> None:
    _alerts.labels(alert_type=alert_type).inc(n)


def set_brute_force_candidates(value: float) -> None:
    _brute_gauge.set(value)


def start_metrics_server(host: str, port: int) -> None:
    start_http_server(port, addr=host)
