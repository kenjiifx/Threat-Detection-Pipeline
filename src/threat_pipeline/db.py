"""PostgreSQL connection and persistence."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Generator, Iterable

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

logger = logging.getLogger(__name__)


@dataclass
class SecurityEventRow:
    source: str
    event_time: datetime | None
    hostname: str | None
    severity: str | None
    message: str
    src_ip: str | None
    user: str | None
    event_subtype: str | None


def connect_pool(database_url: str) -> psycopg.Connection:
    """Single shared connection (sufficient for this pipeline scale)."""
    return psycopg.connect(database_url, autocommit=True)


@contextmanager
def get_cursor(conn: psycopg.Connection) -> Generator[Any, None, None]:
    with conn.cursor() as cur:
        yield cur


def insert_security_events_batch(conn: psycopg.Connection, rows: Iterable[SecurityEventRow]) -> int:
    batch = list(rows)
    if not batch:
        return 0
    values = [
        (
            r.source,
            r.event_time,
            r.hostname,
            r.severity,
            r.message,
            r.src_ip,
            r.user,
            r.event_subtype,
        )
        for r in batch
    ]
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO security_events
                (source, event_time, hostname, severity, message, src_ip, "user", event_subtype)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            values,
        )
    return len(batch)


def insert_detection_alert(
    conn: psycopg.Connection,
    alert_type: str,
    severity: str,
    detail: dict[str, Any],
    related_src_ip: str | None,
    related_user: str | None,
    event_count: int | None,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO detection_alerts
                (alert_type, severity, detail, related_src_ip, related_user, event_count)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                alert_type,
                severity,
                Json(detail),
                related_src_ip,
                related_user,
                event_count,
            ),
        )
        row = cur.fetchone()
        return int(row[0]) if row else -1


def fetch_recent_failed_ssh_by_ip(
    conn: psycopg.Connection,
    since: datetime,
) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT src_ip::text AS src_ip, COUNT(*) AS cnt
            FROM security_events
            WHERE source = 'ssh'
              AND received_at >= %s
              AND event_subtype IN ('ssh_failed_password', 'ssh_invalid_user')
              AND src_ip IS NOT NULL
            GROUP BY src_ip
            """,
            (since,),
        )
        return list(cur.fetchall())


def fetch_credential_stuffing_candidates(
    conn: psycopg.Connection,
    since: datetime,
    min_distinct_users: int,
) -> list[dict[str, Any]]:
    """IPs with failed SSH for at least min_distinct_users distinct usernames."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT src_ip::text AS src_ip,
                   COUNT(DISTINCT "user") AS distinct_users
            FROM security_events
            WHERE source = 'ssh'
              AND received_at >= %s
              AND event_subtype IN ('ssh_failed_password', 'ssh_invalid_user')
              AND src_ip IS NOT NULL
              AND "user" IS NOT NULL
            GROUP BY src_ip
            HAVING COUNT(DISTINCT "user") >= %s
            """,
            (since, min_distinct_users),
        )
        return list(cur.fetchall())


def count_brute_force_ips_over_threshold(
    conn: psycopg.Connection,
    since: datetime,
    threshold: int,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM (
              SELECT src_ip
              FROM security_events
              WHERE source = 'ssh'
                AND received_at >= %s
                AND event_subtype IN ('ssh_failed_password', 'ssh_invalid_user')
                AND src_ip IS NOT NULL
              GROUP BY src_ip
              HAVING COUNT(*) >= %s
            ) t
            """,
            (since, threshold),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0
