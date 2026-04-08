"""Tail log files and enqueue parsed events for batched DB insert."""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from threat_pipeline.db import SecurityEventRow
from threat_pipeline.metrics import inc_ingest_dropped, inc_ingested, inc_ssh_failed
from threat_pipeline.parsers import ParsedLine, parse_ssh_line, parse_system_line

logger = logging.getLogger(__name__)


def _follow_file(path: str, stop: threading.Event) -> Iterator[str]:
    """Yield new lines from a file (like tail -F)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.touch()
    while not stop.is_set():
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                while not stop.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    yield line
        except FileNotFoundError:
            logger.warning("Log file missing, waiting: %s", path)
            time.sleep(1.0)


def _tail_worker(
    path: str,
    label: str,
    parse_fn: Callable[[str], ParsedLine],
    out: queue.Queue,
    stop: threading.Event,
) -> None:
    for line in _follow_file(path, stop):
        if stop.is_set():
            break
        pl: ParsedLine = parse_fn(line)
        row = SecurityEventRow(
            source=label,
            event_time=pl.event_time or datetime.now(timezone.utc),
            hostname=pl.hostname,
            severity=pl.severity,
            message=pl.message,
            src_ip=pl.src_ip,
            user=pl.user,
            event_subtype=pl.event_subtype,
        )
        try:
            out.put(row, timeout=120.0)
        except queue.Full:
            logger.error("Ingest queue full; dropping one event")
            continue
        if label == "ssh" and pl.event_subtype in ("ssh_failed_password", "ssh_invalid_user"):
            inc_ssh_failed(pl.event_subtype or "unknown")


def start_ingestion_threads(
    system_log_path: str | None,
    ssh_log_path: str | None,
    out: queue.Queue,
    stop: threading.Event,
) -> list[threading.Thread]:
    threads: list[threading.Thread] = []
    if system_log_path:
        t = threading.Thread(
            target=_tail_worker,
            args=(system_log_path, "system", parse_system_line, out, stop),
            name="ingest-system",
            daemon=True,
        )
        t.start()
        threads.append(t)
    if ssh_log_path:
        t = threading.Thread(
            target=_tail_worker,
            args=(ssh_log_path, "ssh", parse_ssh_line, out, stop),
            name="ingest-ssh",
            daemon=True,
        )
        t.start()
        threads.append(t)
    return threads


def _insert_batch_with_retry(conn, buf: list[SecurityEventRow]) -> bool:
    """Insert batch; return True on success. On hard failure, drop batch and metric."""
    from threat_pipeline.db import insert_security_events_batch

    if not buf:
        return True
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            insert_security_events_batch(conn, buf)
            return True
        except psycopg.DataError as e:
            logger.error("Invalid row data, dropping %s events: %s", len(buf), e)
            inc_ingest_dropped(len(buf))
            return False
        except (psycopg.OperationalError, psycopg.InterfaceError) as e:
            last_err = e
            logger.warning("Batch insert attempt %s/3 failed: %s", attempt + 1, e)
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    logger.critical("Dropping %s events after DB failures: %s", len(buf), last_err)
    inc_ingest_dropped(len(buf))
    return False


def batch_writer_loop(
    conn,
    q: queue.Queue,
    batch_size: int,
    flush_interval: float,
    stop: threading.Event,
) -> None:
    buf: list[SecurityEventRow] = []
    last_flush = time.monotonic()
    while not stop.is_set():
        try:
            row = q.get(timeout=min(flush_interval, 0.5))
            buf.append(row)
        except queue.Empty:
            pass
        now = time.monotonic()
        if buf and (len(buf) >= batch_size or (now - last_flush) >= flush_interval):
            by_source: dict[str, int] = {}
            for r in buf:
                by_source[r.source] = by_source.get(r.source, 0) + 1
            if _insert_batch_with_retry(conn, buf):
                for src, c in by_source.items():
                    inc_ingested(src, c)
                logger.debug("Flushed %s events", len(buf))
            buf.clear()
            last_flush = now
    if buf:
        by_source = {}
        for r in buf:
            by_source[r.source] = by_source.get(r.source, 0) + 1
        if _insert_batch_with_retry(conn, buf):
            for src, c in by_source.items():
                inc_ingested(src, c)
