"""Tail log files and enqueue parsed events for batched DB insert."""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

from threat_pipeline.db import SecurityEventRow
from threat_pipeline.metrics import inc_ingested, inc_ssh_failed
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
        out.put(row)
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


def batch_writer_loop(
    conn,
    q: queue.Queue,
    batch_size: int,
    flush_interval: float,
    stop: threading.Event,
) -> None:
    from threat_pipeline.db import insert_security_events_batch

    buf: list = []
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
            n = insert_security_events_batch(conn, buf)
            for src, c in by_source.items():
                inc_ingested(src, c)
            logger.debug("Flushed %s events", n)
            buf.clear()
            last_flush = now
    if buf:
        insert_security_events_batch(conn, buf)
        by: dict[str, int] = {}
        for r in buf:
            by[r.source] = by.get(r.source, 0) + 1
        for src, c in by.items():
            inc_ingested(src, c)
