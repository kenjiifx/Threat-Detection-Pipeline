"""Threat Detection Pipeline entrypoint."""

from __future__ import annotations

import logging
import queue
import signal
import sys
import threading
import time

from threat_pipeline.config import load_settings
from threat_pipeline.db import connect_pool_with_retry
from threat_pipeline.detection import detection_loop
from threat_pipeline.ingestion import batch_writer_loop, start_ingestion_threads
from threat_pipeline.metrics import start_metrics_server

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    settings = load_settings()
    conn_ingest = connect_pool_with_retry(settings.database_url)
    conn_detect = connect_pool_with_retry(settings.database_url)

    start_metrics_server(settings.metrics_host, settings.metrics_port)
    logger.info("Metrics listening on %s:%s", settings.metrics_host, settings.metrics_port)

    q: queue.Queue = queue.Queue(maxsize=50_000)
    stop = threading.Event()

    start_ingestion_threads(settings.system_log_path, settings.ssh_log_path, q, stop)

    batch_t = threading.Thread(
        target=batch_writer_loop,
        args=(
            conn_ingest,
            q,
            settings.ingest_batch_size,
            settings.ingest_flush_interval_sec,
            stop,
        ),
        name="batch-writer",
        daemon=True,
    )
    batch_t.start()

    det_t = threading.Thread(
        target=detection_loop,
        args=(conn_detect, settings, stop),
        name="detection",
        daemon=True,
    )
    det_t.start()

    def _handle_sig(*_args: object) -> None:
        logger.info("Shutdown requested")
        stop.set()

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    try:
        while not stop.is_set():
            time.sleep(0.5)
    finally:
        stop.set()
        time.sleep(settings.ingest_flush_interval_sec + 0.5)
        batch_t.join(timeout=5.0)
        det_t.join(timeout=5.0)
        conn_ingest.close()
        conn_detect.close()
        logger.info("Stopped")


if __name__ == "__main__":
    main()
