# Threat Detection Pipeline

Ingests system and SSH logs into **PostgreSQL**, flags brute-force and suspicious login patterns, sends alerts (logs + optional webhook), and exposes **Prometheus** metrics with **Grafana** dashboards.

**Run**

```bash
docker compose up --build
```

| | |
|--|--|
| Grafana | http://localhost:3000 — `admin` / `admin` |
| Prometheus | http://localhost:9090 |
| Metrics | http://localhost:8000/metrics |

Dashboard: **Threat Detection Pipeline** in Grafana.

**Try an alert** (append failed SSH lines, then wait ~10s):

```bash
docker compose exec pipeline sh -c 'for i in 1 2 3 4 5 6; do echo "Jan 15 10:23:45 demo sshd[1234]: Failed password for root from 192.168.99.50 port 22 ssh2" >> /logs/auth.log; done'
```

Tune thresholds and paths via env vars on the `pipeline` service in [`docker-compose.yml`](docker-compose.yml). The process waits for PostgreSQL on startup and retries batch inserts before discarding rows; Grafana’s **Ingest drops** panel should stay at zero in normal operation.
