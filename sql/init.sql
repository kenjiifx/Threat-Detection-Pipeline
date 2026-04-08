-- Threat Detection Pipeline — initial schema

CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source TEXT NOT NULL CHECK (source IN ('system', 'ssh')),
    event_time TIMESTAMPTZ,
    hostname TEXT,
    severity TEXT,
    message TEXT NOT NULL,
    src_ip INET,
    "user" TEXT,
    event_subtype TEXT
);

CREATE INDEX IF NOT EXISTS idx_security_events_received_at ON security_events (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_src_ip ON security_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_subtype_time ON security_events (event_subtype, received_at DESC);

CREATE TABLE IF NOT EXISTS detection_alerts (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail JSONB,
    related_src_ip INET,
    related_user TEXT,
    event_count INTEGER
);

CREATE INDEX IF NOT EXISTS idx_detection_alerts_created_at ON detection_alerts (created_at DESC);
