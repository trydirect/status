CREATE TABLE IF NOT EXISTS agent_audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    installation_hash   TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    payload             JSONB NOT NULL,
    status_panel_id     BIGINT,          -- original ID from Status Panel buffer
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL  -- from Status Panel
);

CREATE INDEX idx_agent_audit_log_installation ON agent_audit_log(installation_hash);
CREATE INDEX idx_agent_audit_log_event_type ON agent_audit_log(event_type);
CREATE INDEX idx_agent_audit_log_received_at ON agent_audit_log(received_at DESC);
