CREATE TABLE IF NOT EXISTS marketplace_event (
    id BIGSERIAL PRIMARY KEY,
    template_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN ('view', 'deploy')),
    viewer_user_id VARCHAR(50),
    deployer_user_id VARCHAR(50),
    cloud_provider VARCHAR(100),
    occurred_at TIMESTAMPTZ DEFAULT (NOW() AT TIME ZONE 'utc'),
    metadata JSONB,
    CONSTRAINT fk_marketplace_event_template
        FOREIGN KEY (template_id) REFERENCES stack_template(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_marketplace_event_template ON marketplace_event(template_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_event_type ON marketplace_event(event_type);
CREATE INDEX IF NOT EXISTS idx_marketplace_event_occurred ON marketplace_event(occurred_at);
CREATE INDEX IF NOT EXISTS idx_marketplace_event_viewer ON marketplace_event(viewer_user_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_event_deployer ON marketplace_event(deployer_user_id);
