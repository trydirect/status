CREATE TABLE IF NOT EXISTS marketplace_template_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES stack_template(id) ON DELETE CASCADE,
    event_type VARCHAR(32) NOT NULL CHECK (event_type IN ('view', 'deploy')),
    user_id VARCHAR(50),
    viewer_user_id VARCHAR(50),
    deployer_user_id VARCHAR(50),
    cloud_provider VARCHAR(64),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_marketplace_template_event_template
    ON marketplace_template_event(template_id);

CREATE INDEX IF NOT EXISTS idx_marketplace_template_event_type_created
    ON marketplace_template_event(event_type, created_at);

CREATE INDEX IF NOT EXISTS idx_marketplace_template_event_template_created
    ON marketplace_template_event(template_id, created_at);

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_user', '/api/templates/mine/analytics', 'GET', '', '', '')
ON CONFLICT DO NOTHING;

INSERT INTO public.casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
VALUES ('p', 'group_admin', '/api/templates/mine/analytics', 'GET', '', '', '')
ON CONFLICT DO NOTHING;
