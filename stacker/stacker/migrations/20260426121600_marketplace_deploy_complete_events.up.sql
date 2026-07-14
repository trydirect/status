CREATE TABLE IF NOT EXISTS stack_template_deployment (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id uuid NOT NULL REFERENCES stack_template(id) ON DELETE CASCADE,
    deployment_hash text NOT NULL UNIQUE,
    server_ip text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_stack_template_deployment_template_id
    ON stack_template_deployment(template_id);
