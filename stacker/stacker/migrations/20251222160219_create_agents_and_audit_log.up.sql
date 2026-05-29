-- Create agents table
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_hash VARCHAR(64) UNIQUE NOT NULL REFERENCES deployment(deployment_hash) ON DELETE CASCADE,
    capabilities JSONB DEFAULT '[]'::jsonb,
    version VARCHAR(50),
    system_info JSONB DEFAULT '{}'::jsonb,
    last_heartbeat TIMESTAMP,
    status VARCHAR(50) DEFAULT 'offline',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT chk_agent_status CHECK (status IN ('online', 'offline', 'degraded'))
);

CREATE INDEX idx_agents_deployment_hash ON agents(deployment_hash);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_last_heartbeat ON agents(last_heartbeat);

-- Create audit_log table
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    deployment_hash VARCHAR(64),
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50),
    details JSONB DEFAULT '{}'::jsonb,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_log_agent_id ON audit_log(agent_id);
CREATE INDEX idx_audit_log_deployment_hash ON audit_log(deployment_hash);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
