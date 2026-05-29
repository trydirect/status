-- Create commands table
CREATE TABLE commands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    command_id VARCHAR(64) UNIQUE NOT NULL,
    deployment_hash VARCHAR(64) NOT NULL REFERENCES deployment(deployment_hash) ON DELETE CASCADE,
    type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'queued' NOT NULL,
    priority VARCHAR(20) DEFAULT 'normal' NOT NULL,
    parameters JSONB DEFAULT '{}'::jsonb,
    result JSONB,
    error JSONB,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL,
    scheduled_for TIMESTAMP,
    sent_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    timeout_seconds INTEGER DEFAULT 300,
    metadata JSONB DEFAULT '{}'::jsonb,
    CONSTRAINT chk_command_status CHECK (status IN ('queued', 'sent', 'executing', 'completed', 'failed', 'cancelled')),
    CONSTRAINT chk_command_priority CHECK (priority IN ('low', 'normal', 'high', 'critical'))
);

CREATE INDEX idx_commands_deployment_hash ON commands(deployment_hash);
CREATE INDEX idx_commands_status ON commands(status);
CREATE INDEX idx_commands_created_by ON commands(created_by);
CREATE INDEX idx_commands_created_at ON commands(created_at);
CREATE INDEX idx_commands_command_id ON commands(command_id);

-- Create command_queue table for long polling
CREATE TABLE command_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    command_id UUID NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    deployment_hash VARCHAR(64) NOT NULL,
    priority INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMP DEFAULT NOW() NOT NULL
);

CREATE INDEX idx_queue_deployment ON command_queue(deployment_hash, priority DESC, created_at ASC);
CREATE INDEX idx_queue_command_id ON command_queue(command_id);
