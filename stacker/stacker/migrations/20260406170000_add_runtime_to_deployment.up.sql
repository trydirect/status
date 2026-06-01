-- Add runtime column to deployment table for Kata containers support
ALTER TABLE deployment ADD COLUMN runtime VARCHAR(20) NOT NULL DEFAULT 'runc';

-- Validate runtime values
ALTER TABLE deployment ADD CONSTRAINT chk_deployment_runtime 
    CHECK (runtime IN ('runc', 'kata'));

-- Index for filtering by runtime
CREATE INDEX idx_deployment_runtime ON deployment(runtime);
