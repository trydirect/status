-- Add cloud_id back to server table to track which cloud provider the server belongs to
-- This allows displaying the provider name in the UI and knowing which cloud API to use

ALTER TABLE server ADD COLUMN cloud_id INTEGER REFERENCES cloud(id) ON DELETE SET NULL;

CREATE INDEX idx_server_cloud_id ON server(cloud_id);

COMMENT ON COLUMN server.cloud_id IS 'Reference to the cloud provider (DO, Hetzner, AWS, etc.) this server belongs to';
