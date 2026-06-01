-- Add updated_at to commands and fix command_queue command_id type

ALTER TABLE commands
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW() NOT NULL;

-- Ensure command_queue.command_id matches commands.command_id (varchar)
ALTER TABLE command_queue
    DROP CONSTRAINT IF EXISTS command_queue_command_id_fkey;

ALTER TABLE command_queue
    ALTER COLUMN command_id TYPE VARCHAR(64);

ALTER TABLE command_queue
    ADD CONSTRAINT command_queue_command_id_fkey
        FOREIGN KEY (command_id) REFERENCES commands(command_id) ON DELETE CASCADE;
