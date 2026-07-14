-- Revert updated_at addition and command_queue command_id type change
ALTER TABLE commands
    DROP COLUMN IF EXISTS updated_at;

ALTER TABLE command_queue
    DROP CONSTRAINT IF EXISTS command_queue_command_id_fkey;

ALTER TABLE command_queue
    ALTER COLUMN command_id TYPE UUID USING command_id::uuid;

ALTER TABLE command_queue
    ADD CONSTRAINT command_queue_command_id_fkey
        FOREIGN KEY (command_id) REFERENCES commands(id) ON DELETE CASCADE;
