-- Revert: Fix foreign key in command_queue to reference commands.command_id (VARCHAR) instead of commands.id (UUID)

-- Drop the new foreign key constraint
ALTER TABLE command_queue DROP CONSTRAINT command_queue_command_id_fkey;

-- Change command_id column back to UUID
ALTER TABLE command_queue ALTER COLUMN command_id TYPE UUID USING command_id::UUID;

-- Restore old foreign key constraint
ALTER TABLE command_queue
ADD CONSTRAINT command_queue_command_id_fkey
FOREIGN KEY (command_id) REFERENCES commands(id) ON DELETE CASCADE;
