-- Fix foreign key in command_queue to reference commands.command_id (VARCHAR) instead of commands.id (UUID)

-- Drop the old foreign key constraint
ALTER TABLE command_queue DROP CONSTRAINT command_queue_command_id_fkey;

-- Change command_id column from UUID to VARCHAR(64)
ALTER TABLE command_queue ALTER COLUMN command_id TYPE VARCHAR(64);

-- Add new foreign key constraint referencing commands.command_id instead
ALTER TABLE command_queue
ADD CONSTRAINT command_queue_command_id_fkey
FOREIGN KEY (command_id) REFERENCES commands(command_id) ON DELETE CASCADE;
