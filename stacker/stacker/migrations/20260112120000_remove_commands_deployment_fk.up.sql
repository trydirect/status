-- Remove FK constraint from commands.deployment_hash to allow hashes from external installations
ALTER TABLE commands DROP CONSTRAINT IF EXISTS commands_deployment_hash_fkey;
