-- Revert project.metadata back to project.body
ALTER TABLE project RENAME COLUMN metadata TO body;
