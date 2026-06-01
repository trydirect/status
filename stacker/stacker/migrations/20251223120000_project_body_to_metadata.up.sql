-- Rename project.body to project.metadata to align with model changes
ALTER TABLE project RENAME COLUMN body TO metadata;
