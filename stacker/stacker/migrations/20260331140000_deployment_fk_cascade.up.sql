-- Fix FK on deployment.project_id to cascade on project delete.
-- Previously it defaulted to RESTRICT, causing 500 when deleting a project
-- that had associated deployments.
ALTER TABLE deployment DROP CONSTRAINT fk_project;
ALTER TABLE deployment
    ADD CONSTRAINT fk_project
    FOREIGN KEY (project_id) REFERENCES project(id)
    ON UPDATE CASCADE ON DELETE CASCADE;
