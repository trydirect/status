-- Revert to original FK without cascade
ALTER TABLE deployment DROP CONSTRAINT fk_project;
ALTER TABLE deployment
    ADD CONSTRAINT fk_project
    FOREIGN KEY (project_id) REFERENCES project(id);
