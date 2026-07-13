-- +goose Up

ALTER TABLE roles ADD CONSTRAINT unique_display_name UNIQUE (org_id, display_name);

-- +goose Down

ALTER TABLE roles DROP CONSTRAINT unique_display_name IF EXISTS;
