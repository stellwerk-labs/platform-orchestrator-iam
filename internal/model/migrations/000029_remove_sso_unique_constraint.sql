-- +goose Up

ALTER TABLE sso_configuration DROP CONSTRAINT unique_provider_org_id;

-- +goose Down

ALTER TABLE sso_configuration ADD CONSTRAINT unique_provider_org_id UNIQUE (provider_org_id);

