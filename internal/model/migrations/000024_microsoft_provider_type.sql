-- +goose Up

ALTER TYPE identity_provider ADD VALUE IF NOT EXISTS 'microsoft';

-- +goose Down

ALTER TYPE identity_provider DROP VALUE 'microsoft' IF EXISTS;
