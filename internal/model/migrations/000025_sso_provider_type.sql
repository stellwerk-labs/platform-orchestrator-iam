-- +goose Up

ALTER TYPE identity_provider ADD VALUE IF NOT EXISTS 'sso';

-- +goose Down

ALTER TYPE identity_provider DROP VALUE 'sso' IF EXISTS;
