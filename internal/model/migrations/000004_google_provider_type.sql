-- +goose Up

ALTER TYPE identity_provider ADD VALUE IF NOT EXISTS 'google';

-- +goose Down
