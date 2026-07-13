-- +goose Up

ALTER TABLE users ADD COLUMN primary_email_address text null;

-- +goose Down

ALTER TABLE users DROP COLUMN primary_email_address;
