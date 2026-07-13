-- +goose Up

ALTER TABLE session_tokens
    ADD COLUMN client_ip text null,
    ADD COLUMN client_city text null,
    ADD COLUMN client_region text null;
ALTER TABLE device_login_requests
    ADD COLUMN client_ip text null,
    ADD COLUMN client_city text null,
    ADD COLUMN client_region text null;

-- +goose Down

ALTER TABLE session_tokens DROP COLUMN client_ip, DROP COLUMN client_city, DROP COLUMN client_region;
ALTER TABLE device_login_requests DROP COLUMN client_ip, DROP COLUMN client_city, DROP COLUMN client_region;
