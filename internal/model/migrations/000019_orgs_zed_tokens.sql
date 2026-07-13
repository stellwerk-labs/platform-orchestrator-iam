-- +goose Up

CREATE TABLE org_zed_tokens (
    org_id text primary key,
    zed_token text
);


-- +goose Down

DROP TABLE org_zed_tokens IF EXISTS;
