-- +goose Up

ALTER TABLE service_user_tokens ADD COLUMN generated_by UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';

-- +goose Down

ALTER TABLE service_user_tokens DROP COLUMN generated_by;
