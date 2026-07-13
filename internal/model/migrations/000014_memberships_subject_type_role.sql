-- +goose Up

ALTER TYPE membership_subject_type ADD VALUE 'role';

-- +goose Down

ALTER TYPE membership_subject_type DROP VALUE 'role' IF EXISTS;