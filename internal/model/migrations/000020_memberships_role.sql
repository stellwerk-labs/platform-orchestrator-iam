-- +goose Up

UPDATE memberships m
SET 
    role = subject::uuid
WHERE 
    subject_type = 'role' AND role IS NULL;
