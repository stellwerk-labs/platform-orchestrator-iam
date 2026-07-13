-- +goose Up

CREATE TABLE dismissed_prompts (
    user_id uuid NOT NULL,
    id text NOT NULL,
    PRIMARY KEY (user_id, id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- +goose Down

DROP TABLE dismissed_prompts;
