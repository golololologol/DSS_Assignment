-- +goose Up
CREATE TABLE IF NOT EXISTS bbb (
    user_id SERIAL NOT NULL,
    user_name VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    admin BOOL NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS comments (
    comment_id SERIAL NOT NULL,
    sender_id INTEGER  NOT NULL,
    content VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (sender_id) REFERENCES bbb(user_id)
);
-- +goose Down
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS bbb;
