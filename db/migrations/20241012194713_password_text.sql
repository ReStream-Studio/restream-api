-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
-- +goose StatementEnd

-- +goose Down
ALTER TABLE users ADD COLUMN jwt_token TEXT;
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
