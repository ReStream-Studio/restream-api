-- +goose Up
ALTER TABLE sessions ALTER COLUMN access_token TYPE TEXT;
ALTER TABLE sessions ALTER COLUMN refresh_token TYPE TEXT;
-- +goose StatementBegin
SELECT 'up SQL query';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
