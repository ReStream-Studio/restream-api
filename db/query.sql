-- name: GetUser :one
SELECT * FROM users WHERE email = $1;

-- name: GetUsers :many
SELECT * FROM users ORDER BY username;

-- name: CreateUser :exec
INSERT INTO
    users (username, email, password)
VALUES ($1, $2, $3);

-- name: CreateSession :exec
WITH deleted_session AS (
  DELETE FROM sessions
  WHERE user_id = $1
  RETURNING *
)
INSERT INTO sessions (user_id, access_token, refresh_token)
VALUES ($1, $2, $3);