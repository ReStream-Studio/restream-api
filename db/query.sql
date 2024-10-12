-- name: GetUser :one
SELECT * FROM users WHERE email = $1;

-- name: GetUsers :many
SELECT * FROM users ORDER BY username;

-- name: CreateUser :one
INSERT INTO
    users (username, email, password)
VALUES ($1, $2, $3)
RETURNING
    *;