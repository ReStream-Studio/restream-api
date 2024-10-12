package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"net/http"
	"net/mail"
	"os"

	"github.com/ReStream-Studio/restream-api/db/generated/user"
	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ReStream-Studio/restream-api/utils"
)

func coolJSON(object interface{}) string {
	jsonBytes, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return string(jsonBytes)
}

func main() {

	app := fiber.New()

	app.Get("/", func(c fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	v1 := app.Group("/v1")
	auth := v1.Group("/auth")
	auth.Post("/register", register)
	auth.Post("/login", login)
	log.Fatal(app.Listen(":3000"))
}

func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func register(c fiber.Ctx) error {
	if c.Method() != http.MethodPost {
		return c.Status(405).JSON(fiber.Map{"message": "Method not allowed"})
	}

	creds := new(Credentials)
	if err := c.Bind().Body(creds); err != nil {
		return err
	}

	email := creds.Email
	password := creds.Password

	if creds.Email == "" || creds.Password == "" {
		return c.Status(400).JSON(fiber.Map{"message": "Missing email or password"})
	}

	if !validateEmail(email) {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid email"})
	}

	ctx := context.Background()
	dbConnectionString := "postgres://postgres:postgres@localhost:5432/postgres"
	conn, err := pgx.Connect(ctx, dbConnectionString)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	queries := user.New(conn)

	_, err = queries.GetUser(ctx, email)

	if err == nil {
		return c.Status(400).JSON(fiber.Map{"message": "User already exists"})
	}

	hashed, err := utils.HashPassword(password)

	if err != nil {
		log.Fatal(err)
	}

	queries.CreateUser(ctx, user.CreateUserParams{
		Email:    email,
		Password: pgtype.Text{String: hashed, Valid: true},
	})

	return c.Status(200).JSON(fiber.Map{"message": "User created"})
}

func login(c fiber.Ctx) error {
	if c.Method() != http.MethodPost {
		return c.Status(405).JSON(fiber.Map{"message": "Method not allowed"})
	}

	creds := new(Credentials)
	if err := c.Bind().Body(creds); err != nil {
		return err
	}

	email := creds.Email
	password := creds.Password

	if creds.Email == "" || creds.Password == "" {
		return c.Status(400).JSON(fiber.Map{"message": "Missing email or password"})
	}

	if !validateEmail(email) {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid email"})
	}

	ctx := context.Background()
	dbConnectionString := "postgres://postgres:postgres@localhost:5432/postgres"
	conn, err := pgx.Connect(ctx, dbConnectionString)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	queries := user.New(conn)

	user, err := queries.GetUser(ctx, email)

	if !utils.CheckPasswordHash(password, user.Password.String) {
		return c.Status(401).JSON(fiber.Map{"message": "Invalid credentials"})
	}

	return c.Status(200).JSON(fiber.Map{"message": "Login successful"})
}
