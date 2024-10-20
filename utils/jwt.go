package utils

import (
	"fmt"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

var (
	key   []byte
	token *jwt.Token
)

func GenerateJWT() (string, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	key = []byte(os.Getenv("JWT_SECRET"))
	token = jwt.New(jwt.SigningMethodHS256)
	str, err := token.SignedString(key)

	if err != nil {
		return "", err
	}

	return str, err
}

func DecodeJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}
