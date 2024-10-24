package utils

import (
	"fmt"
	"log"
	"os"
	"time"

	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

var (
	key            []byte
	token          *jwt.Token
	expirationTime time.Time
)

var (
	TimeFifteenMinutes = time.Now().Add(15 * time.Minute)
	TimeOneMonth       = time.Now().Add(30 * 24 * time.Hour)
)

func GenerateJWT(tokenType string) (string, error) {
	if tokenType == "access" {
		expirationTime = TimeFifteenMinutes
	} else if tokenType == "refresh" {
		expirationTime = TimeOneMonth
	}

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	key = []byte(os.Getenv("JWT_SECRET"))
	token = jwt.New(jwt.SigningMethodHS256)

	token.Claims = jwt.MapClaims{
		"exp": expirationTime,
	}

	str, err := token.SignedString(key)

	if err != nil {
		return "", err
	}

	return str, err
}

type CustomClaims struct {
	Exp string `json:"exp"`
	jwt.RegisteredClaims
}

func ValidateJWT(tokenStr string) (interface{}, error) {
	log.Printf("Validating token: %s", tokenStr)

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		log.Printf("Error validating token: %s", err)
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, errors.New("invalid type for claims")
	}
	exp, err := time.Parse(time.RFC3339, claims.Exp)
    if err != nil {
        return nil, err
    }

	log.Printf("exp: %s", exp)
    if exp.Before(time.Now()) {
        return nil, errors.New("token expired")
    }

	return token.Valid, nil
}
