package utils

import (
	"log"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	log.Printf("Hashing password, %s", password)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	log.Println("Hashed password: ", string(bytes))
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
