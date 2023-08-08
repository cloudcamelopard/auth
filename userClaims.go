package auth

import "github.com/golang-jwt/jwt/v4"

type userClaims[T any] struct {
	jwt.RegisteredClaims
	KID    string
	UserData T
}