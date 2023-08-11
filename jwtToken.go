package auth

import (
	//"crypto/ecdsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AuthToken[T any] struct {
	Username string
	IssuedAt time.Time
	ExpiresAt time.Time
	UserData T
	Valid bool
}

// HARDCODE SIGNINGMETHOD
func(a *Auth[T]) WriteToken(token AuthToken[T]) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, userClaims[T] {
		RegisteredClaims: jwt.RegisteredClaims {
			Subject: token.Username,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(token.ExpiresAt),
		},
		UserData: token.UserData,
	},)
	signedToken, err := tok.SignedString(a.privateKey)
	return signedToken, err
}



func(a *Auth[T]) ReadToken(tokenString string) (AuthToken[T], error) {
		var  usrClaims userClaims[T]
	
		token, err := jwt.ParseWithClaims(tokenString, &usrClaims,
			func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, errors.New("unexpected signing method")
				}
				return a.privateKey.PublicKey, nil
			},
		)
		tok := AuthToken[T] { usrClaims.Subject, time.Time(usrClaims.IssuedAt.Time), time.Time(usrClaims.ExpiresAt.Time), usrClaims.UserData, token.Valid, }
		return tok, err
}