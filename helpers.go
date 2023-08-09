package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	//"errors"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type SigningMethod int
const(
	SigningMethodES256 SigningMethod = iota
	SigningMethodES384 
	SigningMethodES512 
)

func hashAndSalt(pwd string, cost ...int) (string, error) {
	c := bcrypt.DefaultCost
	if len(cost) > 0 && cost[0] >= bcrypt.MinCost && cost[0] <= bcrypt.MaxCost {
		if cost[0] <= bcrypt.MinCost {
			c = bcrypt.MinCost
		} else if cost[0] > bcrypt.MaxCost {
			c = bcrypt.MaxCost
		} else {
			c = cost[0]
		}
	}
	pwdBytes := []byte(pwd)
	hash, err := bcrypt.GenerateFromPassword(pwdBytes, c)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func newJwtPrivateKey(signingMethod ...SigningMethod) *ecdsa.PrivateKey {
	
	var signMeth SigningMethod = SigningMethodES256
	if len(signingMethod) > 0 {
		signMeth = signingMethod[0]
	}

	var c elliptic.Curve
	
	switch(signMeth) {
	case SigningMethodES256:
		c = elliptic.P256();
	case SigningMethodES384:
		c = elliptic.P384();
	case SigningMethodES512:
		c = elliptic.P521();
	}
	
	pk, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		panic("failed to generate JWT key")
	}
	return pk
}

func JwtPrivateKeyToPem(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: map[string]string{},
		Bytes:   privateKeyBytes,
	})
	return privateKeyPem, nil
}

func jwtPrivateKeyFromPem(pemData []byte) (*ecdsa.PrivateKey, error) {

	// Decode the PEM data to get the block
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("bad format")
	}

	// Parse the ECDSA private key
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("error parsing ECDSA private key")
	}
	return privateKey, err
}

func comparePasswords(hashedPwd, plainPwd string) bool {
	byteHash := []byte(hashedPwd)
	plainPwdBytes := []byte(plainPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwdBytes)
	
	return err == nil
}

func validateJwtTokenAndReadUser[T any](jwtTokenString string, 
	publicKey *ecdsa.PublicKey, currentKID string) (string, *T, error) {
	var  usrClaims userClaims[T]

	token, err := jwt.ParseWithClaims(jwtTokenString, &usrClaims,
		func(token *jwt.Token) (any, error) {
			if usrClaims.KID != currentKID {
				return nil, errors.New("wrong or old key")
			}
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return publicKey, nil
		})
	if err != nil {
		return usrClaims.Subject, &usrClaims.UserData, err
	}
	if !token.Valid {
		return "",nil, errors.New("login expired or token invalid")
	}

	return usrClaims.Subject, &usrClaims.UserData, nil
}

func GetJwtToken[T any](user User[T], maxIdleTime time.Duration, signMethod SigningMethod, privKey *ecdsa.PrivateKey) (string, error) {
	var signingMethod jwt.SigningMethod
	switch signMethod {
	case SigningMethodES256:
		signingMethod = jwt.SigningMethodES256
	case SigningMethodES384:
		signingMethod = jwt.SigningMethodES384
	case SigningMethodES512:
		signingMethod = jwt.SigningMethodES512
	}

	token := jwt.NewWithClaims(signingMethod, userClaims[T] {
		RegisteredClaims: jwt.RegisteredClaims {
			Subject: user.Username,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(maxIdleTime)),
		},
		KID: "1",
		UserData: user.UserData,
	},)

	signedToken, err := token.SignedString(privKey)
	return signedToken, err
}

