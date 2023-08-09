package auth

import (
	"crypto/ecdsa"
	"strings"
	//"crypto/elliptic"
	//"crypto/rand"
	//"crypto/x509"
	//"encoding/pem"
	//"errors"
	"time"

	"github.com/gofiber/fiber/v2"
	//"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func GetNewPrivateKey(signingMethod ...SigningMethod) ([]byte, error) {
	var signMeth SigningMethod = SigningMethodES256
	if len(signingMethod) > 0 {
		signMeth = signingMethod[0]
	}
	
	pk := newJwtPrivateKey(signMeth)
	
	pem, err := JwtPrivateKeyToPem(pk)
	if err != nil {
		return nil, err
	}
	return pem, nil
}

func HashString(stringToHash string) string {
	hashedString, err :=  hashAndSalt(stringToHash, bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return hashedString
}

type Auth[T any] struct {
	privateKey *ecdsa.PrivateKey
	signingMethod SigningMethod
	currentKeyId string
	maxIdleTime time.Duration
	visitors map[string]Visit[T]
}

type Visit[T any] struct {
	user T
	lastVisit time.Time
}

func New[T any]() Auth[T] {
	defaultAuth := Auth[T] {
		privateKey: newJwtPrivateKey(),
		signingMethod: SigningMethodES256,
		currentKeyId: "1",
		maxIdleTime: 20 * time.Minute,
		visitors: make(map[string]Visit[T]),
	}

	return defaultAuth
}

// Todo: Remove second parameter
func (a *Auth[T]) SetPrivateKey(keyPem []byte, signMethod ...SigningMethod) {
	signingMethod := SigningMethodES256
	if len(signMethod) > 0 {
		signingMethod = signMethod[0]
	}
	
	pk, err := jwtPrivateKeyFromPem(keyPem)
	if err != nil {
		panic(err)
	}
	a.privateKey = pk
	a.signingMethod = signingMethod
}

func (a *Auth[T]) SetMaxIdleTime(maxIdleTime time.Duration) {
	a.maxIdleTime = maxIdleTime
}

func (a *Auth[T]) Authenticate(loginHandler func(username string) (hashedPwd string, userData T, err error)) fiber.Handler {

	return func(c *fiber.Ctx) error {
		if c.Method() == fiber.MethodPost && c.Path() == "/login" {
			return a.login(c, loginHandler)
		}
		
		var currentUser T
		
		jwtTokenString := c.Cookies("auth")
		if jwtTokenString != "" {
			username, usr, err := validateJwtTokenAndReadUser[T](jwtTokenString, 
				&a.privateKey.PublicKey, a.currentKeyId)
			if err == nil {
				currentUser = *usr
				c.Locals("current_user", User[T] { Username: username, UserData: currentUser })
				a.visitors[username] = Visit[T] { user: currentUser, lastVisit: time.Now() }
				return c.Next()
			} else if strings.HasPrefix(err.Error(), "token is expired by") {
				lastVisit, ok := a.visitors[username]
				if ok && time.Since(lastVisit.lastVisit) < a.maxIdleTime {
					currentUser = *usr
					signedToken, err := GetJwtToken[T](User[T]{Username: username, UserData: currentUser}, a.maxIdleTime, a.signingMethod, a.privateKey)
					if err == nil {		
						c.Cookie(&fiber.Cookie {
							Name: "auth",
							Value: signedToken,
							Expires: time.Now().Add(a.maxIdleTime + 2 * time.Minute),
							HTTPOnly: true,
						})
					}
				}
			} 
		} 

		c.Locals("current_user", User[T] { Username: "Anon" })
		return c.Next()
	}
}

func (a *Auth[T]) Authorize(acc func(username string, userdata T) bool) fiber.Handler {
	
	return func(c *fiber.Ctx) error {
		currentUser := a.GetCurrentUser(c)
		if acc(currentUser.Username, currentUser.UserData) {
			return c.Next()
		}
		return fiber.ErrForbidden
	}
}

func (a *Auth[T]) GetCurrentUser(c *fiber.Ctx) User[T] {
	usr, ok := c.Locals("current_user").(User[T])
	if !ok {
		var anon T
		return User[T] { Username: "Anon", UserData: anon }
	}
	return usr
}

// ----------------------------------------------------------------------

type User[T any] struct {
	Username string
	UserData T
}

func (a *Auth[T]) login(c *fiber.Ctx, loginHandler func(username string) (hashedPwd string, userData T, err error)) error {

	c.ClearCookie("auth")

	type loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var request loginRequest
	err := c.BodyParser(&request)
	if err != nil {
		return fiber.ErrBadRequest
	}
	
	hashedPwd, user, err := loginHandler(request.Username) //a.LoginHandler(request.Username)
	if err != nil {
		return fiber.ErrUnauthorized
	}

	if !comparePasswords(hashedPwd, request.Password) {
		return fiber.ErrUnauthorized
	}

	c.Locals("current_user", User[T] { Username: request.Username, UserData: user })
	
	//---
	/*var signingMethod jwt.SigningMethod
	switch a.signingMethod {
	case SigningMethodES256:
		signingMethod = jwt.SigningMethodES256
	case SigningMethodES384:
		signingMethod = jwt.SigningMethodES384
	case SigningMethodES512:
		signingMethod = jwt.SigningMethodES512
	}

	token := jwt.NewWithClaims(signingMethod, userClaims[T] {
		RegisteredClaims: jwt.RegisteredClaims {
			Subject: request.Username,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(a.maxIdleTime)),
		},
		KID: "1",
		UserData: user,
	},)

	signedToken, err := token.SignedString(a.privateKey)
	if err != nil {
		return err
	}
	*/
	signedToken, err := GetJwtToken[T](User[T]{Username: request.Username, UserData: user}, a.maxIdleTime, a.signingMethod, a.privateKey)
	if err != nil {
		return err
	}
	// ----

	c.Cookie(&fiber.Cookie {
		Name: "auth",
		Value: signedToken,
		Expires: time.Now().Add(a.maxIdleTime + 2 * time.Minute),
		HTTPOnly: true,
	})

	return c.SendString(signedToken)
}


/*
type Auth[T any] struct {
	privateKey *ecdsa.PrivateKey
	currentKeyId string
	signingMethod jwt.SigningMethod

	OnLogin func(username string) (hashedPwd string, user T, err error)
}

type Config[T any] struct {
	PrivateKeyPem string
	OnLogin	func(username string) (hashedPwd string, user T, err error)
}

func New[T any](config ...Config[T]) Auth[T] {
	cfg := configDefault(config)
	
	var pk *ecdsa.PrivateKey
	var err error

	if cfg.PrivateKeyPem != "" {
		pk, err = jwtPrivateKeyFromPem(cfg.PrivateKeyPem)
	} else {
		pk, err = newJwtPrivateKey(jwt.SigningMethodES256)
	}
	if err != nil {
		panic(err)
	}

	return Auth[T] {
		privateKey: pk,
		currentKeyId: "1",
		signingMethod: jwt.SigningMethodES256,
		OnLogin: cfg.OnLogin,
	}
}

func (a *Auth[T]) Authenticate(anonFactory ...func(c *fiber.Ctx) T) fiber.Handler {

	return func(c *fiber.Ctx) error {
		if c.Method() == fiber.MethodPost && c.Path() == "/login" {
			return a.login(c)
		}

		var currentUser T
		jwtTokenString := c.Cookies("auth")
		if jwtTokenString != "" {
			usr, err := validateJwtTokenAndReadUser[T](jwtTokenString, 
				&a.privateKey.PublicKey, a.currentKeyId)
			if err == nil {
				currentUser = *usr
			} else if len(anonFactory) > 0 {
				currentUser = anonFactory[0](c)
			}
		} else if len(anonFactory) > 0 {
			currentUser = anonFactory[0](c)
		}

		c.Locals("current_user", currentUser)

		return c.Next()
	}
}

func (a *Auth[T]) Authorize(authFunc func(user T) bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		usr := a.GetCurrentUser(c)
		if authFunc(usr) {
			return c.Next()
		}
		return fiber.ErrForbidden
	}
}

func configDefault[T any](config []Config[T]) Config[T] {
	cfg := Config[T] {
		PrivateKeyPem: "",
		OnLogin: nil,
	}

	if len(config) > 0 {
		c := config[0]
		if c.PrivateKeyPem != "" {
			cfg.PrivateKeyPem = c.PrivateKeyPem
		}
		if c.OnLogin != nil {
			cfg.OnLogin = c.OnLogin
		}
	}

	return cfg
}

func (a *Auth[T]) login(c *fiber.Ctx) error {

	c.ClearCookie("auth")

	type loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var request loginRequest
	err := c.BodyParser(&request)
	if err != nil {
		return fiber.ErrBadRequest
	}
	
	hashedPwd, user, err := a.OnLogin(request.Username)
	if err != nil {
		return fiber.ErrUnauthorized
	}

	if !comparePasswords(hashedPwd, request.Password) {
		return fiber.ErrUnauthorized
	}

	c.Locals("current_user", user)
	
	token := jwt.NewWithClaims(a.signingMethod, userClaims[T] {
		RegisteredClaims: jwt.RegisteredClaims {
			Subject: request.Username,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 20)),
		},
		KID: "1",
		UserData: user,
	},)

	signedToken, err := token.SignedString(a.privateKey)
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie {
		Name: "auth",
		Value: signedToken,
		Expires: time.Now().Add(30*time.Minute),
		HTTPOnly: true,
	})

	return c.SendString(signedToken)
}

func (a *Auth[T]) GetCurrentUser(c *fiber.Ctx, anonUser ...T) T {
	usr, ok := c.Locals("current_user").(T)
	if !ok {
		if len(anonUser) > 0 {
			return anonUser[0]
		} else {
			var empty T
			return empty
		}
	}
	return usr
}


func GenerateNewPrivateKey() (string, error) {
	pk, err := newJwtPrivateKey(jwt.SigningMethodES256)
	if err != nil {
		return "", err
	}
	pemKey, err := jwtPrivateKeyToString(pk)
	if err != nil {
		return "", err
	}
	return pemKey, nil
}

func HashPassword(pwd string) (string, error) {
	return hashAndSalt(pwd, bcrypt.MinCost)
}


func newJwtPrivateKey(signingMethod jwt.SigningMethod) (*ecdsa.PrivateKey, error) {
		
	var c elliptic.Curve
	
	switch(signingMethod) {
	case jwt.SigningMethodES256:
		c = elliptic.P256();
	case jwt.SigningMethodES384:
		c = elliptic.P384();
	case jwt.SigningMethodES512:
		c = elliptic.P521();
	}
	
	pk, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, errors.New("failed to generate JWT key")
	}
	return pk, nil
}

func jwtPrivateKeyFromPem(pemString string) (*ecdsa.PrivateKey, error) {
	pemData := []byte(pemString)

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

func jwtPrivateKeyToString(privateKey *ecdsa.PrivateKey) (string, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: map[string]string{},
		Bytes:   privateKeyBytes,
	})
	return string(privateKeyPem), nil
}

func hashAndSalt(pwd string, cost ...int) (string, error) {
	c := bcrypt.DefaultCost
	if len(cost) > 0 && cost[0] >= bcrypt.MinCost && cost[0] <= bcrypt.MaxCost  {
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

func comparePasswords(hashedPwd, plainPwd string) bool {
	byteHash := []byte(hashedPwd)
	plainPwdBytes := []byte(plainPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwdBytes)
	
	return err == nil
}

func validateJwtTokenAndReadUser[T any](jwtTokenString string, 
	publicKey *ecdsa.PublicKey, currentKID string) (*T, error) {
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
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("login expired or token invalid")
	}

	return &usrClaims.UserData, nil
}
*/


