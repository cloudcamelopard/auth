package auth

import (
	"embed"
	"crypto/ecdsa"
	"time"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

//go:embed html/*
var content embed.FS

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
	minIdleTime time.Duration
}

func New[T any]() Auth[T] {
	defaultAuth := Auth[T] {
		

		privateKey: newJwtPrivateKey(),
		signingMethod: SigningMethodES256,
		currentKeyId: "1",
		maxIdleTime: 30 * time.Minute,
		minIdleTime: 10 * time.Minute,
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

func (a *Auth[T]) SetMinIdleTime(minIdleTime time.Duration) {
	a.minIdleTime = minIdleTime
}

func (a *Auth[T]) Authenticate(loginHandler func(username string) (hashedPwd string, userData T, err error)) fiber.Handler {

	return func(c *fiber.Ctx) error {
		if c.Method() == fiber.MethodGet && c.Path() == "/login" {
			loginHTML, err := content.ReadFile("html/login.html")
			if err != nil {
				return err
			}
			c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
			return c.Send(loginHTML)
		}
		if c.Method() == fiber.MethodPost && c.Path() == "/login" {
			return a.login(c, loginHandler)
		}
		
		currentUser := User[T] { Username: "Anon" }
		
		jwtTokenString := c.Cookies("auth")
		if jwtTokenString != "" {
			token, err := a.ReadToken(jwtTokenString)
			if err != nil {
				currentUser = User[T] { Username: token.Username, UserData: token.UserData }
			} else if(time.Since(token.ExpiresAt) < a.maxIdleTime) {
				newToken := AuthToken[T]{
					Username: token.Username,
					IssuedAt: token.IssuedAt,
					ExpiresAt: time.Now().Add(a.maxIdleTime - a.minIdleTime),
					UserData: token.UserData,
					Valid: true,
				}
				tokenAsString,err := a.WriteToken(newToken)
				if err == nil {
					c.Cookie(&fiber.Cookie {
						Name: "auth",
						Value: tokenAsString,
						Expires: time.Now().Add(a.maxIdleTime),
						HTTPOnly: true,
					})
					currentUser = User[T] { Username: token.Username, UserData: token.UserData }
				}
			}
		}
		c.Locals("current_user", currentUser)
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
	
	hashedPwd, user, err := loginHandler(request.Username)
	if err != nil {
		return fiber.ErrUnauthorized
	}

	if !comparePasswords(hashedPwd, request.Password) {
		return fiber.ErrUnauthorized
	}

	c.Locals("current_user", User[T] { Username: request.Username, UserData: user })
	
	token := AuthToken[T] { Username: request.Username, UserData: user, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(a.maxIdleTime - a.minIdleTime), }
	tokenString, err := a.WriteToken(token)
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie {
		Name: "auth",
		Value: tokenString,
		Expires: time.Now().Add(a.maxIdleTime),
		HTTPOnly: true,
	})

	return c.SendString(tokenString)
}