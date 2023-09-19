package auth

import (
	"bytes"
	"crypto/ecdsa"
	"embed"
	"fmt"
	"html/template"
	"log"
	"reflect"
	"time"

	//"github.com/jinzhu/copier"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
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
	hashedString, err := hashAndSalt(stringToHash, bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return hashedString
}

type Auth[T any] struct {
	privateKey    *ecdsa.PrivateKey
	signingMethod SigningMethod
	currentKeyId  string
	maxIdleTime   time.Duration
	minIdleTime   time.Duration

	registerHandler func(username, hashedPwd string, userData T) error
	loginHandler    func(username string) (hashedPwd string, userData T, err error)
}

type Config[T any] struct {
	PrivateKey      *ecdsa.PrivateKey
	SigningMethod   SigningMethod
	CurrentKeyId    string
	MaxIdleTime     time.Duration
	MinIdleTime     time.Duration
	RegisterHandler func(username, hashedPwd string, userData T) error
	LoginHandler    func(username string) (hashedPwd string, userData T, err error)
}

func New[T any](config ...Config[T]) Auth[T] {
	a := Auth[T]{

		privateKey:      newJwtPrivateKey(),
		signingMethod:   SigningMethodES256,
		currentKeyId:    "1",
		maxIdleTime:     30 * time.Minute,
		minIdleTime:     10 * time.Minute,
		registerHandler: nil,
		loginHandler:    nil,
	}

	if len(config) > 0 {
		cfg := config[0]
		if cfg.PrivateKey != nil {
			a.privateKey = cfg.PrivateKey
		}
		if cfg.SigningMethod != 0 {
			a.signingMethod = cfg.SigningMethod
		}
		if cfg.CurrentKeyId != "" {
			a.currentKeyId = cfg.CurrentKeyId
		}
		if cfg.MaxIdleTime != 0 {
			a.maxIdleTime = cfg.MaxIdleTime
		}
		if cfg.MinIdleTime != 0 {
			a.minIdleTime = cfg.MinIdleTime
		}
		if cfg.RegisterHandler != nil {
			a.registerHandler = cfg.RegisterHandler
		}
		if cfg.LoginHandler != nil {
			a.loginHandler = cfg.LoginHandler
		}
	}

	return a
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

func (a *Auth[T]) Authenticate(/*loginHandler func(username string) (hashedPwd string, userData T, err error)*/) fiber.Handler {

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
			return a.login(c, a.loginHandler)
		}

		if c.Method() == fiber.MethodGet && c.Path() == "/register" {
			registerHTML, err := content.ReadFile("html/register.html")
			if err != nil {
				return err
			}

			tmpl, err := template.New("dynamic-template").Parse(string(registerHTML))
			if err != nil {
				return c.SendStatus(fiber.StatusInternalServerError)
			}

			var t T
			formType := reflect.TypeOf(t)

			var fieldNames []string
			for i := 0; i < formType.NumField(); i++ {
				field := formType.Field(i)
				fieldNames = append(fieldNames, field.Name)
			}

			var renderedContent bytes.Buffer
			err = tmpl.Execute(&renderedContent, fiber.Map{
				"Fields": fieldNames,
			})
			if err != nil {
				fmt.Println(err)
				return c.SendStatus(fiber.StatusInternalServerError)
			}

			c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
			return c.Send(renderedContent.Bytes())
		}
		if c.Method() == fiber.MethodPost && c.Path() == "/register" {
			log.Println("ONCE")
			return a.register(c, a.registerHandler)
		}

		currentUser := User[T]{Username: "Anon"}

		jwtTokenString := c.Cookies("auth")
		if jwtTokenString != "" {
			token, err := a.ReadToken(jwtTokenString)
			if err != nil {
				currentUser = User[T]{Username: token.Username, UserData: token.UserData}
			} else if time.Since(token.ExpiresAt) < a.maxIdleTime {
				newToken := AuthToken[T]{
					Username:  token.Username,
					IssuedAt:  token.IssuedAt,
					ExpiresAt: time.Now().Add(a.maxIdleTime - a.minIdleTime),
					UserData:  token.UserData,
					Valid:     true,
				}
				tokenAsString, err := a.writeToken(newToken)
				if err == nil {
					c.Cookie(&fiber.Cookie{
						Name:     "auth",
						Value:    tokenAsString,
						Expires:  time.Now().Add(a.maxIdleTime),
						HTTPOnly: true,
					})
					currentUser = User[T]{Username: token.Username, UserData: token.UserData}
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
		return User[T]{Username: "Anon", UserData: anon}
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

	if loginHandler == nil {
		return fiber.ErrNotFound
	}

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

	c.Locals("current_user", User[T]{Username: request.Username, UserData: user})

	token := AuthToken[T]{Username: request.Username, UserData: user, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(a.maxIdleTime - a.minIdleTime)}
	tokenString, err := a.writeToken(token)
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie{
		Name:     "auth",
		Value:    tokenString,
		Expires:  time.Now().Add(a.maxIdleTime),
		HTTPOnly: true,
	})

	return c.SendString(tokenString)
}

func (a *Auth[T]) register(c *fiber.Ctx, registerHandler func(username, hashedPwd string, userData T) error) error {
	
	if registerHandler == nil {
		return fiber.ErrNotFound
	}

	type usernamePwd struct {
		Username string
		Password string
		RepeatPassword string
	}
	
	unpwd := usernamePwd{}
	err := c.BodyParser(&unpwd)
	if err != nil {
		return fiber.ErrBadRequest
	}
	

	username := utils.CopyString(unpwd.Username)
	
	var userdata T 
	err = c.BodyParser(&userdata)
	if err != nil {
		return fiber.ErrBadRequest
	}



	
	var userdataCopy T
	copyFieldsUsingReflection(&userdata, &userdataCopy)
	//err = copier.Copy(&userdataCopy, &userdata)
	//if err != nil {		
	//	return fiber.ErrBadRequest
	//}

	if unpwd.Password != unpwd.RepeatPassword {
		return fiber.ErrBadRequest
	}
	hashedPwd := HashString(unpwd.Password)
	err = registerHandler(username, hashedPwd, userdataCopy)
	if err != nil {
		return fiber.ErrBadRequest
	}

	return c.JSON(userdata)

	/*type registerRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
		UserData *T      `json:"userData"`
	}
	var t T
	userData := &t
	request := registerRequest{
		Username: "",
		Password: "",
		UserData: &t,
	}

	//var request any //loginRequest
	err := c.BodyParser(&request)
	if err != nil {
		return fiber.ErrBadRequest
	}
	hashedPwd := HashString(request.Password)

	return registerHandler(request.Username, hashedPwd, *request.UserData)
	//return nil*/
}


func copyFieldsUsingReflection(source, destination interface{}) {
	sourceValue := reflect.ValueOf(source).Elem()
	destinationValue := reflect.ValueOf(destination).Elem()

	for i := 0; i < sourceValue.NumField(); i++ {
		sourceField := sourceValue.Field(i)
		destinationField := destinationValue.Field(i)

		if destinationField.CanSet() && sourceField.Type() == destinationField.Type() {
			value,ok := sourceField.Interface().(string)
			if ok {
				destinationField.SetString(utils.CopyString(value))
			}

		}
	}
}
