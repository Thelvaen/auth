package auth

import (
	"log"
	"reflect"

	"github.com/Thelvaen/iris-auth-gorm/models"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	dataStore     *gorm.DB
	loginRoute    string
	returnOnError bool
)

// Config struct allows the configuration to be passed to the function at init
type Config struct {
	DataStore     *gorm.DB
	LoginRoute    string
	ReturnOnError bool
}

// MiddleWare exports the middleware function to check authentification
func MiddleWare(config Config) iris.Handler {
	// check if DB backend has been provided, will die if not
	if config.DataStore == nil {
		log.Fatalf("no DB provided to AuthMiddleware")
	}
	dataStore = config.DataStore

	// check if default login route has been provided, assumes /login if not
	if config.LoginRoute == "" {
		loginRoute = config.LoginRoute
	} else {
		loginRoute = "/login"
	}

	if config.ReturnOnError {
		returnOnError = true
	}

	return func(ctx iris.Context) {
		session := sessions.Get(ctx)

		userID := session.Get("userID")
		if userID == nil || userID == "NULL" {
			ctx.Next()
		}
		var user models.User
		if err := dataStore.Where("ID = ?", userID).First(&user).Error; err == nil {
			ctx.SetUser(&user)
		}
		ctx.Next()
	}
}

// Check verifies the provided user against the DB
func Check(user models.User, ctx iris.Context) {
	session := sessions.Get(ctx)

	clearPassword := user.Password
	if err := dataStore.Where("Username = ?", user.Username).First(&user).Error; err != nil {
		ctx.Redirect(loginRoute, iris.StatusFound)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(clearPassword)); err != nil {
		ctx.Redirect(loginRoute, iris.StatusFound)
		return
	}
	session.Set("userID", user.ID)
	callback := ctx.URLParamDefault("callback_url", "/")
	ctx.Redirect(callback, iris.StatusFound)
	return
}

// IsAuth returns true if User has been authenticated
func IsAuth(ctx iris.Context) bool {
	if ctx.User() != nil {
		return true
	}
	return false
}

// IsAdmin returns true if User has been authenticated
func IsAdmin(ctx iris.Context) bool {
	if ctx.User() == nil {
		return false
	}
	roles, _ := ctx.User().GetRoles()
	if !inArray("admin", roles) {
		return false
	}
	return true
}

func inArray(needle interface{}, haystack interface{}) (exists bool) {
	exists = false

	switch reflect.TypeOf(haystack).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(haystack)
		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(needle, s.Index(i).Interface()) == true {
				exists = true
				return
			}
		}
	}
	return
}

// MiddleAuth exports the middleware function to check authentification
func MiddleAuth(ctx iris.Context) {
	session := sessions.Get(ctx)

	userID := session.Get("userID")
	if userID == nil || userID == "NULL" {
		requireAuth(ctx)
	}
	ctx.Next()
}

// MiddleAdmin exports the middleware function to check authentification
func MiddleAdmin(ctx iris.Context) {
	session := sessions.Get(ctx)

	userID := session.Get("userID")
	if userID == nil || userID == "NULL" {
		requireAuth(ctx)
	}
	roles, _ := ctx.User().GetRoles()
	if !inArray("admin", roles) {
		requireAuth(ctx)
	}
	ctx.Next()
}

func requireAuth(ctx iris.Context) {
	if returnOnError {
		ctx.Redirect(loginRoute, iris.StatusPermanentRedirect)
		ctx.StopExecution()
	}
	ctx.StatusCode(401)
	ctx.WriteString("Not Authorized")
	ctx.StopExecution()
}
