package auth

import (
	"log"
	"reflect"

	"github.com/Thelvaen/iris-auth-gorm/models"
	"github.com/kataras/iris/v12"
	"gorm.io/gorm"
)

var (
	dataStore     *gorm.DB
	loginRoute    string
	returnOnError bool
)

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

func requireAuth(ctx iris.Context) {
	if returnOnError {
		ctx.Redirect(loginRoute+"?callback_url="+ctx.Request().RequestURI, iris.StatusTemporaryRedirect)
		ctx.StopExecution()
	}
	ctx.StatusCode(401)
	ctx.WriteString("Not Authorized")
	ctx.StopExecution()
}

func requireAdm(ctx iris.Context) {
	ctx.StatusCode(401)
	ctx.WriteString("Not Authorized")
	ctx.StopExecution()
}

func migrate() {
	dataStore.Migrator().AutoMigrate(&models.User{})
}

func parseConfig(config Config) {
	// check if DB backend has been provided, will die if not
	if config.DataStore == nil {
		log.Fatalf("no DB provided to AuthMiddleware")
	}
	dataStore = config.DataStore

	if !dataStore.Migrator().HasTable("users") {
		migrate()
	}

	// check if default login route has been provided, assumes /login if not
	if config.LoginRoute == "" {
		loginRoute = config.LoginRoute
	} else {
		loginRoute = "/login"
	}

	if config.ReturnOnError {
		returnOnError = true
	}
}
