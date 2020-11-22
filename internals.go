package auth

import (
	"reflect"

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
