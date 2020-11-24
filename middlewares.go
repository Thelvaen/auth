package auth

import (
	"github.com/Thelvaen/auth/models"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/sessions"
)

// Init exports the middleware function to initialize DB if needed, and populate
// the ctx.User() object at each run.
func Init(config Config) iris.Handler {
	parseConfig(config)

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

// MiddleAuth exports the middleware function to check authentification
func MiddleAuth(ctx iris.Context) {
	session := sessions.Get(ctx)

	userID := session.Get("userID")
	if userID == nil || userID == "NULL" {
		requireAuth(ctx)
		return
	}
	ctx.Next()
}

// MiddleRole check if the user has the required Role
func MiddleRole(role string) iris.Handler {
	return func(ctx iris.Context) {
		session := sessions.Get(ctx)

		userID := session.Get("userID")
		if userID == nil || userID == "NULL" {
			requireAuth(ctx)
			ctx.StopExecution()
			return
		}
		roles, _ := ctx.User().GetRoles()
		if !inArray(role, roles) {
			requireAdm(ctx)
			ctx.StopExecution()
			return
		}
		ctx.Next()
	}
}
