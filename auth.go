package auth

import (
	"github.com/Thelvaen/iris-auth-gorm/models"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	dataStore  *gorm.DB
	loginRoute string
)

// MiddleWare exports the middleware function to check authentification
func MiddleWare(ctx iris.Context) {
	session := sessions.Get(ctx)

	userID := session.Get("userID")
	if userID == nil {
		ctx.Next()
	}
	var user models.User
	if err := dataStore.Where("ID = ?", userID).First(&user).Error; err == nil {
		ctx.SetUser(&user)
	}
	ctx.Next()
}

// SetDB allows the using package to provide us with the DB information
func SetDB(DataStore *gorm.DB) {
	dataStore = DataStore
	dataStore.Migrator().AutoMigrate(&models.User{})
}

// RequireAuthRoute gets the route to call if auth fail
func RequireAuthRoute(login string) {
	loginRoute = login
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
