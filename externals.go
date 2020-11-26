package auth

import (
	"encoding/base64"
	"encoding/json"

	"github.com/Thelvaen/auth/models"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Config struct allows the configuration to be passed to the function at init
type Config struct {
	DataStore     *gorm.DB
	LoginRoute    string
	ReturnOnError bool
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

// HasRole verify if the user has the requested Role
func HasRole(ctx iris.Context, role string) bool {
	session := sessions.Get(ctx)

	userID := session.Get("userID")
	if userID == nil || userID == "NULL" {
		return false
	}
	roles, _ := ctx.User().GetRoles()
	if !inArray(role, roles) {
		return false
	}
	return true
}

// CreateUser allow to store a user in the DB
func CreateUser(user models.User) (token string, id uuid.UUID) {

	// Generate Token
	var ttoken map[string]string
	ttoken = make(map[string]string)
	ttoken["password"] = string(base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)))
	user.Token, _ = json.Marshal(ttoken)
	dataStore.Create(&user)
	return ttoken["password"], user.ID
}
