package auth

import (
	"bytes"
	"encoding/json"
	"log"
	"net/smtp"
	"reflect"
	"text/template"

	"github.com/Thelvaen/iris-auth-gorm/models"
	"github.com/kataras/iris/v12"
	"gorm.io/gorm"
)

var (
	dataStore     *gorm.DB
	loginRoute    string
	returnOnError bool
	mailServer    SMTP
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

	if config.MailServer.Host != "" {
		mailServer.Host = config.MailServer.Host
	}
	if config.MailServer.Port != "" {
		mailServer.Port = config.MailServer.Port
	}
	if config.MailServer.Username != "" {
		mailServer.Username = config.MailServer.Username
	}
	if config.MailServer.Password != "" {
		mailServer.Password = config.MailServer.Password
	}
	if config.MailServer.Template != "" {
		mailServer.Template = config.MailServer.Template
	}
}

type mailVars struct {
	User  string
	Token string
}

type tokenStruct struct {
	Token string `json:"password"`
}

func sendMail(user models.User) {
	// Sender data.
	var from string
	if mailServer.Username != "" {
		from = "<" + mailServer.Username + ">"
	} else {
		from = "no-reply@twitchbot.domain"
	}

	// Receiver email address.
	to := []string{
		user.Email,
	}

	// Using template to process mail
	t := template.Must(template.New("mailTemplate").Parse(string(mailServer.Template)))
	newToken := tokenStruct{}
	json.Unmarshal(user.Token, &newToken)

	mail := mailVars{
		User:  user.Username,
		Token: newToken.Token,
	}
	message := new(bytes.Buffer)

	err := t.Execute(message, mail)
	if err != nil {
		log.Println("executing template:", err)
	}

	// Authentication.
	auth := smtp.PlainAuth("", mailServer.Username, mailServer.Password, mailServer.Host)

	// Sending email.
	err = smtp.SendMail(mailServer.Host+":"+mailServer.Port, auth, from, to, message.Bytes())
	if err != nil {
		// Process error here
		return
	}
}
