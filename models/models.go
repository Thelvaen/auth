package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kataras/iris/v12/context"
	"gorm.io/gorm"
)

// User structure made exportable to be used with Gorm ORM
type User struct {
	gorm.Model
	Username      string                 `gorm:"not null;unique" form:"username" json:"username,omitempty"`
	Password      string                 `gorm:"not null" form:"password" json:"-"`
	Email         string                 `gorm:"not null;unique" json:"email,omitempty"`
	Roles         MultiString            `gorm:"type:text" json:"roles,omitempty"`
	Authorization string                 `json:"authorization,omitempty"`
	AuthorizedAt  time.Time              `json:"authorized_at,omitempty"`
	Token         json.RawMessage        `gorm:"type:json" json:"token,omitempty"`
	Fields        map[string]interface{} `gorm:"-" json:"fields,omitempty"`
}

var _ context.User = (*User)(nil)

// GetAuthorization returns the authorization method,
// e.g. Basic Authentication.
func (u *User) GetAuthorization() (string, error) {
	return u.Authorization, nil
}

// GetAuthorizedAt returns the exact time the
// client has been authorized for the "first" time.
func (u *User) GetAuthorizedAt() (time.Time, error) {
	return u.AuthorizedAt, nil
}

// GetID returns the ID of the User.
func (u *User) GetID() (string, error) {
	return strconv.Itoa(int(u.ID)), nil
}

// GetUsername returns the name of the User.
func (u *User) GetUsername() (string, error) {
	return u.Username, nil
}

// GetPassword returns the raw password of the User.
func (u *User) GetPassword() (string, error) {
	return u.Password, nil
}

// GetEmail returns the e-mail of (string,error) User.
func (u *User) GetEmail() (string, error) {
	return u.Email, nil
}

// GetRoles returns the specific user's roles.
// Returns with `ErrNotSupported` if the Roles field is not initialized.
func (u *User) GetRoles() ([]string, error) {
	if u.Roles == nil {
		return nil, context.ErrNotSupported
	}

	return u.Roles, nil
}

// GetToken returns the token associated with this User.
// It may return empty if the User is not featured with a Token.
//
// The implementation can change that behavior.
// Returns with `ErrNotSupported` if the Token field is empty.
func (u *User) GetToken() ([]byte, error) {
	if len(u.Token) == 0 {
		return nil, context.ErrNotSupported
	}

	return u.Token, nil
}

// GetField optionally returns a dynamic field from the `Fields` field
// based on its key.
func (u *User) GetField(key string) (interface{}, error) {
	if u.Fields == nil {
		return nil, context.ErrNotSupported
	}

	return u.Fields[key], nil
}

type MultiString []string

func (s *MultiString) Scan(src interface{}) error {
	var bytes []byte
	switch v := src.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", src))
	}
	result := MultiString{}
	err := json.Unmarshal(bytes, &result)
	*s = result
	return err
}

func (s MultiString) Value() (driver.Value, error) {
	if s == nil || len(s) == 0 {
		return nil, nil
	}
	data, _ := json.Marshal(s)
	return data, nil
}
