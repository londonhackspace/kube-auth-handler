package auth

import "errors"

type User struct {
	Uid      int
	Name     string
	Username string
	Groups   []string
}

type Auth interface {
	AuthenticateUser(username string, password string) (*User, error)
}

var (
	ServerError = errors.New("could not contact server")
	AuthError   = errors.New("could not authenticate user")
)
