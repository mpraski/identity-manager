package authentication

import (
	"context"

	"github.com/mpraski/identity-manager/app/identity"
)

type (
	Strategy = string

	Challenge = interface{}

	Provider interface {
		Authenticate(context.Context, Challenge) (*identity.Identity, error)
	}
)

const (
	PasswordStrategy Strategy = "password"
)
