package authentication

import (
	"context"

	"github.com/mpraski/identity-manager/app/identity"
)

type (
	Provider interface {
		Authenticate(context.Context, Challenge) (*identity.Identity, error)
	}

	Challenge = interface{}

	Strategy = string
)

const (
	PasswordStrategy Strategy = "password"
)
