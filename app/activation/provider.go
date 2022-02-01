package activation

import (
	"context"

	"github.com/mpraski/identity-manager/app/identity"
)

type (
	Provider interface {
		Activate(context.Context, Request) (*identity.Identity, error)
	}

	Request struct {
		Token string `validate:"required,safe_token" json:"token"`
	}
)
