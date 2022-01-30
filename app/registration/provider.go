package registration

import (
	"context"

	"github.com/mpraski/identity-manager/app/identity"
)

type (
	Provider interface {
		Register(context.Context, Request) (*identity.Identity, error)
		Activate(context.Context, Request) (*identity.Identity, error)
	}

	Request = interface{}
)
