package authentication

import (
	"context"
	"errors"
	"fmt"

	"github.com/mpraski/identity-manager/app/identity"
)

type (
	Password struct {
		reader identityReader
	}

	PasswordChallenge struct {
		Email    string `validate:"required,safe_email" json:"email"`
		Password string `validate:"required,password" json:"password"`
	}

	identityReader interface {
		GetByEmail(context.Context, string) (*identity.Identity, error)
	}
)

var (
	ErrPasswordAuthenticationFailed = errors.New("password authentication failed")
	ErrPasswordChallengeMissing     = errors.New("password challenge is missing")
	ErrPasswordChallengeInvalid     = errors.New("password challenge is invalid")
)

func NewPassword(reader identityReader) *Password {
	return &Password{reader: reader}
}

func (p *Password) Authenticate(ctx context.Context, challenge Challenge) (*identity.Identity, error) {
	r, ok := challenge.(*PasswordChallenge)
	if !ok {
		return nil, ErrPasswordChallengeMissing
	}

	if err := identity.Validate.StructCtx(ctx, r); err != nil {
		return nil, ErrPasswordChallengeInvalid
	}

	i, err := p.reader.GetByEmail(ctx, r.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch identity by email: %w", err)
	}

	if !i.IsActive() {
		return nil, ErrPasswordAuthenticationFailed
	}

	l := identity.Challenge{
		"email":    r.Email,
		"password": r.Password,
	}

	if c, ok := i.GetCredential(ctx, identity.PasswordCredential); ok {
		if ok, err := c.Verify(ctx, l); err == nil && ok {
			return i, nil
		}
	}

	return nil, ErrPasswordAuthenticationFailed
}
