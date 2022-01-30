package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type (
	Credential struct {
		ID         uuid.UUID      `validate:"required" json:"id"`
		IdentityID uuid.UUID      `validate:"required" json:"identity_id"`
		Kind       CredentialKind `validate:"required,oneof=password oidc totp" json:"kind"`
		Secret     Secret         `validate:"required" json:"-"`
		InsertedAt time.Time      `validate:"required" json:"inserted_at"`
		UpdatedAt  time.Time      `validate:"required" json:"updated_at"`
	}

	CredentialKind = string

	Credentials = map[CredentialKind]Credential

	Challenge = map[string]string

	Secret interface {
		Validate(context.Context) error
		Verify(context.Context, Challenge) (bool, error)
	}
)

const (
	// Credentials
	PasswordCredential CredentialKind = "password"
	OIDCCredential     CredentialKind = "oidc"
	TOTPCredential     CredentialKind = "totp"
)

var (
	ErrCredentialMisconfigured   = errors.New("credential is misconfigured")
	ErrPasswordCredentialMissing = errors.New("password credential is missing")
)

func NewCredential(identity uuid.UUID, kind CredentialKind) *Credential {
	return &Credential{
		ID:         uuid.New(),
		IdentityID: identity,
		Kind:       kind,
		InsertedAt: time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
}

func (c *Credential) WithSecret(secret Secret) *Credential {
	c.Secret = secret
	return c
}

func (c *Credential) Validate(ctx context.Context) error {
	return Validate.StructCtx(ctx, c)
}

func (c *Credential) Verify(ctx context.Context, challenge Challenge) (bool, error) {
	if c.Kind == PasswordCredential {
		p, ok := c.Secret.(*PasswordSecret)
		if !ok {
			return false, ErrPasswordCredentialMissing
		}

		if err := p.Validate(ctx); err != nil {
			return false, fmt.Errorf("failed to validate password credential: %w", err)
		}

		return p.Verify(ctx, challenge)
	}

	return false, ErrCredentialMisconfigured
}
