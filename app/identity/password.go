package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/mpraski/identity-manager/app/crypto"
)

type PasswordSecret struct {
	hash []byte `validate:"required,len>0" json:"-"`
}

var ErrPasswordMissing = errors.New("password is missing")

func NewPasswordSecret(hash []byte) *PasswordSecret {
	return &PasswordSecret{hash: hash}
}

func (p *PasswordSecret) Validate(ctx context.Context) error {
	return Validate.StructCtx(ctx, p)
}

func (p *PasswordSecret) Verify(_ context.Context, challenge Challenge) (bool, error) {
	h, ok := challenge["password"]
	if !ok {
		return false, ErrPasswordMissing
	}

	if h == "" {
		return false, ErrPasswordMissing
	}

	o, err := crypto.CompareHash(h, string(p.hash))
	if err != nil {
		return false, fmt.Errorf("failed to compare hashes: %w", err)
	}

	return o, nil
}
