package activation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/mpraski/identity-manager/app/identity"
	"github.com/mpraski/identity-manager/app/storage"
	"gopkg.in/guregu/null.v4"
)

type (
	DefaultActivation struct {
		identityReader     identityReader
		identityWriter     identityWriter
		tokenReader        tokenReader
		tokenWriter        tokenWriter
		addressWriter      addressWriter
		transactionManager transactionManager
	}

	transactionManager interface {
		MustBegin(context.Context) *sqlx.Tx
	}

	identityReader interface {
		Get(context.Context, uuid.UUID) (*identity.Identity, error)
	}

	identityWriter interface {
		Save(context.Context, *sqlx.Tx, *identity.Identity) error
	}

	tokenReader interface {
		GetByValueAndKind(context.Context, string, string) (*identity.Token, error)
	}

	tokenWriter interface {
		Delete(context.Context, *sqlx.Tx, *identity.Token) error
	}

	addressWriter interface {
		Save(context.Context, *sqlx.Tx, *identity.VerifiableAddress) error
	}
)

var (
	ErrInvalidRequest        = errors.New("invalid  request")
	ErrIdentityAlreadyActive = errors.New("identity is already active")
	ErrTokenInvalid          = errors.New("token is invalid")
)

func NewDefaultActivation(
	identityReader identityReader,
	identityWriter identityWriter,
	tokenReader tokenReader,
	tokenWriter tokenWriter,
	addressWriter addressWriter,
	transactionManager transactionManager,
) *DefaultActivation {
	return &DefaultActivation{
		identityReader:     identityReader,
		identityWriter:     identityWriter,
		tokenReader:        tokenReader,
		tokenWriter:        tokenWriter,
		addressWriter:      addressWriter,
		transactionManager: transactionManager,
	}
}

func (a *DefaultActivation) Activate(ctx context.Context, request Request) (*identity.Identity, error) {
	if err := identity.Validate.StructCtx(ctx, request); err != nil {
		return nil, ErrInvalidRequest
	}

	t, err := a.tokenReader.GetByValueAndKind(ctx, request.Token, identity.AddressVerificationToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get token by value: %w", err)
	}

	i, err := a.identityReader.Get(ctx, t.IdentityID)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}

	if i.IsActive() {
		return nil, ErrIdentityAlreadyActive
	}

	var v *identity.VerifiableAddress

	for e := range i.Addresses {
		if i.Addresses[e].ID == t.VerifiableAddressID {
			v = &i.Addresses[e]
			break
		}
	}

	if v == nil {
		return nil, storage.ErrAddressNotFound
	}

	i.State = identity.Active
	i.UpdatedAt = time.Now().UTC()
	v.State = identity.VerificationCompleted
	v.Verified = true
	v.VerifiedAt = null.TimeFrom(time.Now().UTC())
	v.UpdatedAt = time.Now().UTC()

	tx := a.transactionManager.MustBegin(ctx)

	if err := a.identityWriter.Save(ctx, tx, i); err != nil {
		return nil, fmt.Errorf("failed to save identity: %w", err)
	}

	if err := a.addressWriter.Save(ctx, tx, v); err != nil {
		return nil, fmt.Errorf("failed to save address: %w", err)
	}

	if err := a.tokenWriter.Delete(ctx, tx, t); err != nil {
		return nil, fmt.Errorf("failed to delete token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return i, nil
}
