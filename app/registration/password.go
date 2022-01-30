package registration

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/mpraski/identity-manager/app/courier"
	"github.com/mpraski/identity-manager/app/crypto"
	"github.com/mpraski/identity-manager/app/identity"
)

type (
	PasswordRegistration struct {
		identityReader     identityReader
		identityWriter     identityWriter
		credentialWriter   credentialWriter
		addressWriter      addressWriter
		dataWriter         dataWriter
		transactionManager transactionManager
		sender             courier.Courier
	}

	PasswordRequest struct {
		FirstName string `validate:"required,safe_name" json:"first_name"`
		LastName  string `validate:"required,safe_name" json:"last_name"`
		Email     string `validate:"required,safe_email" json:"email"`
		Password  string `validate:"required,safe_password" json:"password"`
	}

	PasswordActivationRequest struct {
		Token string `validate:"required,len=32" json:"token"`
	}

	transactionManager interface {
		Begin(context.Context) (*sqlx.Tx, error)
	}

	identityReader interface {
		ExistsByEmail(context.Context, string) (bool, error)
	}

	identityWriter interface {
		Save(context.Context, *sqlx.Tx, *identity.Identity) error
	}

	credentialWriter interface {
		Save(context.Context, *sqlx.Tx, *identity.Credential) error
	}

	addressWriter interface {
		Save(context.Context, *sqlx.Tx, *identity.VerifiableAddress) error
	}

	dataWriter interface {
		Save(context.Context, *sqlx.Tx, *identity.Data) error
	}
)

var (
	ErrIdentityExists = errors.New("identity already exists")
	ErrInvalidRequest = errors.New("invalid  request")
)

func NewPasswordRegistration(
	identityReader identityReader,
	identityWriter identityWriter,
	credentialWriter credentialWriter,
	addressWriter addressWriter,
	dataWriter dataWriter,
	transactionManager transactionManager,
	sender courier.Courier,
) *PasswordRegistration {
	return &PasswordRegistration{
		identityReader:     identityReader,
		identityWriter:     identityWriter,
		credentialWriter:   credentialWriter,
		addressWriter:      addressWriter,
		dataWriter:         dataWriter,
		transactionManager: transactionManager,
		sender:             sender,
	}
}

func (r *PasswordRegistration) Register(ctx context.Context, req Request) (*identity.Identity, error) {
	request, ok := req.(*PasswordRequest)
	if !ok {
		return nil, ErrInvalidRequest
	}

	if err := identity.Validate.StructCtx(ctx, request); err != nil {
		return nil, ErrInvalidRequest
	}

	e, err := r.identityReader.ExistsByEmail(ctx, request.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check for existence by email: %w", err)
	}

	if e {
		return nil, ErrIdentityExists
	}

	h, err := crypto.Hash(request.Password, crypto.DefaultArgonParams)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	var (
		i = identity.New().WithEmail(request.Email)
		c = identity.
			NewCredential(identity.PasswordCredential, i.ID).
			WithSecret(identity.NewPasswordSecret(h))
		a = identity.NewVerifiableAddress(
			identity.EmailAddress,
			request.Email,
			i.ID,
		)
		d = identity.NewData(i.ID, nil, &identity.SensitiveData{
			Personal: &identity.PersonalData{
				FirstName: request.FirstName,
				LastName:  request.LastName,
			},
		})
	)

	tx, err := r.transactionManager.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := r.identityWriter.Save(ctx, tx, i); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("failed to save identity: %w", err)
	}

	if err := r.credentialWriter.Save(ctx, tx, c); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	if err := r.addressWriter.Save(ctx, tx, a); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("failed to save address: %w", err)
	}

	if err := r.dataWriter.Save(ctx, tx, d); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("failed to save data: %w", err)
	}

	i = i.
		WithCredential(c).
		WithVerifiableAddress(a).
		WithData(d)

	m := courier.NewMessage(
		courier.IdentityRegistrationTemplate,
		i.Traits.Email,
		courier.Variables{
			"token": a.Token.Value,
		},
	)

	if err := r.sender.Deliver(ctx, m); err != nil {
		return nil, fmt.Errorf("failed to send registration message: %w", err)
	}

	return i, nil
}

func (r *PasswordRegistration) Activate(ctx context.Context, req Request) (*identity.Identity, error) {
	request, ok := req.(*PasswordActivationRequest)
	if !ok {
		return nil, ErrInvalidRequest
	}

	if err := identity.Validate.StructCtx(ctx, request); err != nil {
		return nil, ErrInvalidRequest
	}

	return nil, nil
}
