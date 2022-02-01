package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/mpraski/identity-manager/app/identity"
	"gopkg.in/guregu/null.v4"
)

type (
	VerifiableAddress struct {
		ID         uuid.UUID `db:"id"`
		IdentityID uuid.UUID `db:"identity_id"`
		Kind       string    `db:"kind"`
		State      string    `db:"state"`
		Value      string    `db:"value"`
		Verified   bool      `db:"verified"`
		VerifiedAt null.Time `db:"verified_at"`
		InsertedAt time.Time `db:"inserted_at"`
		UpdatedAt  time.Time `db:"updated_at"`
	}

	AddressReader struct{}

	AddressWriter struct{}
)

var (
	ErrAddressNotFound = errors.New("address not found")
)

func NewAddressWriter() *AddressWriter { return &AddressWriter{} }

func (w *AddressWriter) Save(ctx context.Context, tx *sqlx.Tx, a *identity.VerifiableAddress) error {
	const query = `
		insert into verifiable_addresses (id, identity_id, kind, state, value, verified, verified_at, inserted_at, updated_at)
			values(:id, :identity_id, :kind, :state, :value, :verified, :verified_at, :inserted_at, :updated_at) 
		on conflict (identity_id) do
			update set kind = :kind,
				state = :state,
				value = :value,
				verified = :verified,
				verified_at = :verified_at,
				updated_at = :updated_at;
		`

	if err := a.Validate(ctx); err != nil {
		return fmt.Errorf("failed to validate address: %w", err)
	}

	address := VerifiableAddress{
		ID:         a.ID,
		IdentityID: a.IdentityID,
		Kind:       a.Kind,
		State:      a.State,
		Value:      a.Value,
		Verified:   a.Verified,
		VerifiedAt: a.VerifiedAt,
		InsertedAt: a.InsertedAt,
		UpdatedAt:  a.UpdatedAt,
	}

	if _, err := tx.NamedExecContext(ctx, query, address); err != nil {
		return fmt.Errorf("failed to save address: %w", err)
	}

	return nil
}
