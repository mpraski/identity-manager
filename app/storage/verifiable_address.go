package storage

import (
	"errors"
	"time"

	"github.com/google/uuid"
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
