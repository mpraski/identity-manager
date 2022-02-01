package storage

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type (
	Token struct {
		ID                  uuid.UUID `db:"id"`
		IdentityID          uuid.UUID `db:"identity_id"`
		VerifiableAddressID uuid.UUID `db:"verifiable_address_id"`
		Kind                string    `db:"kind"`
		Value               string    `db:"value"`
		InsertedAt          time.Time `db:"inserted_at"`
		UpdatedAt           time.Time `db:"updated_at"`
	}

	TokenReader struct{}

	TokenWriter struct{}
)

var (
	ErrTokenNotFound = errors.New("token not found")
)
