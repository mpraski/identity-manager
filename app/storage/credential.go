package storage

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

type (
	Credential struct {
		ID           uuid.UUID `db:"id"`
		IdentityID   uuid.UUID `db:"identity_id"`
		Kind         string    `db:"kind"`
		PasswordHash []byte    `db:"password_hash"`
		InsertedAt   time.Time `db:"inserted_at"`
		UpdatedAt    time.Time `db:"updated_at"`
	}

	CredentialReader struct{}

	CredentialWriter struct{}
)

var (
	ErrCredentialNotFound = errors.New("credential not found")
)
