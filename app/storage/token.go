package storage

import (
	"time"

	"github.com/google/uuid"
)

type (
	Token struct {
		ID         uuid.UUID `db:"id"`
		IdentityID uuid.UUID `db:"identity_id"`
		Kind       string    `db:"kind"`
		Value      string    `db:"value"`
		InsertedAt time.Time `db:"inserted_at"`
		UpdatedAt  time.Time `db:"updated_at"`
	}

	TokenReader struct{}

	TokenWriter struct{}
)
