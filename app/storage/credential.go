package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/mpraski/identity-manager/app/identity"
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

	CredentialWriter struct{}
)

var (
	ErrCredentialNotFound        = errors.New("credential not found")
	ErrPasswordCredentialMissing = errors.New("password credential is missing")
)

func NewCredentialWriter() *CredentialWriter { return &CredentialWriter{} }

func (w *CredentialWriter) Save(ctx context.Context, tx *sqlx.Tx, c *identity.Credential) error {
	const query = `
		insert into credentials (id, identity_id, kind, password_hash, inserted_at, updated_at)
			values(:id, :identity_id, :kind, :password_hash, :inserted_at, :updated_at) 
		on conflict (identity_id) do
			update set kind = :kind, password_hash = :password_hash, updated_at = :updated_at;
		`

	if err := c.Validate(ctx); err != nil {
		return fmt.Errorf("failed to validate credential: %w", err)
	}

	credential := Credential{
		ID:         c.ID,
		IdentityID: c.IdentityID,
		Kind:       c.Kind,
		InsertedAt: c.InsertedAt,
		UpdatedAt:  c.UpdatedAt,
	}

	if c.Kind == identity.PasswordCredential {
		p, ok := c.Secret.(*identity.PasswordSecret)
		if !ok {
			return ErrPasswordCredentialMissing
		}

		if err := p.Validate(ctx); err != nil {
			return fmt.Errorf("failed to validate password credential: %w", err)
		}

		credential.PasswordHash = p.Hash()
	}

	if _, err := tx.NamedExecContext(ctx, query, credential); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	return nil
}
