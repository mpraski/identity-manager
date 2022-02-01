package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/mpraski/identity-manager/app/identity"
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

	TokenReader struct{ db *sqlx.DB }

	TokenWriter struct{}
)

var (
	ErrTokenNotFound = errors.New("token not found")
)

func NewTokenReader(db *sqlx.DB) *TokenReader { return &TokenReader{db: db} }

func (r *TokenReader) GetByValueAndKind(ctx context.Context, value, kind string) (*identity.Token, error) {
	return r.get(ctx, r.builder().Where(sq.Eq{"value": value, "kind": kind}))
}

func (r *TokenReader) builder() sq.SelectBuilder {
	return sq.Select(
		"id",
		"identity_id",
		"verifiable_address_id",
		"kind",
		"value",
		"inserted_at",
		"updated_at",
	).From("tokens")
}

func (r *TokenReader) get(ctx context.Context, builder sq.SelectBuilder) (*identity.Token, error) {
	query, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}

	var t Token
	if err = r.db.GetContext(ctx, &t, query, args...); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrTokenNotFound
		}

		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return &identity.Token{
		ID:                  t.ID,
		IdentityID:          t.IdentityID,
		VerifiableAddressID: t.ID,
		Kind:                t.Kind,
		Value:               t.Value,
		InsertedAt:          t.InsertedAt,
		UpdatedAt:           t.UpdatedAt,
	}, nil
}

func NewTokenWriter() *TokenWriter { return &TokenWriter{} }

func (w *TokenWriter) Delete(ctx context.Context, tx *sqlx.Tx, t *identity.Token) error {
	const query = `delete from tokens where id = ?`

	if err := t.Validate(ctx); err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}

	r, err := tx.ExecContext(ctx, query, t.ID)
	if err != nil {
		return fmt.Errorf("failed to execute delete query: %w", err)
	}

	c, err := r.RowsAffected()
	if err != nil {
		return ErrTokenNotFound
	}

	if c != 1 {
		return ErrTokenNotFound
	}

	return nil
}
