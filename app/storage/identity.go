package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/mpraski/identity-manager/app/identity"
	"gopkg.in/guregu/null.v4"

	sq "github.com/Masterminds/squirrel"
)

type (
	Identity struct {
		ID         uuid.UUID   `db:"id"`
		State      string      `db:"state"`
		Groups     []string    `db:"groups"`
		Email      null.String `db:"email"`
		Data       []byte      `db:"data"`
		InsertedAt time.Time   `db:"inserted_at"`
		UpdatedAt  time.Time   `db:"updated_at"`
	}

	IdentityReader struct{ db *sqlx.DB }

	IdentityWriter struct{}
)

var (
	ErrIdentityNotFound      = errors.New("identity not found")
	ErrInvalidPasswordSecret = errors.New("invalid password secret")
)

func NewIdentityReader(db *sqlx.DB) *IdentityReader { return &IdentityReader{db: db} }

func (s *IdentityReader) Get(ctx context.Context, id uuid.UUID) (*identity.Identity, error) {
	return s.get(ctx, s.builder().Where(sq.Eq{"id": id.String()}))
}

func (s *IdentityReader) GetByEmail(ctx context.Context, email string) (*identity.Identity, error) {
	return s.get(ctx, s.builder().Where(sq.Eq{"email": email}))
}

func (s *IdentityReader) GetGroups(ctx context.Context, id uuid.UUID) ([]string, error) {
	const query = `select groups from identities where id = ?`

	var groups []string
	if err := s.db.QueryRow(query, id.String()).Scan(&groups); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrIdentityNotFound
		}

		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	return groups, nil
}

func (s *IdentityReader) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	const query = `select exists(id from identities where email = ?)`

	var exists bool
	if err := s.db.QueryRow(query, email).Scan(&exists); err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("failed to execute query: %w", err)
	}

	return exists, nil
}

func (s *IdentityReader) builder() sq.SelectBuilder {
	return sq.Select(
		"id",
		"state",
		"email",
		"groups",
		"inserted_at",
		"updated_at",
	).From("identities")
}

func (s *IdentityReader) get(ctx context.Context, builder sq.SelectBuilder) (*identity.Identity, error) {
	const getAddresses = `
		select
			a.id,
			a.identity_id,
			a.kind,
			a.state,
			a.value,
			a.verified,
			a.verified_at,
			a.inserted_at,
			a.updated_at
		from verifiable_addresses a
		where a.identity_id = ?
	`

	query, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}

	var i Identity
	if err := s.db.GetContext(ctx, &i, query, args...); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrIdentityNotFound
		}

		return nil, fmt.Errorf("failed to get identity: %w", err)
	}

	var va []VerifiableAddress
	if err := s.db.SelectContext(ctx, &va, getAddresses, i.ID.String()); err != nil {
		return nil, fmt.Errorf("failed to get addresses: %w", err)
	}

	return makeIdentity(&i, va)
}

func NewIdentityWriter() *IdentityWriter { return &IdentityWriter{} }

func (w *IdentityWriter) Save(ctx context.Context, tx *sqlx.Tx, i *identity.Identity) error {
	if err := i.Validate(ctx); err != nil {
		return fmt.Errorf("failed to validate identity: %w", err)
	}

	return nil
}

func (w *IdentityWriter) Delete(ctx context.Context, tx *sqlx.Tx, i *identity.Identity) error {
	const query = `delete from identities where id = ?`

	if err := i.Validate(ctx); err != nil {
		return fmt.Errorf("failed to validate identity: %w", err)
	}

	r, err := tx.ExecContext(ctx, query, i.ID)
	if err != nil {
		return fmt.Errorf("failed to execute delete query: %w", err)
	}

	c, err := r.RowsAffected()
	if err != nil {
		return ErrIdentityNotFound
	}

	if c != 1 {
		return ErrIdentityNotFound
	}

	return nil
}
