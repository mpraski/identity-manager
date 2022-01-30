package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/mpraski/identity-manager/app/crypto"
	"github.com/mpraski/identity-manager/app/identity"
)

type (
	Data struct {
		ID         uuid.UUID `db:"id"`
		IdentityID uuid.UUID `db:"identity_id"`
		Public     []byte    `db:"public"`
		Sensitive  []byte    `db:"sensitive"`
	}

	DataReader struct {
		db  *sqlx.DB
		aes *crypto.AES
	}

	DataWriter struct{ aes *crypto.AES }
)

var ErrIncompleteData = errors.New("identity data is incomplete")

func (s *DataReader) Get(ctx context.Context, id uuid.UUID) (*identity.Data, error) {
	return s.get(ctx, s.builder().Where(sq.Eq{"id": id.String()}))
}

func (s *DataReader) GetByIdentity(ctx context.Context, identityID uuid.UUID) (*identity.Data, error) {
	return s.get(ctx, s.builder().Where(sq.Eq{"identity_id": identityID.String()}))
}

func (s *DataReader) builder() sq.SelectBuilder {
	return sq.Select(
		"id",
		"identity_id",
		"public",
		"sensitive",
	).From("identities_data")
}

func (s *DataReader) get(ctx context.Context, builder sq.SelectBuilder) (*identity.Data, error) {
	query, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("failed to build sql: %w", err)
	}

	var d Data
	if err = s.db.GetContext(ctx, &d, query, args...); err != nil {
		return nil, fmt.Errorf("failed to get identity data: %w", err)
	}

	if d.Public == nil || d.Sensitive == nil {
		return nil, ErrIncompleteData
	}

	var p *identity.PublicData
	if err = json.NewDecoder(bytes.NewReader(d.Public)).Decode(p); err != nil {
		return nil, fmt.Errorf("failed to decode public data: %w", err)
	}

	var c *identity.SensitiveData

	b, err := s.aes.Decrypt(d.Sensitive)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt sensitive data: %w", err)
	}

	if err := json.NewDecoder(bytes.NewReader(b)).Decode(c); err != nil {
		return nil, fmt.Errorf("failed to decode sensitive data: %w", err)
	}

	return &identity.Data{
		ID:         d.ID,
		IdentityID: d.IdentityID,
		Public:     p,
		Sensitive:  c,
	}, nil
}

func (w *DataWriter) Save(ctx context.Context, tx *sqlx.Tx, d *identity.Data) error {
	const query = `
		insert into identities_data (id, identity_id, public, sensitive)
			values(:id, :identity_id, :public, :sensitive) 
		on conflict (identity_id) do
			update set public = :public, sensitive = :sensitive;
		`

	if err := d.Validate(ctx); err != nil {
		return fmt.Errorf("failed to validate identity data: %w", err)
	}

	var (
		p = new(bytes.Buffer)
		c = new(bytes.Buffer)
	)

	if err := json.NewEncoder(p).Encode(d.Public); err != nil {
		return fmt.Errorf("failed to encode public data: %w", err)
	}

	if err := json.NewEncoder(p).Encode(d.Public); err != nil {
		return fmt.Errorf("failed to encode sensitive data: %w", err)
	}

	b, err := w.aes.Encrypt(c.Bytes())
	if err != nil {
		return fmt.Errorf("failed to encrypt sensitive data: %w", err)
	}

	data := Data{
		ID:         d.ID,
		IdentityID: d.IdentityID,
		Public:     p.Bytes(),
		Sensitive:  b,
	}

	if _, err := tx.NamedExecContext(ctx, query, data); err != nil {
		return fmt.Errorf("failed to save identity data: %w", err)
	}

	return nil
}
