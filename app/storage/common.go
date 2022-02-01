package storage

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/mpraski/identity-manager/app/identity"

	// The postgresql connector
	_ "github.com/lib/pq"
)

type TransactionManager struct{ db *sqlx.DB }

func NewTransactionManager(db *sqlx.DB) *TransactionManager {
	return &TransactionManager{db: db}
}

func (t *TransactionManager) MustBegin(ctx context.Context) *sqlx.Tx {
	return t.db.MustBeginTx(ctx, nil)
}

func makeIdentity(
	i *Identity,
	va []VerifiableAddress,
) (*identity.Identity, error) {
	addresses := make([]identity.VerifiableAddress, 0, len(va))

	for i := range va {
		v := &va[i]

		addresses = append(addresses, identity.VerifiableAddress{
			ID:         v.ID,
			IdentityID: v.IdentityID,
			Kind:       v.Kind,
			State:      v.State,
			Value:      v.Value,
			Verified:   v.Verified,
			VerifiedAt: v.VerifiedAt,
			InsertedAt: v.InsertedAt,
			UpdatedAt:  v.UpdatedAt,
		})
	}

	return &identity.Identity{
		ID:          i.ID,
		State:       i.State,
		Groups:      i.Groups,
		Traits:      identity.Traits{Email: i.Email},
		Addresses:   addresses,
		Credentials: make(identity.Credentials),
		InsertedAt:  i.InsertedAt,
		UpdatedAt:   i.UpdatedAt,
	}, nil
}
