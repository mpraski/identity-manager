package identity

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/mpraski/identity-manager/app/crypto"
)

type (
	Token struct {
		ID                  uuid.UUID `validate:"required" json:"id"`
		IdentityID          uuid.UUID `validate:"required" json:"identity_id"`
		VerifiableAddressID uuid.UUID `validate:"required" json:"verifiable_address_id"`
		Kind                TokenKind `validate:"required,oneof=address_verification" json:"kind"`
		Value               string    `validate:"required,safe_token" json:"-"`
		InsertedAt          time.Time `validate:"required" json:"inserted_at"`
		UpdatedAt           time.Time `validate:"required" json:"updated_at"`
	}

	TokenKind = string
)

const (
	// Kind
	AddressVerificationToken TokenKind = "address_verification"
)

func NewToken(kind TokenKind) *Token {
	return &Token{
		ID:         uuid.New(),
		Kind:       kind,
		Value:      crypto.RandomString(),
		InsertedAt: time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
}

func (t *Token) WithAddressID(addressID uuid.UUID) *Token {
	t.VerifiableAddressID = addressID
	return t
}

func (t *Token) Validate(ctx context.Context) error {
	return Validate.StructCtx(ctx, t)
}
