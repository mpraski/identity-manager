package identity

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gopkg.in/guregu/null.v4"
)

type (
	VerifiableAddress struct {
		ID         uuid.UUID             `validate:"required" json:"id"`
		IdentityID uuid.UUID             `validate:"required" json:"identity_id"`
		Kind       VerifiableAddressKind `validate:"required,oneof=email phone" json:"kind"`
		State      VerificationState     `validate:"required,oneof=pending completed" json:"state"`
		Token      *Token                `json:"-"`
		Value      string                `validate:"required,min=4,max=255" json:"value"`
		Verified   bool                  `validate:"required" json:"verified"`
		VerifiedAt null.Time             `validate:"past_date" json:"verified_at"`
		InsertedAt time.Time             `validate:"required,past_date" json:"inserted_at"`
		UpdatedAt  time.Time             `validate:"required,past_date" json:"updated_at"`
	}

	VerifiableAddressKind = string

	VerificationState = string
)

const (
	// Kind
	EmailAddress VerifiableAddressKind = "email"
	PhoneAddress VerifiableAddressKind = "phone"
	// State
	VerificationPending   VerificationState = "pending"
	VerificationCompleted VerificationState = "completed"
)

func NewVerifiableAddress(
	identityID uuid.UUID,
	kind VerifiableAddressKind,
	value string,
) *VerifiableAddress {
	id := uuid.New()

	return &VerifiableAddress{
		ID:         id,
		IdentityID: identityID,
		Kind:       kind,
		State:      VerificationPending,
		Token:      NewToken(identityID, AddressVerificationToken).WithAddressID(id),
		Value:      value,
		InsertedAt: time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
}

func (a *VerifiableAddress) Validate(ctx context.Context) error {
	return Validate.StructCtx(ctx, a)
}
