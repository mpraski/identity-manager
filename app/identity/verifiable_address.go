package identity

import (
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
		VerifiedAt null.Time             `json:"verified_at"`
		InsertedAt time.Time             `validate:"required" json:"inserted_at"`
		UpdatedAt  time.Time             `validate:"required" json:"updated_at"`
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
	identity uuid.UUID,
	kind VerifiableAddressKind,
	value string,
) *VerifiableAddress {
	return &VerifiableAddress{
		ID:         uuid.New(),
		IdentityID: identity,
		Kind:       kind,
		State:      VerificationPending,
		Token:      NewToken(AddressVerificationToken),
		Value:      value,
		InsertedAt: time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
}
