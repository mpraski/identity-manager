package identity

import (
	"context"

	"github.com/google/uuid"
	"gopkg.in/guregu/null.v4"
)

type (
	Data struct {
		ID         uuid.UUID      `validate:"required" json:"id"`
		IdentityID uuid.UUID      `validate:"required" json:"identity_id"`
		Public     *PublicData    `validate:"required"`
		Sensitive  *SensitiveData `validate:"required"`
	}

	PublicData struct {
	}

	SensitiveData struct {
		Personal *PersonalData `json:"personal"`
		Address  *AddressData  `json:"address"`
		Billing  *BillingData  `json:"billing"`
	}

	PersonalData struct {
		FirstName string      `validate:"required,safe_name" json:"first_name"`
		LastName  string      `validate:"required,safe_name" json:"last_name"`
		Email     null.String `validate:"safe_email" json:"email"`
		Phone     null.String `validate:"safe_phone" json:"phone"`
		BirthDate null.Time   `validate:"birth_date" json:"birth_date"`
	}

	AddressData struct {
		Name         string `json:"name"`
		Street       string `validate:"required,exclude_space_around,min=4,max=255" json:"street"`
		StreetNumber string `validate:"required,exclude_space_around,min=4,max=32" json:"street_number"`
		Postcode     string `validate:"required,exclude_space_around,postcode_iso3166_alpha2_field=Country" json:"postcode"`
		City         string `validate:"required,exclude_space_around,min=4,max=32" json:"city"`
		Country      string `validate:"required,exclude_space_around,iso3166_1_alpha2" json:"country"`
	}

	BillingData struct {
	}
)

func NewData(identity uuid.UUID, public *PublicData, sensitive *SensitiveData) *Data {
	return &Data{
		ID:         uuid.New(),
		IdentityID: identity,
		Public:     public,
		Sensitive:  sensitive,
	}
}

func (d *Data) Validate(ctx context.Context) error {
	return Validate.StructCtx(ctx, d)
}
