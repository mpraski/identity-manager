package identity

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type (
	State = string

	Groups = []string

	Identity struct {
		ID          uuid.UUID           `validate:"required" json:"id"`
		State       State               `validate:"required,oneof=active inactive" json:"state"`
		Groups      Groups              `validate:"required,unique" json:"groups"`
		Traits      Traits              `validate:"required" json:"traits"`
		Credentials Credentials         `validate:"required,len>0" json:"-"`
		Addresses   []VerifiableAddress `validate:"required,len>0" json:"addresses"`
		Data        *Data               `json:"-"`
		InsertedAt  time.Time           `validate:"required" json:"inserted_at"`
		UpdatedAt   time.Time           `validate:"required" json:"updated_at"`
	}

	Traits struct {
		Email string `validate:"required,safe_email" json:"email"`
	}
)

const (
	// State
	Active   State = "active"
	Inactive State = "inactive"
)

func New() *Identity {
	return &Identity{
		ID:          uuid.New(),
		State:       Inactive,
		Addresses:   make([]VerifiableAddress, 0),
		Credentials: make(Credentials),
		InsertedAt:  time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
}

func (i *Identity) WithGroups(groups []string) *Identity {
	i.Groups = groups
	return i
}

func (i *Identity) WithEmail(email string) *Identity {
	i.Traits.Email = email
	return i
}

func (i *Identity) WithCredential(credential *Credential) *Identity {
	i.Credentials[credential.Kind] = *credential
	return i
}

func (i *Identity) WithVerifiableAddress(address *VerifiableAddress) *Identity {
	i.Addresses = append(i.Addresses, *address)
	return i
}

func (i *Identity) WithData(data *Data) *Identity {
	i.Data = data
	return i
}

func (i *Identity) Validate(ctx context.Context) error {
	return Validate.StructCtx(ctx, i)
}

func (i *Identity) IsActive() bool {
	return i.State == Active
}

func (i *Identity) GetCredential(ctx context.Context, kind CredentialKind) (Credential, bool) {
	if c, ok := i.Credentials[kind]; ok && c.Kind == kind {
		if err := c.Validate(ctx); err == nil {
			return c, true
		}
	}

	return Credential{}, false
}
