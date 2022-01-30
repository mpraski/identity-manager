package storage

import "github.com/mpraski/identity-manager/app/identity"

func makeIdentity(
	i *Identity,
	cs []Credential,
	va []VerifiableAddress,
) (*identity.Identity, error) {
	creds := make(identity.Credentials)

	for i := range cs {
		var (
			c      = &cs[i]
			secret = identity.Secret(nil)
		)

		if c.Kind == identity.PasswordCredential {
			if c.PasswordHash == nil {
				return nil, ErrInvalidPasswordSecret
			}

			secret = identity.NewPasswordSecret(c.PasswordHash)
		}

		creds[c.Kind] = identity.Credential{
			ID:         c.ID,
			IdentityID: c.IdentityID,
			Kind:       c.Kind,
			Secret:     secret,
			InsertedAt: c.InsertedAt,
			UpdatedAt:  c.UpdatedAt,
		}
	}

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
		Credentials: creds,
		InsertedAt:  i.InsertedAt,
		UpdatedAt:   i.UpdatedAt,
	}, nil
}
