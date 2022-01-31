package rbac

import (
	"context"

	"github.com/google/uuid"
)

type (
	Authorization interface {
		HasScopes(context.Context, uuid.UUID, []string) (bool, error)
	}

	DefaultAuthorization struct {
		groupReader groupReader
		groupScopes map[string][]string
	}

	groupReader interface {
		GetGroups(context.Context, uuid.UUID) ([]string, error)
	}
)

func NewDefaultAuthorization(rules *RBAC, groupReader groupReader) *DefaultAuthorization {
	groupScopes := make(map[string][]string, len(rules.Groups))

	for n, s := range rules.ScopesByGroup {
		groupScopes[n] = make([]string, 0, len(s))

		for _, r := range s {
			groupScopes[n] = append(groupScopes[n], r.String())
		}
	}

	return &DefaultAuthorization{
		groupReader: groupReader,
		groupScopes: groupScopes,
	}
}

func (a *DefaultAuthorization) HasScopes(
	ctx context.Context,
	identityID uuid.UUID,
	scopes []string,
) (bool, error) {
	if len(scopes) == 0 {
		return false, nil
	}

	groups, err := a.groupReader.GetGroups(ctx, identityID)
	if err != nil {
		return false, err
	}

	for _, t := range scopes {
		var found bool

	outer:
		for _, g := range groups {
			for _, s := range a.groupScopes[g] {
				if found = t == s; found {
					break outer
				}
			}
		}

		if !found {
			return false, nil
		}
	}

	return true, nil
}
