package rbac

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
)

type (
	Group struct {
		Name  string
		Roles []Role
	}

	Role struct {
		Name   string
		Scopes []Scope
	}

	Scope struct {
		Resource string
		Actions  []string
	}

	ScopedAction [2]string

	RBAC struct {
		Scopes        []Scope
		FlatScopes    []ScopedAction
		Roles         []Role
		Groups        []Group
		ScopesByGroup map[string][]ScopedAction
	}
)

var ErrInvalidRole = errors.New("role is invalid")

func (s ScopedAction) String() string {
	return s[0] + "." + s[1]
}

func (s ScopedAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func Make(files fs.FS) (*RBAC, error) {
	c, err := parseConfig(files)
	if err != nil {
		return nil, err
	}

	scopes := make([]Scope, 0, len(c.scopes))

	for n, s := range c.scopes {
		for i := range s {
			s[i] = trim(s[i])
		}

		scopes = append(scopes, Scope{
			Resource: trim(n),
			Actions:  s,
		})
	}

	roles := make([]Role, 0, len(c.roles))

	for n, r := range c.roles {
		sc := make([]Scope, 0, len(r.Scopes))

		for m, s := range r.Scopes {
			for i := range s {
				s[i] = trim(s[i])
			}

			sc = append(sc, Scope{
				Resource: trim(m),
				Actions:  s,
			})
		}

		roles = append(roles, Role{
			Name:   trim(n),
			Scopes: sc,
		})
	}

	groups := make([]Group, 0, len(c.groups))

	for n, g := range c.groups {
		ts := make([]Role, 0, len(g.Roles))

		for _, r := range g.Roles {
			t, ok := findByName(roles, r)
			if !ok {
				return nil, ErrInvalidRole
			}

			ts = append(ts, t)
		}

		groups = append(groups, Group{
			Name:  trim(n),
			Roles: ts,
		})
	}

	flatScopes := make([]ScopedAction, 0, len(scopes))

	for _, s := range scopes {
		for _, a := range s.Actions {
			flatScopes = append(flatScopes, ScopedAction{s.Resource, a})
		}
	}

	scopesByGroup := make(map[string][]ScopedAction, len(groups))

	for _, g := range groups {
		scopesByGroup[g.Name] = make([]ScopedAction, 0, len(g.Roles))

		for _, r := range g.Roles {
			for _, s := range r.Scopes {
				for _, a := range s.Actions {
					scopesByGroup[g.Name] = append(scopesByGroup[g.Name], ScopedAction{s.Resource, a})
				}
			}
		}
	}

	return &RBAC{
		Scopes:        scopes,
		Roles:         roles,
		Groups:        groups,
		FlatScopes:    flatScopes,
		ScopesByGroup: scopesByGroup,
	}, nil
}

func (r *RBAC) ScopesForGroup(group string) []ScopedAction {
	return r.ScopesByGroup[group]
}

func findByName(roles []Role, name string) (Role, bool) {
	for i := range roles {
		if roles[i].Name == name {
			return roles[i], true
		}
	}

	return Role{}, false
}

func trim(s string) string { return strings.TrimSpace(strings.ToLower(s)) }
