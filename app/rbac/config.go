package rbac

import (
	"fmt"
	"io/fs"

	"gopkg.in/yaml.v2"
)

type (
	config struct {
		groups map[string]group
		roles  map[string]role
		scopes map[string]actions
	}

	group struct {
		Roles []string `yaml:"roles,flow"`
	}

	role struct {
		Scopes map[string]actions `yaml:"scopes,flow"`
	}

	actions = []string
)

func parseConfig(files fs.FS) (*config, error) {
	var err error

	g, err := files.Open("config/rbac/groups.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to open groups.yaml: %w", err)
	}

	defer g.Close()

	var groupsTemp struct {
		Groups map[string]group `yaml:"groups,flow"`
	}

	if err = yaml.NewDecoder(g).Decode(&groupsTemp); err != nil {
		return nil, fmt.Errorf("failed to decode groups.yaml: %w", err)
	}

	r, err := files.Open("config/rbac/roles.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to open roles.yaml: %w", err)
	}

	defer r.Close()

	var rolesTemp struct {
		Roles map[string]role `yaml:"roles,flow"`
	}

	if err = yaml.NewDecoder(r).Decode(&rolesTemp); err != nil {
		return nil, fmt.Errorf("failed to decode roles.yaml: %w", err)
	}

	s, err := files.Open("config/rbac/scopes.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to open scopes.yaml: %w", err)
	}

	defer s.Close()

	var scopesTemp struct {
		Scopes map[string]actions `yaml:"scopes,flow"`
	}

	if err = yaml.NewDecoder(s).Decode(&scopesTemp); err != nil {
		return nil, fmt.Errorf("failed to decode scopes.yaml: %w", err)
	}

	return &config{
		groups: groupsTemp.Groups,
		roles:  rolesTemp.Roles,
		scopes: scopesTemp.Scopes,
	}, nil
}
