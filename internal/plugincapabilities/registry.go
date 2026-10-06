// Package plugincapabilities validates and registers plugin-owned human
// capabilities. It never registers service-to-service grants.
package plugincapabilities

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
)

const permissionIDMaxLength = 255

var (
	pluginIDPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$`)
	capabilityPattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]*[a-z0-9])?$`)
)

type Definition struct {
	Name        string
	DisplayName string
	Description string
	Category    string
	Level       sharedauthz.PermissionLevel
	Scopes      []sharedauthz.PermissionScope
}

type Registry struct {
	Database model.Databaser
	Reloader PolicyReloader
}

type PolicyReloader interface {
	ReloadPolicy() error
}

func (r Registry) Replace(ctx context.Context, orgID, authenticatedPluginID string, definitions []Definition) error {
	if r.Database == nil || r.Reloader == nil {
		return errors.New("plugin capability registry is not configured")
	}
	capabilities, err := validate(orgID, authenticatedPluginID, definitions)
	if err != nil {
		return err
	}
	tx, err := r.Database.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, "failed to begin plugin capability transaction")
	}
	defer func() { _ = tx.Rollback() }()
	if err := model.ReplacePluginCapabilities(ctx, tx, orgID, authenticatedPluginID, capabilities); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, "failed to commit plugin capabilities")
	}
	// Replacement can revoke capabilities. Reload synchronously so an old policy
	// snapshot and its known-permission cache cannot extend that authority.
	return errors.Wrap(r.Reloader.ReloadPolicy(), "failed to reload plugin capability policy")
}

func validate(orgID, pluginID string, definitions []Definition) ([]model.PluginCapability, error) {
	if orgID == "" || !pluginIDPattern.MatchString(pluginID) || strings.Contains(pluginID, "..") {
		return nil, errors.New("invalid organization or authenticated plugin identity")
	}
	seen := make(map[string]struct{}, len(definitions))
	capabilities := make([]model.PluginCapability, 0, len(definitions))
	for _, definition := range definitions {
		id := "plugin." + pluginID + "." + definition.Name
		if !capabilityPattern.MatchString(definition.Name) || len(id) > permissionIDMaxLength {
			return nil, errors.New("invalid plugin capability name")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, errors.New("duplicate plugin capability")
		}
		seen[id] = struct{}{}
		if definition.DisplayName == "" || definition.Description == "" || definition.Category == "" || len(definition.Scopes) == 0 {
			return nil, errors.New("incomplete plugin capability definition")
		}
		if !slices.Contains([]sharedauthz.PermissionLevel{sharedauthz.PermissionLevelRead, sharedauthz.PermissionLevelWrite, sharedauthz.PermissionLevelManage}, definition.Level) {
			return nil, errors.New("invalid plugin capability level")
		}
		for _, scope := range definition.Scopes {
			if !slices.Contains([]sharedauthz.PermissionScope{sharedauthz.PermissionScopeOrganization, sharedauthz.PermissionScopeProject, sharedauthz.PermissionScopeEnvironment}, scope) {
				return nil, errors.New("invalid plugin capability scope")
			}
		}
		capabilities = append(capabilities, model.PluginCapability{
			OrgID: orgID, PluginID: pluginID, ID: id, DisplayName: definition.DisplayName,
			Description: definition.Description, Category: definition.Category, Level: definition.Level,
			Scopes: slices.Clone(definition.Scopes),
		})
	}
	return capabilities, nil
}
