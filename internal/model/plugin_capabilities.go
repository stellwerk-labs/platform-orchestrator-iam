package model

import (
	"context"
	"time"

	"github.com/lib/pq"
	"github.com/pkg/errors"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"go.uber.org/zap"
)

type PluginCapability struct {
	OrgID       string
	PluginID    string
	ID          string
	DisplayName string
	Description string
	Category    string
	Level       sharedauthz.PermissionLevel
	Scopes      []sharedauthz.PermissionScope
	CreatedAt   time.Time
}

// ReplacePluginCapabilities atomically replaces one plugin's assignable human
// capabilities. Service-to-service grants deliberately use a separate contract.
func ReplacePluginCapabilities(ctx context.Context, tx Tx, orgID, pluginID string, capabilities []PluginCapability) error {
	if tx == nil {
		return errors.New("transaction is required")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_capabilities WHERE org_id=$1 AND plugin_id=$2`, orgID, pluginID); err != nil {
		return errors.Wrap(err, "failed to remove previous plugin capabilities")
	}
	for _, capability := range capabilities {
		scopes := make([]string, len(capability.Scopes))
		for index, scope := range capability.Scopes {
			scopes[index] = string(scope)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO plugin_capabilities (org_id, plugin_id, id, display_name, description, category, level, scopes)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, orgID, pluginID, capability.ID, capability.DisplayName, capability.Description,
			capability.Category, capability.Level, pq.Array(scopes)); err != nil {
			return errors.Wrap(err, "failed to register plugin capability")
		}
	}
	return nil
}

func (d *databaser) ListPluginCapabilities(ctx context.Context, optionalTx Tx, orgID string) ([]PluginCapability, error) {
	rows, err := d.txOrDb(optionalTx).QueryContext(ctx, `
		SELECT plugin_id, id, display_name, description, category, level, scopes, created_at
		FROM plugin_capabilities WHERE org_id=$1 ORDER BY id
	`, orgID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list plugin capabilities")
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			d.logger.Error("failed to close plugin capability rows", zap.Error(closeErr))
		}
	}()
	capabilities := make([]PluginCapability, 0)
	for rows.Next() {
		capability := PluginCapability{OrgID: orgID}
		var scopes pq.StringArray
		if err := rows.Scan(&capability.PluginID, &capability.ID, &capability.DisplayName, &capability.Description,
			&capability.Category, &capability.Level, &scopes, &capability.CreatedAt); err != nil {
			return nil, errors.Wrap(err, "failed to scan plugin capability")
		}
		capability.Scopes = make([]sharedauthz.PermissionScope, len(scopes))
		for index, scope := range scopes {
			capability.Scopes[index] = sharedauthz.PermissionScope(scope)
		}
		capabilities = append(capabilities, capability)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate plugin capabilities")
	}
	return capabilities, nil
}
