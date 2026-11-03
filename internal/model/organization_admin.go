package model

import (
	"context"
	"github.com/google/uuid"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// IsOrganizationAdmin requires an active human's organization-wide membership in
// the canonical seeded Admin role. Permissions, role names and platform grants
// do not participate in this predicate.
func IsOrganizationAdmin(ctx context.Context, db Databaser, org string, actor uuid.UUID) (bool, error) {
	if org == "" || !userid.IsHumanUser(actor) || actor == userid.InternalSystemUuid {
		return false, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	active, err := db.IsAuthorizationSubjectActive(ctx, tx, actor)
	if err != nil || !active {
		return false, err
	}
	var allowed bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN roles r ON r.org_id=m.org_id AND r.id=m.role WHERE m.user_id=$1 AND m.org_id=$2 AND m.subject_type='role' AND m.subject=r.id::text AND m.scope='' AND r.builtin_key='admin' AND r.is_system)`, actor, org).Scan(&allowed)
	return allowed, err
}
