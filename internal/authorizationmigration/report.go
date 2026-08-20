package authorizationmigration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/pressly/goose/v3"
)

const (
	LegacySchemaVersion = int64(29)
	CasbinSchemaVersion = int64(30)
)

type Phase string

const (
	PhasePreflight Phase = "preflight"
	PhaseVerify    Phase = "verify"
)

type Counts struct {
	Organizations       int64 `json:"organizations"`
	Roles               int64 `json:"roles"`
	UserRoleBindings    int64 `json:"user_role_bindings"`
	ServiceRoleBindings int64 `json:"service_role_bindings"`
	Projects            int64 `json:"projects"`
	Environments        int64 `json:"environments"`
	Resources           int64 `json:"resources"`
}

type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

type Report struct {
	Phase         Phase            `json:"phase"`
	GeneratedAt   time.Time        `json:"generated_at"`
	SchemaVersion int64            `json:"schema_version"`
	PolicySHA256  string           `json:"policy_sha256"`
	Counts        Counts           `json:"counts"`
	Checks        []Check          `json:"checks"`
	Reconciled    *ReconcileResult `json:"reconciled,omitempty"`
	Ready         bool             `json:"ready"`
}

func Inspect(ctx context.Context, db *sql.DB, phase Phase) (Report, error) {
	report := Report{Phase: phase, GeneratedAt: time.Now().UTC(), Ready: true}
	version, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return report, errors.Wrap(err, "failed to read database migration version")
	}
	report.SchemaVersion = version

	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return report, errors.Wrap(err, "failed to begin migration inspection transaction")
	}
	defer func() { _ = tx.Rollback() }()

	switch phase {
	case PhasePreflight:
		if version != LegacySchemaVersion {
			report.fail("schema-version", fmt.Sprintf("expected SpiceDB schema version %d, found %d", LegacySchemaVersion, version))
		} else {
			report.pass("schema-version", fmt.Sprintf("legacy schema is at version %d", version))
		}
		if err := inspectLegacy(ctx, tx, &report); err != nil {
			return report, err
		}
	case PhaseVerify:
		if version != CasbinSchemaVersion {
			report.fail("schema-version", fmt.Sprintf("expected Casbin schema version %d, found %d", CasbinSchemaVersion, version))
		} else {
			report.pass("schema-version", fmt.Sprintf("Casbin schema is at version %d", version))
		}
		if err := inspectCasbin(ctx, tx, &report); err != nil {
			return report, err
		}
	default:
		return report, errors.Errorf("unsupported inspection phase %q", phase)
	}

	fingerprint, err := policyFingerprint(ctx, tx)
	if err != nil {
		return report, err
	}
	report.PolicySHA256 = fingerprint
	if err := populateCommonCounts(ctx, tx, &report.Counts); err != nil {
		return report, err
	}

	if err := tx.Commit(); err != nil {
		return report, errors.Wrap(err, "failed to commit migration inspection transaction")
	}
	return report, nil
}

func inspectLegacy(ctx context.Context, tx *sql.Tx, report *Report) error {
	checks := []struct {
		name    string
		query   string
		failure string
	}{
		{
			name: "role-membership-identifiers",
			query: `SELECT count(*) FROM memberships
				WHERE subject_type = 'role'
				AND role IS NULL
				AND subject !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'`,
			failure: "role memberships contain a null role and a subject that is not a UUID",
		},
		{
			name: "role-membership-references",
			query: `SELECT count(*) FROM memberships m
				LEFT JOIN roles r ON r.org_id = m.org_id
				 AND r.id::text = COALESCE(m.role::text, m.subject)
				WHERE m.subject_type = 'role' AND r.id IS NULL`,
			failure: "role memberships reference a role that does not exist in the same organization",
		},
		{
			name: "scope-format",
			query: `SELECT count(*) FROM (
				SELECT scope FROM memberships WHERE subject_type = 'role' AND scope <> ''
				UNION ALL SELECT scope FROM service_user_roles WHERE scope <> ''
				UNION ALL SELECT scope FROM scoped_roles WHERE scope <> ''
			) scopes
			WHERE scope !~* '^(project|env):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'`,
			failure: "role bindings or projected roles contain malformed scopes",
		},
		{
			name: "scoped-projection-coverage",
			query: `SELECT count(*) FROM (
				SELECT m.org_id, m.scope, COALESCE(m.role::text, m.subject) AS role_id
				FROM memberships m WHERE m.subject_type = 'role' AND m.scope <> ''
				UNION
				SELECT org_id, scope, role_id::text FROM service_user_roles WHERE scope <> ''
			) bindings
			WHERE NOT EXISTS (
				SELECT 1 FROM scoped_roles sr
				WHERE sr.org_id = bindings.org_id AND sr.scope = bindings.scope
				AND sr.org_role_id::text = bindings.role_id
			)`,
			failure: "scoped role bindings are missing from the legacy PostgreSQL projection",
		},
		{
			name: "scope-organization-uniqueness",
			query: `SELECT count(*) FROM (
				SELECT scope FROM scoped_roles GROUP BY scope HAVING count(DISTINCT org_id) > 1
			) conflicts`,
			failure: "the same project or environment UUID is associated with multiple organizations",
		},
	}
	for _, check := range checks {
		if err := report.runZeroCheck(ctx, tx, check.name, check.query, check.failure); err != nil {
			return err
		}
	}

	return populateLegacyResourceCounts(ctx, tx, &report.Counts)
}

func inspectCasbin(ctx context.Context, tx *sql.Tx, report *Report) error {
	checks := []struct {
		name    string
		query   string
		failure string
	}{
		{
			name: "scope-format",
			query: `SELECT count(*) FROM (
				SELECT scope FROM memberships WHERE subject_type = 'role' AND scope <> ''
				UNION ALL SELECT scope FROM service_user_roles WHERE scope <> ''
			) scopes
			WHERE scope !~* '^(project|env):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'`,
			failure: "role bindings contain malformed scopes",
		},
		{
			name: "role-membership-references",
			query: `SELECT count(*) FROM memberships m
				LEFT JOIN roles r ON r.org_id = m.org_id AND r.id = m.role
				WHERE m.subject_type = 'role' AND (m.role IS NULL OR r.id IS NULL)`,
			failure: "role memberships are missing a valid role in the same organization",
		},
		{
			name: "organization-resource-coverage",
			query: `SELECT count(*) FROM (
				SELECT org_id FROM roles
				UNION SELECT org_id FROM memberships WHERE subject_type = 'role'
				UNION SELECT org_id FROM service_user_roles
			) orgs
			WHERE NOT EXISTS (
				SELECT 1 FROM authorization_resources ar
				WHERE ar.resource = 'organization:' || orgs.org_id AND ar.org_id = orgs.org_id
			)`,
			failure: "organizations referenced by RBAC data are missing authorization resources",
		},
		{
			name: "scoped-resource-coverage",
			query: `SELECT count(*) FROM (
				SELECT org_id, scope FROM memberships WHERE subject_type = 'role' AND scope <> ''
				UNION SELECT org_id, scope FROM service_user_roles WHERE scope <> ''
			) bindings
			WHERE NOT EXISTS (
				SELECT 1 FROM authorization_resources ar
				WHERE ar.resource = bindings.scope AND ar.org_id = bindings.org_id
			)`,
			failure: "scoped RBAC bindings reference resources missing from the Casbin hierarchy",
		},
		{
			name: "project-parentage",
			query: `SELECT count(*) FROM authorization_resources child
			LEFT JOIN authorization_resources parent ON parent.resource = child.parent_resource
			WHERE child.resource_type = 'project'
			AND (parent.resource_type IS DISTINCT FROM 'organization' OR parent.org_id IS DISTINCT FROM child.org_id)`,
			failure: "projects are not attached to an organization in the same authorization tree",
		},
		{
			name: "environment-parentage",
			query: `SELECT count(*) FROM authorization_resources child
			LEFT JOIN authorization_resources parent ON parent.resource = child.parent_resource
			WHERE child.resource_type = 'env'
			AND (parent.resource_type IS DISTINCT FROM 'project' OR parent.org_id IS DISTINCT FROM child.org_id)`,
			failure: "environments are not attached to a project; rerun apply while the control plane is reachable",
		},
	}
	for _, check := range checks {
		if err := report.runZeroCheck(ctx, tx, check.name, check.query, check.failure); err != nil {
			return err
		}
	}

	return populateCasbinResourceCounts(ctx, tx, &report.Counts)
}

func (r *Report) runZeroCheck(ctx context.Context, tx *sql.Tx, name, query, failure string) error {
	var count int64
	if err := tx.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return errors.Wrapf(err, "failed migration check %s", name)
	}
	if count == 0 {
		r.pass(name, "no invalid rows found")
	} else {
		r.fail(name, fmt.Sprintf("%s: %d row(s)", failure, count))
	}
	return nil
}

func (r *Report) pass(name, details string) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: true, Details: details})
}

func (r *Report) fail(name, details string) {
	r.Ready = false
	r.Checks = append(r.Checks, Check{Name: name, Passed: false, Details: details})
}

func populateCommonCounts(ctx context.Context, tx *sql.Tx, counts *Counts) error {
	queries := []struct {
		target *int64
		query  string
	}{
		{&counts.Organizations, `SELECT count(*) FROM (SELECT org_id FROM roles UNION SELECT org_id FROM memberships WHERE subject_type = 'role' UNION SELECT org_id FROM service_user_roles) orgs`},
		{&counts.Roles, `SELECT count(*) FROM roles`},
		{&counts.UserRoleBindings, `SELECT count(*) FROM memberships WHERE subject_type = 'role'`},
		{&counts.ServiceRoleBindings, `SELECT count(*) FROM service_user_roles`},
	}
	for _, item := range queries {
		if err := tx.QueryRowContext(ctx, item.query).Scan(item.target); err != nil {
			return errors.Wrap(err, "failed to count authorization records")
		}
	}
	return nil
}

func populateLegacyResourceCounts(ctx context.Context, tx *sql.Tx, counts *Counts) error {
	return tx.QueryRowContext(ctx, `SELECT
		count(DISTINCT scope) FILTER (WHERE scope LIKE 'project:%'),
		count(DISTINCT scope) FILTER (WHERE scope LIKE 'env:%'),
		count(DISTINCT scope)
		FROM scoped_roles`).Scan(&counts.Projects, &counts.Environments, &counts.Resources)
}

func populateCasbinResourceCounts(ctx context.Context, tx *sql.Tx, counts *Counts) error {
	return tx.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE resource_type = 'project'),
		count(*) FILTER (WHERE resource_type = 'env'),
		count(*)
		FROM authorization_resources`).Scan(&counts.Projects, &counts.Environments, &counts.Resources)
}

func policyFingerprint(ctx context.Context, tx *sql.Tx) (string, error) {
	canonical := make([]string, 0)
	if err := appendCanonicalRoles(ctx, tx, &canonical); err != nil {
		return "", err
	}
	if err := appendCanonicalBindings(ctx, tx, &canonical); err != nil {
		return "", err
	}

	slices.Sort(canonical)
	digest := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return hex.EncodeToString(digest[:]), nil
}

func appendCanonicalRoles(ctx context.Context, tx *sql.Tx, canonical *[]string) error {
	roleRows, err := tx.QueryContext(ctx, `SELECT org_id, id::text, display_name, permissions FROM roles`)
	if err != nil {
		return errors.Wrap(err, "failed to read roles for migration fingerprint")
	}
	defer func() { _ = roleRows.Close() }()
	for roleRows.Next() {
		var orgID, roleID, displayName string
		var permissions pq.StringArray
		if err := roleRows.Scan(&orgID, &roleID, &displayName, &permissions); err != nil {
			return errors.Wrap(err, "failed to scan role for migration fingerprint")
		}
		slices.Sort(permissions)
		*canonical = append(*canonical, strings.Join([]string{"role", orgID, roleID, displayName, strings.Join(permissions, ",")}, "\x00"))
	}
	if err := roleRows.Err(); err != nil {
		return errors.Wrap(err, "failed to iterate role fingerprint rows")
	}
	return nil
}

func appendCanonicalBindings(ctx context.Context, tx *sql.Tx, canonical *[]string) error {
	bindingRows, err := tx.QueryContext(ctx, `
		SELECT 'user', org_id, user_id::text, scope, COALESCE(role::text, subject)
		FROM memberships WHERE subject_type = 'role'
		UNION ALL
		SELECT 'service-user', org_id, service_user_id::text, scope, role_id::text
		FROM service_user_roles`)
	if err != nil {
		return errors.Wrap(err, "failed to read bindings for migration fingerprint")
	}
	defer func() { _ = bindingRows.Close() }()
	for bindingRows.Next() {
		var kind, orgID, subjectID, scope, roleID string
		if err := bindingRows.Scan(&kind, &orgID, &subjectID, &scope, &roleID); err != nil {
			return errors.Wrap(err, "failed to scan binding for migration fingerprint")
		}
		*canonical = append(*canonical, strings.Join([]string{kind, orgID, subjectID, scope, roleID}, "\x00"))
	}
	if err := bindingRows.Err(); err != nil {
		return errors.Wrap(err, "failed to iterate binding fingerprint rows")
	}
	return nil
}
