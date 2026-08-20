package authorization

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
)

const (
	benchmarkDeveloperCount   = 5_000
	benchmarkDevelopersPerOrg = 50
	benchmarkProjectsPerUser  = 5
)

type authorizationBenchmarkStore struct {
	policies  []model.AuthorizationPolicy
	relations []model.AuthorizationResourceRelation
}

func (s *authorizationBenchmarkStore) ListAuthorizationPolicies(context.Context, model.Tx) ([]model.AuthorizationPolicy, error) {
	return s.policies, nil
}

func (s *authorizationBenchmarkStore) ListAuthorizationResourceRelations(context.Context, model.Tx) ([]model.AuthorizationResourceRelation, error) {
	return s.relations, nil
}

func (s *authorizationBenchmarkStore) ListKnownAuthorizationPermissions(_ context.Context, _ model.Tx, checks []model.AuthorizationPermissionCheck) ([]model.AuthorizationPermissionCheck, error) {
	return checks, nil
}

func BenchmarkAuthorize(b *testing.B) {
	store := newAuthorizationBenchmarkStore(b)

	benchmarks := []struct {
		name       string
		permission string
		checks     func(iteration int) (uuid.UUID, []Check)
		allowed    bool
	}{
		{name: "hot-cache-hit", permission: "read", checks: benchmarkHotChecks, allowed: true},
		{name: "rotating-allow", permission: "read", checks: benchmarkAllowedChecks(1, false), allowed: true},
		{name: "rotating-custom-allow", permission: "deployment_cancel", checks: benchmarkAllowedChecks(1, false), allowed: true},
		{name: "rotating-deny", permission: "read", checks: benchmarkAllowedChecks(1, true), allowed: false},
		{name: "rotating-batch-5", permission: "read", checks: benchmarkAllowedChecks(benchmarkProjectsPerUser, false), allowed: true},
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			authorizer, err := New(b.Context(), store)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(authorizer.Close)

			subject, checks := benchmark.checks(0)
			for index := range checks {
				checks[index].Permission = benchmark.permission
			}
			results, err := authorizer.Authorize(b.Context(), subject, checks)
			if err != nil {
				b.Fatal(err)
			}
			for _, result := range results {
				if result.Allowed != benchmark.allowed || result.Invalid {
					b.Fatalf("unexpected benchmark fixture result: %+v", result)
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				subject, checks := benchmark.checks(iteration)
				for index := range checks {
					checks[index].Permission = benchmark.permission
				}
				if _, err := authorizer.Authorize(b.Context(), subject, checks); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func newAuthorizationBenchmarkStore(tb testing.TB) *authorizationBenchmarkStore {
	tb.Helper()
	store := &authorizationBenchmarkStore{
		policies:  make([]model.AuthorizationPolicy, 0, benchmarkDeveloperCount*2),
		relations: make([]model.AuthorizationResourceRelation, 0, benchmarkDeveloperCount*benchmarkProjectsPerUser),
	}
	for developer := 1; developer <= benchmarkDeveloperCount; developer++ {
		subject := benchmarkSubject(tb, developer)
		organization := benchmarkOrganization(developer)
		roleId := benchmarkRole(tb, developer)
		store.policies = append(store.policies,
			model.AuthorizationPolicy{SubjectId: subject, Resource: organization, Permission: PermissionReadAll, RoleId: roleId},
			model.AuthorizationPolicy{SubjectId: subject, Resource: organization, Permission: "deployment_cancel", RoleId: roleId},
		)
		for project := 1; project <= benchmarkProjectsPerUser; project++ {
			store.relations = append(store.relations, model.AuthorizationResourceRelation{
				Resource:       benchmarkProject(developer, project),
				ParentResource: organization,
			})
		}
	}
	return store
}

func benchmarkRole(tb testing.TB, developer int) uuid.UUID {
	organization := ((developer - 1) / benchmarkDevelopersPerOrg) + 1
	roleId, err := uuid.Parse(fmt.Sprintf("20000000-0000-4000-8000-%012d", organization))
	if err != nil {
		tb.Fatal(err)
	}
	return roleId
}

func benchmarkAllowedChecks(count int, denied bool) func(int) (uuid.UUID, []Check) {
	return func(iteration int) (uuid.UUID, []Check) {
		developer := (iteration % benchmarkDeveloperCount) + 1
		targetDeveloper := developer
		if denied {
			targetDeveloper = ((developer - 1 + benchmarkDevelopersPerOrg) % benchmarkDeveloperCount) + 1
		}
		checks := make([]Check, count)
		for index := range checks {
			project := ((iteration / benchmarkDeveloperCount) + index) % benchmarkProjectsPerUser
			checks[index].Resource = benchmarkProject(targetDeveloper, project+1)
		}
		return benchmarkSubject(nil, developer), checks
	}
}

func benchmarkHotChecks(int) (uuid.UUID, []Check) {
	return benchmarkSubject(nil, 1), []Check{{Resource: benchmarkProject(1, 1)}}
}

func benchmarkSubject(tb testing.TB, developer int) uuid.UUID {
	subject, err := uuid.Parse(fmt.Sprintf("10000000-0000-4000-8000-%012d", developer))
	if err != nil {
		if tb != nil {
			tb.Fatal(err)
		}
		panic(err)
	}
	return subject
}

func benchmarkOrganization(developer int) string {
	organization := ((developer - 1) / benchmarkDevelopersPerOrg) + 1
	return fmt.Sprintf("organization:authorization-benchmark-org-%04d", organization)
}

func benchmarkProject(developer, project int) string {
	return fmt.Sprintf("project:authorization-benchmark-project-%06d-%d", developer, project)
}
