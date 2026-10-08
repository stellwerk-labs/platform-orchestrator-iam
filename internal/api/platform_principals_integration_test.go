//go:build integration

package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// platformOperator adds a human holder of plugin_workload_binding_write.
func (f *workloadFixture) platformOperator(t *testing.T) uuid.UUID {
	t.Helper()
	operator := userid.NewHumanUserId()
	_, err := f.raw.ExecContext(f.ctx, `INSERT INTO users (id, display_name, created_at) VALUES ($1, 'Platform operator', now())`, operator)
	require.NoError(t, err)
	holders := f.server.PlatformPermissionHolders[sharedauthz.PermissionPluginWorkloadBindingWrite]
	f.server.PlatformPermissionHolders[sharedauthz.PermissionPluginWorkloadBindingWrite] = append(holders, operator)
	return operator
}

func (f *workloadFixture) createChecker(t *testing.T, operator uuid.UUID) PlatformPrincipalWithToken {
	t.Helper()
	response, err := f.server.CreatePlatformPrincipal(f.as(operator), CreatePlatformPrincipalRequestObject{
		Body: &PlatformPrincipalCreateBody{DisplayName: "Data Plane admission checker", ExpiryInDays: 365},
	})
	require.NoError(t, err)
	created, ok := response.(CreatePlatformPrincipal201JSONResponse)
	require.True(t, ok, "creation refused: %#v", response)
	return PlatformPrincipalWithToken(created)
}

func (f *workloadFixture) regeneratePlatformPrincipal(t *testing.T, operator, principal uuid.UUID) RegeneratePlatformPrincipalResponseObject {
	t.Helper()
	response, err := f.server.RegeneratePlatformPrincipal(f.as(operator), RegeneratePlatformPrincipalRequestObject{
		PrincipalId: principal, Body: &ServiceUserRegenerateBody{ExpiryInDays: 30},
	})
	require.NoError(t, err)
	return response
}

// The Data Plane admission checker is one identity for every installation
// and organization: a static-token platform principal that belongs to no
// organization, holds no role and is managed only by platform operators.
func TestStaticTokenPlatformPrincipalAuthenticatesOutsideEveryOrganization(t *testing.T) {
	f := newWorkloadFixture(t)
	operator := f.platformOperator(t)

	// Only users or IAM's internal system identity issue static platform tokens.
	_, err := f.server.CreatePlatformPrincipal(f.as(f.admin), CreatePlatformPrincipalRequestObject{
		Body: &PlatformPrincipalCreateBody{DisplayName: "checker", ExpiryInDays: 30},
	})
	requireForbidden(t, err, "an organization admin holds no platform permission")
	refused, err := f.server.CreatePlatformPrincipal(f.as(f.operator), CreatePlatformPrincipalRequestObject{
		Body: &PlatformPrincipalCreateBody{DisplayName: "checker", ExpiryInDays: 30},
	})
	require.NoError(t, err)
	require.Equal(t, CreatePlatformPrincipal403JSONResponse{Generate403Response(serviceUsersMayNotIssuePlatformTokens)}, refused,
		"a service user holding the platform permission still cannot mint a long-lived credential")
	require.Zero(t, f.platformPrincipalCount(t))

	checker := f.createChecker(t, operator)
	require.Equal(t, PlatformPrincipalCredentialStaticToken, checker.Credential)
	require.Equal(t, operator, checker.GeneratedBy)
	require.NotNil(t, checker.CurrentTokenExpiresAt)
	require.WithinDuration(t, time.Now().Add(365*24*time.Hour), *checker.CurrentTokenExpiresAt, time.Minute)
	require.Nil(t, checker.WorkloadBindingId)
	require.True(t, strings.HasPrefix(checker.Token, ServiceUserTokenPrefix))
	require.True(t, userid.IsServiceUser(checker.Id))
	system := f.createChecker(t, userid.InternalSystemUuid)
	require.Equal(t, userid.InternalSystemUuid, system.GeneratedBy, "IAM's internal system identity may create one too")

	subject, ok := f.authenticate(t, checker.Token)
	require.True(t, ok)
	require.Equal(t, checker.Id, subject)
	require.True(t, f.active(t, checker.Id))
	organization := "organization:" + workloadOrg
	checks := []ResourcePermissionCheck{{Resource: organization, Permission: "member"}, {Resource: organization, Permission: "read"}}
	require.ElementsMatch(t, checks, f.authorize(t, checker.Id, checks...), "the checker has no authority in any organization")

	// It is no plugin workload identity.
	unbindable := f.rebindingBody(checker.Id)
	require.Equal(t, CreatePluginWorkloadBinding400JSONResponse{Generate400Response("a platform principal with a static token cannot be bound to a plugin workload")},
		f.createBinding(t, unbindable))

	// The organization's admin neither sees nor reaches it, and removing the
	// organization's access leaves it working.
	listed, err := f.server.ListServiceUsers(f.as(f.admin), ListServiceUsersRequestObject{OrgId: workloadOrg})
	require.NoError(t, err)
	for _, item := range listed.(ListServiceUsers200JSONResponse).Items {
		require.NotEqual(t, checker.Id, item.Id)
	}
	deleted, err := f.server.DeleteServiceUser(f.as(f.admin), DeleteServiceUserRequestObject{OrgId: workloadOrg, ServiceUserId: checker.Id})
	require.NoError(t, err)
	require.IsType(t, DeleteServiceUser404JSONResponse{}, deleted)
	require.IsType(t, RegenerateServiceUser404JSONResponse{}, f.regenerate(t, checker.Id))
	_, err = f.server.RegeneratePlatformPrincipal(f.as(f.admin), RegeneratePlatformPrincipalRequestObject{
		PrincipalId: checker.Id, Body: &ServiceUserRegenerateBody{ExpiryInDays: 30},
	})
	requireForbidden(t, err)
	require.Equal(t, RegeneratePlatformPrincipal403JSONResponse{Generate403Response(serviceUsersMayNotIssuePlatformTokens)},
		f.regeneratePlatformPrincipal(t, f.operator, checker.Id), "a service user cannot regenerate a static platform token")
	_, err = f.server.InternalRemoveAccessFromOrg(f.ctx, InternalRemoveAccessFromOrgRequestObject{OrgId: workloadOrg})
	require.NoError(t, err)
	subject, ok = f.authenticate(t, checker.Token)
	require.True(t, ok, "organization access removal never reaches a platform principal")
	require.Equal(t, checker.Id, subject)
	require.True(t, f.active(t, checker.Id))

	// Regeneration replaces the token.
	regenerated, ok := f.regeneratePlatformPrincipal(t, operator, checker.Id).(RegeneratePlatformPrincipal200JSONResponse)
	require.True(t, ok)
	require.Equal(t, checker.Id, regenerated.Id)
	require.NotEqual(t, checker.Token, regenerated.Token)
	require.WithinDuration(t, time.Now().Add(30*24*time.Hour), *regenerated.CurrentTokenExpiresAt, time.Minute)
	_, ok = f.authenticate(t, checker.Token)
	require.False(t, ok, "the previous token stops")
	subject, ok = f.authenticate(t, regenerated.Token)
	require.True(t, ok)
	require.Equal(t, checker.Id, subject)
	require.IsType(t, RegeneratePlatformPrincipal404JSONResponse{}, f.regeneratePlatformPrincipal(t, operator, userid.NewServiceUserTokenId()))
	require.IsType(t, RegeneratePlatformPrincipal404JSONResponse{}, f.regeneratePlatformPrincipal(t, operator, f.legacy),
		"an organization service user is not reachable through the platform routes")

	// Expiry stops it like any static token.
	_, err = f.raw.ExecContext(f.ctx, `UPDATE service_user_tokens SET generated_at = $2, current_token_expires_at = $3 WHERE id = $1`,
		checker.Id, time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(-time.Minute))
	require.NoError(t, err)
	_, ok = f.authenticate(t, regenerated.Token)
	require.False(t, ok)
	require.False(t, f.active(t, checker.Id))
}

func TestPlatformPrincipalsAreListedAndDeletedByPlatformOperatorsOnly(t *testing.T) {
	f := newWorkloadFixture(t)
	operator := f.platformOperator(t)
	checker := f.createChecker(t, operator)
	binding := f.bind(t, f.bindingBody())
	workloadToken := f.exchangeToken(t)

	listed, err := f.server.ListPlatformPrincipals(f.as(f.operator), ListPlatformPrincipalsRequestObject{})
	require.NoError(t, err)
	items := listed.(ListPlatformPrincipals200JSONResponse).Items
	require.Len(t, items, 2, "organization service users are never platform principals")
	byID := map[uuid.UUID]PlatformPrincipal{}
	for _, item := range items {
		byID[item.Id] = item
	}
	require.Equal(t, PlatformPrincipalCredentialStaticToken, byID[checker.Id].Credential)
	workload := byID[binding.ServiceUserId]
	require.Equal(t, PlatformPrincipalCredentialWorkload, workload.Credential)
	require.Nil(t, workload.CurrentTokenExpiresAt)
	require.Equal(t, binding.Id, *workload.WorkloadBindingId)
	require.Equal(t, "progressive-rollouts", workload.DisplayName)
	require.Equal(t, f.operator, workload.GeneratedBy)

	read, err := f.server.GetPlatformPrincipal(f.as(f.operator), GetPlatformPrincipalRequestObject{PrincipalId: binding.ServiceUserId})
	require.NoError(t, err)
	require.Equal(t, GetPlatformPrincipal200JSONResponse(workload), read)
	missing, err := f.server.GetPlatformPrincipal(f.as(f.operator), GetPlatformPrincipalRequestObject{PrincipalId: f.legacy})
	require.NoError(t, err)
	require.IsType(t, GetPlatformPrincipal404JSONResponse{}, missing)
	_, err = f.server.ListPlatformPrincipals(f.as(f.admin), ListPlatformPrincipalsRequestObject{})
	requireForbidden(t, err)
	_, err = f.server.DeletePlatformPrincipal(f.as(f.admin), DeletePlatformPrincipalRequestObject{PrincipalId: checker.Id})
	requireForbidden(t, err)
	require.Equal(t, RegeneratePlatformPrincipal409JSONResponse{Generate409Response("a plugin workload principal has no static token")},
		f.regeneratePlatformPrincipal(t, operator, binding.ServiceUserId))

	// Deleting a workload principal revokes its binding and tokens at once.
	deleted, err := f.server.DeletePlatformPrincipal(f.as(f.operator), DeletePlatformPrincipalRequestObject{PrincipalId: binding.ServiceUserId})
	require.NoError(t, err)
	require.IsType(t, DeletePlatformPrincipal204Response{}, deleted)
	_, ok := f.authenticate(t, workloadToken)
	require.False(t, ok)
	require.IsType(t, ExchangePluginWorkloadToken400JSONResponse{}, f.exchange(t, f.validClaims()))
	gone, err := f.server.GetPluginWorkloadBinding(f.as(f.operator), GetPluginWorkloadBindingRequestObject{BindingId: binding.Id})
	require.NoError(t, err)
	require.IsType(t, GetPluginWorkloadBinding404JSONResponse{}, gone)

	// Deleting the checker stops its token; an organization service user is
	// not deletable here.
	deleted, err = f.server.DeletePlatformPrincipal(f.as(f.operator), DeletePlatformPrincipalRequestObject{PrincipalId: checker.Id})
	require.NoError(t, err)
	require.IsType(t, DeletePlatformPrincipal204Response{}, deleted)
	_, ok = f.authenticate(t, checker.Token)
	require.False(t, ok)
	for _, principal := range []uuid.UUID{checker.Id, f.legacy} {
		again, err := f.server.DeletePlatformPrincipal(f.as(f.operator), DeletePlatformPrincipalRequestObject{PrincipalId: principal})
		require.NoError(t, err)
		require.IsType(t, DeletePlatformPrincipal404JSONResponse{}, again)
	}
	require.True(t, f.active(t, f.legacy), "the organization service user is untouched")
	require.Zero(t, f.platformPrincipalCount(t))
}
