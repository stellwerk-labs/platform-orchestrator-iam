package integrationtests

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// rolesHeldByEmail returns the global user id and the set of role ids (the
// membership subjects) held in the org by the user with the given primary
// email, as seen through the members API.
func rolesHeldByEmail(t *testing.T, client serverclient.ClientWithResponsesInterface, orgId string, asUser uuid.UUID, email string) (uuid.UUID, map[string]bool) {
	t.Helper()
	r, err := client.ListMembersWithResponse(t.Context(), orgId, &serverclient.ListMembersParams{}, WithAuthenticatedUserId(asUser))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, r.StatusCode(), "list members: %s", string(r.Body))
	var userId uuid.UUID
	roles := make(map[string]bool)
	for _, m := range r.JSON200.Items {
		if m.UserPrimaryEmailAddress != nil && *m.UserPrimaryEmailAddress == email {
			userId = m.UserId
			roles[m.Subject] = true
		}
	}
	return userId, roles
}

// TestScimGroupRoleMapping covers the group→role mapping feature end to end:
// mapping CRUD authorization, provisioning fallback, group membership driving
// mapped roles, the Viewer fallback on group removal, and the guarantee that a
// manually granted membership survives reconciliation.
func TestScimGroupRoleMapping(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	cpInternalClient := MustInternalControlPlaneClient(t)

	org := MustCreateTestOrg(cpInternalClient, t)
	admin := MustRegisterTestUser(client, t)
	adminRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, admin.Id, adminRoleId)
	viewerRoleId := MustObtainRoleIdByName(t, client, org.Id, DefaultViewerRoleName)
	deployerRoleId := MustObtainRoleIdByName(t, client, org.Id, "Deployer")

	// The custom role a SCIM group will map to.
	mappedRole, err := client.CreateRoleWithResponse(t.Context(), org.Id, serverclient.CreateRoleJSONRequestBody{
		DisplayName: "Group Mapped Role",
		Permissions: []string{authz.PermissionRoleRead},
	}, WithAuthenticatedUserId(admin.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, mappedRole.StatusCode(), "create mapped role: %s", string(mappedRole.Body))
	mappedRoleId := mappedRole.JSON201.Id

	// SCIM caller with ONLY provisioning permissions (this is the IDP's identity).
	provRole, err := client.CreateRoleWithResponse(t.Context(), org.Id, serverclient.CreateRoleJSONRequestBody{
		DisplayName: "Provisioner",
		Permissions: []string{authz.PermissionProvisioningRead, authz.PermissionProvisioningWrite},
	}, WithAuthenticatedUserId(admin.Id))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, provRole.StatusCode(), "create provisioner role: %s", string(provRole.Body))

	scimCaller := MustRegisterTestUser(client, t)
	cm, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id,
		serverclient.InternalCreateOrgMembershipJSONRequestBody{
			UserId:      scimCaller.Id,
			SubjectType: serverclient.SubjectTypeRole,
			Subject:     provRole.JSON201.Id.String(),
		})
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, cm.StatusCode(), "add scim caller membership: %s", string(cm.Body))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		resp, err := client.CheckPermissionsWithResponse(t.Context(), []serverclient.ResourcePermissionCheck{
			authz.OrgCheck(org.Id, authz.PermissionProvisioningWrite),
		}, WithAuthenticatedUserId(scimCaller.Id))
		require.NoError(t, err)
		if !assert.Equal(c, http.StatusOK, resp.StatusCode(), "check perms: %s", string(resp.Body)) {
			return
		}
		assert.Equal(c, []serverclient.ResourcePermissionCheckResultItem{
			{Allowed: true, PermissionCheck: authz.OrgCheck(org.Id, authz.PermissionProvisioningWrite)},
		}, resp.JSON200.Items)
	}, 30*time.Second, 500*time.Millisecond, "scim caller did not get provisioning permissions in time")

	const groupName = "Platform Engineers"

	// ------------------------------------------------------------------ mapping CRUD + authorization

	t.Run("provisioning-only caller cannot manage mappings", func(t *testing.T) {
		// role_write is required; the SCIM client's provisioning_write must NOT
		// be enough, or the IDP could self-escalate via a group→Admin mapping.
		r, err := client.UpsertScimGroupMappingWithResponse(t.Context(), org.Id, groupName,
			serverclient.UpsertScimGroupMappingJSONRequestBody{RoleId: mappedRoleId},
			WithAuthenticatedUserId(scimCaller.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, r.StatusCode(), "body: %s", string(r.Body))

		d, err := client.DeleteScimGroupMappingWithResponse(t.Context(), org.Id, groupName, WithAuthenticatedUserId(scimCaller.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, d.StatusCode(), "body: %s", string(d.Body))

		l, err := client.ListScimGroupMappingsWithResponse(t.Context(), org.Id, WithAuthenticatedUserId(scimCaller.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, l.StatusCode(), "body: %s", string(l.Body))
	})

	t.Run("mapping to a role from another org is rejected", func(t *testing.T) {
		otherOrg := MustCreateTestOrg(cpInternalClient, t)
		otherAdmin := MustRegisterTestUser(client, t)
		otherAdminRoleId := MustObtainRoleIdByName(t, client, otherOrg.Id, DefaultAdminRoleName)
		_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, otherOrg.Id, otherAdmin.Id, otherAdminRoleId)

		foreignRole, err := client.CreateRoleWithResponse(t.Context(), otherOrg.Id, serverclient.CreateRoleJSONRequestBody{
			DisplayName: "Foreign Role",
			Permissions: []string{authz.PermissionRoleRead},
		}, WithAuthenticatedUserId(otherAdmin.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, foreignRole.StatusCode())

		r, err := client.UpsertScimGroupMappingWithResponse(t.Context(), org.Id, groupName,
			serverclient.UpsertScimGroupMappingJSONRequestBody{RoleId: foreignRole.JSON201.Id},
			WithAuthenticatedUserId(admin.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, r.StatusCode(), "cross-org role must be a 404; body: %s", string(r.Body))
	})

	t.Run("admin can create and list a mapping", func(t *testing.T) {
		// Configured with different casing than the group will sync with, to
		// prove the case-insensitive match.
		r, err := client.UpsertScimGroupMappingWithResponse(t.Context(), org.Id, "platform engineers",
			serverclient.UpsertScimGroupMappingJSONRequestBody{RoleId: mappedRoleId},
			WithAuthenticatedUserId(admin.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "upsert mapping: %s", string(r.Body))
		assert.Equal(t, "platform engineers", r.JSON200.GroupDisplayName)
		assert.Equal(t, mappedRoleId, r.JSON200.RoleId)

		l, err := client.ListScimGroupMappingsWithResponse(t.Context(), org.Id, WithAuthenticatedUserId(admin.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, l.StatusCode(), "list mappings: %s", string(l.Body))
		require.Len(t, l.JSON200.Items, 1)
		assert.Equal(t, mappedRoleId, l.JSON200.Items[0].RoleId)
	})

	// ------------------------------------------------------------------ provisioning + group membership

	scimBaseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), org.Id)
	userEmail := "mapped-" + uuid.New().String()[:8] + "@test.example"

	var scimUserId uuid.UUID
	t.Run("provisioned user starts on the Viewer fallback", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, scimBaseURL+"/Users", &scimCaller.Id, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: userEmail,
			Active:   true,
			Emails:   []testScimEmail{{Value: userEmail, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "body: %s", string(body))
		u := mustDecodeScimUser(t, body)
		scimUserId = uuid.MustParse(u.Id)

		_, roles := rolesHeldByEmail(t, client, org.Id, admin.Id, userEmail)
		assert.Equal(t, map[string]bool{viewerRoleId.String(): true}, roles, "no mapping applies yet → Viewer only")
	})

	var groupId uuid.UUID
	t.Run("adding the user to the mapped group swaps Viewer for the mapped role", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, scimBaseURL+"/Groups", &scimCaller.Id, testScimGroupBody{
			Schemas:     []string{testScimGroupSchema},
			DisplayName: groupName, // "Platform Engineers" vs the mapping's "platform engineers"
			Members:     []map[string]string{{"value": scimUserId.String()}},
		})
		require.Equal(t, http.StatusCreated, status, "create group: %s", string(body))
		g := mustDecodeScimGroup(t, body)
		groupId = uuid.MustParse(g.Id)

		_, roles := rolesHeldByEmail(t, client, org.Id, admin.Id, userEmail)
		assert.Equal(t, map[string]bool{mappedRoleId.String(): true}, roles,
			"user must hold exactly the mapped role — not Viewer")
	})

	t.Run("removing the user from the group falls back to Viewer", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Groups/%s", scimBaseURL, groupId), &scimCaller.Id, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "remove", Path: fmt.Sprintf(`members[value eq "%s"]`, scimUserId)},
			},
		})
		require.Equal(t, http.StatusOK, status, "remove member: %s", string(body))

		_, roles := rolesHeldByEmail(t, client, org.Id, admin.Id, userEmail)
		assert.Equal(t, map[string]bool{viewerRoleId.String(): true}, roles,
			"mapped role must be revoked, Viewer fallback restored")
	})

	t.Run("a manually granted membership survives reconciliation", func(t *testing.T) {
		// Put the user back in the mapped group.
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Groups/%s", scimBaseURL, groupId), &scimCaller.Id, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "add", Path: "members", Value: []map[string]string{{"value": scimUserId.String()}}},
			},
		})
		require.Equal(t, http.StatusOK, status, "re-add member: %s", string(body))

		globalUserId, roles := rolesHeldByEmail(t, client, org.Id, admin.Id, userEmail)
		require.Equal(t, map[string]bool{mappedRoleId.String(): true}, roles)
		require.NotEqual(t, uuid.Nil, globalUserId)

		// A human grants Deployer by hand.
		mm, err := internalClient.InternalCreateOrgMembershipWithResponse(t.Context(), org.Id,
			serverclient.InternalCreateOrgMembershipJSONRequestBody{
				UserId:      globalUserId,
				SubjectType: serverclient.SubjectTypeRole,
				Subject:     deployerRoleId.String(),
			})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, mm.StatusCode(), "manual membership: %s", string(mm.Body))

		// Pull the user out of the group again: the mapped role must go, the
		// manual Deployer must stay, and no Viewer is piled on top because the
		// user still has access through the manual grant.
		status, body = scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Groups/%s", scimBaseURL, groupId), &scimCaller.Id, testScimPatch{
			Schemas: []string{testScimPatchSchema},
			Operations: []testScimPatchOp{
				{Op: "remove", Path: fmt.Sprintf(`members[value eq "%s"]`, scimUserId)},
			},
		})
		require.Equal(t, http.StatusOK, status, "remove member again: %s", string(body))

		_, roles = rolesHeldByEmail(t, client, org.Id, admin.Id, userEmail)
		assert.Equal(t, map[string]bool{deployerRoleId.String(): true}, roles,
			"manual Deployer must survive; mapped role gone; no Viewer fallback on top of a manual grant")
	})

	t.Run("a mapping change applies to users already in the group without further SCIM traffic", func(t *testing.T) {
		// Provision a user and put them into a group FIRST, while no mapping
		// exists for that group.
		lateEmail := "late-" + uuid.New().String()[:8] + "@test.example"
		status, body := scimDo(t, http.MethodPost, scimBaseURL+"/Users", &scimCaller.Id, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: lateEmail,
			Active:   true,
			Emails:   []testScimEmail{{Value: lateEmail, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "provision late user: %s", string(body))
		lateScimUserId := uuid.MustParse(mustDecodeScimUser(t, body).Id)

		status, body = scimDo(t, http.MethodPost, scimBaseURL+"/Groups", &scimCaller.Id, testScimGroupBody{
			Schemas:     []string{testScimGroupSchema},
			DisplayName: "Late Binders",
			Members:     []map[string]string{{"value": lateScimUserId.String()}},
		})
		require.Equal(t, http.StatusCreated, status, "create late group: %s", string(body))

		_, roles := rolesHeldByEmail(t, client, org.Id, admin.Id, lateEmail)
		require.Equal(t, map[string]bool{viewerRoleId.String(): true}, roles, "no mapping yet → Viewer only")

		// NOW create the mapping (different casing, as usual). No SCIM request
		// follows — the upsert alone must reconcile the existing member.
		r, err := client.UpsertScimGroupMappingWithResponse(t.Context(), org.Id, "late binders",
			serverclient.UpsertScimGroupMappingJSONRequestBody{RoleId: mappedRoleId},
			WithAuthenticatedUserId(admin.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode(), "upsert late mapping: %s", string(r.Body))

		_, roles = rolesHeldByEmail(t, client, org.Id, admin.Id, lateEmail)
		assert.Equal(t, map[string]bool{mappedRoleId.String(): true}, roles,
			"the upsert alone must grant the mapped role to the existing group member")

		// And deleting the mapping must take it away again, restoring Viewer.
		d, err := client.DeleteScimGroupMappingWithResponse(t.Context(), org.Id, "Late Binders", WithAuthenticatedUserId(admin.Id))
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, d.StatusCode(), "delete late mapping: %s", string(d.Body))

		_, roles = rolesHeldByEmail(t, client, org.Id, admin.Id, lateEmail)
		assert.Equal(t, map[string]bool{viewerRoleId.String(): true}, roles,
			"the delete alone must revoke the mapped role and restore the Viewer fallback")
	})

	t.Run("mapping can be deleted and re-deleting yields 404", func(t *testing.T) {
		// Deletion is case-insensitive like the match itself.
		d, err := client.DeleteScimGroupMappingWithResponse(t.Context(), org.Id, "PLATFORM ENGINEERS", WithAuthenticatedUserId(admin.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, d.StatusCode(), "body: %s", string(d.Body))

		d2, err := client.DeleteScimGroupMappingWithResponse(t.Context(), org.Id, groupName, WithAuthenticatedUserId(admin.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, d2.StatusCode(), "body: %s", string(d2.Body))
	})
}

// TestScimGroupMemberDeleteCascade pins the FK cascade path: deleting a SCIM
// user who belongs to a group removes the scim_group_members row via ON DELETE
// CASCADE, not through the handler. The group must read back cleanly without
// the member (no dangling id, no error), and the deleted user's mapped role
// must be gone while the surviving member keeps theirs.
func TestScimGroupMemberDeleteCascade(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	baseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), orgId)

	// A mapped group, so the deleted member's role revocation is observable.
	mappedRole, err := client.CreateRoleWithResponse(t.Context(), orgId, serverclient.CreateRoleJSONRequestBody{
		DisplayName: "Cascade Mapped Role",
		Permissions: []string{authz.PermissionRoleRead},
	}, WithAuthenticatedUserId(adminId))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, mappedRole.StatusCode(), "create mapped role: %s", string(mappedRole.Body))
	mappedRoleId := mappedRole.JSON201.Id

	const groupName = "Cascade Crew"
	m, err := client.UpsertScimGroupMappingWithResponse(t.Context(), orgId, groupName,
		serverclient.UpsertScimGroupMappingJSONRequestBody{RoleId: mappedRoleId},
		WithAuthenticatedUserId(adminId))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, m.StatusCode(), "upsert mapping: %s", string(m.Body))

	provision := func(t *testing.T, email string) uuid.UUID {
		t.Helper()
		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
			Schemas:  []string{testScimUserSchema},
			UserName: email,
			Active:   true,
			Emails:   []testScimEmail{{Value: email, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "provision %s: %s", email, string(body))
		return uuid.MustParse(mustDecodeScimUser(t, body).Id)
	}
	doomedEmail := "cascade-doomed-" + uuid.New().String()[:8] + "@test.example"
	survivorEmail := "cascade-survivor-" + uuid.New().String()[:8] + "@test.example"
	doomedId := provision(t, doomedEmail)
	survivorId := provision(t, survivorEmail)

	status, body := scimDo(t, http.MethodPost, baseURL+"/Groups", &caller, testScimGroupBody{
		Schemas:     []string{testScimGroupSchema},
		DisplayName: groupName,
		Members: []map[string]string{
			{"value": doomedId.String()},
			{"value": survivorId.String()},
		},
	})
	require.Equal(t, http.StatusCreated, status, "create group: %s", string(body))
	groupId := uuid.MustParse(mustDecodeScimGroup(t, body).Id)

	// Both members hold the mapped role before the delete.
	_, doomedRoles := rolesHeldByEmail(t, client, orgId, adminId, doomedEmail)
	require.Equal(t, map[string]bool{mappedRoleId.String(): true}, doomedRoles)
	_, survivorRoles := rolesHeldByEmail(t, client, orgId, adminId, survivorEmail)
	require.Equal(t, map[string]bool{mappedRoleId.String(): true}, survivorRoles)

	status, body = scimDo(t, http.MethodDelete, fmt.Sprintf("%s/Users/%s", baseURL, doomedId), &caller, nil)
	require.Equal(t, http.StatusNoContent, status, "delete member: %s", string(body))

	t.Run("group reads back without the deleted member", func(t *testing.T) {
		status, body := scimDo(t, http.MethodGet, fmt.Sprintf("%s/Groups/%s", baseURL, groupId), &caller, nil)
		require.Equal(t, http.StatusOK, status, "get group after member delete: %s", string(body))
		g := mustDecodeScimGroup(t, body)
		require.Len(t, g.Members, 1, "only the survivor must remain")
		assert.Equal(t, survivorId.String(), g.Members[0]["value"], "no dangling id of the deleted member")
	})

	t.Run("deleted member's mapped role is gone, survivor keeps theirs", func(t *testing.T) {
		_, roles := rolesHeldByEmail(t, client, orgId, adminId, doomedEmail)
		assert.Empty(t, roles, "the deleted user must hold no roles in the org")
		_, roles = rolesHeldByEmail(t, client, orgId, adminId, survivorEmail)
		assert.Equal(t, map[string]bool{mappedRoleId.String(): true}, roles, "the survivor's mapped role must be untouched")
	})
}
