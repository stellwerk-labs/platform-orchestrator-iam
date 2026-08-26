package integrationtests

// Integration tests for the SCIM interop audit fixes that only a real
// database can prove: case-insensitive uniqueness and lookup (backed by the
// LOWER() indexes from migration 000035), PUT full-replace clearing omitted
// attributes, and the multi-org global profile ownership rule.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// scimListTotal runs a filtered list request and returns totalResults.
func scimListTotal(t *testing.T, baseURL, resource, filter string, caller uuid.UUID) int {
	t.Helper()
	params := url.Values{"filter": {filter}}
	status, body := scimDo(t, http.MethodGet, baseURL+"/"+resource+"?"+params.Encode(), &caller, nil)
	require.Equal(t, http.StatusOK, status, "filtered list: %s", string(body))
	var list struct {
		TotalResults int `json:"totalResults"`
	}
	require.NoError(t, json.Unmarshal(body, &list))
	return list.TotalResults
}

func TestScimCaseInsensitiveUniquenessAndLookup(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	baseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), orgId)

	suffix := uuid.New().String()[:8]
	userName := "Case.User-" + suffix + "@Test.Example"

	t.Run("user case-variant duplicate yields 409, lookup is case-insensitive, stored value keeps its case", func(t *testing.T) {
		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
			Schemas: []string{testScimUserSchema}, UserName: userName, Active: true,
		})
		require.Equal(t, http.StatusCreated, status, "body: %s", string(body))
		assert.Equal(t, userName, mustDecodeScimUser(t, body).UserName, "userName must be stored as supplied")

		// The same person, sent with different casing, is the same resource:
		// /Schemas says caseExact=false, so this must be a uniqueness conflict.
		status, body = scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
			Schemas: []string{testScimUserSchema}, UserName: "case.user-" + suffix + "@test.example", Active: true,
		})
		assert.Equal(t, http.StatusConflict, status, "case-variant duplicate must conflict: %s", string(body))

		// Entra filters with whatever casing its side stores; both must hit.
		assert.Equal(t, 1, scimListTotal(t, baseURL, "Users", fmt.Sprintf(`userName eq "CASE.USER-%s@TEST.EXAMPLE"`, suffix), caller))
		assert.Equal(t, 1, scimListTotal(t, baseURL, "Users", fmt.Sprintf(`userName eq "%s"`, userName), caller))
	})

	t.Run("group case-variant duplicate yields 409 and lookup is case-insensitive", func(t *testing.T) {
		groupName := "CaseGroup-" + suffix
		status, body := scimDo(t, http.MethodPost, baseURL+"/Groups", &caller, testScimGroupBody{
			Schemas: []string{testScimGroupSchema}, DisplayName: groupName,
		})
		require.Equal(t, http.StatusCreated, status, "body: %s", string(body))

		status, body = scimDo(t, http.MethodPost, baseURL+"/Groups", &caller, testScimGroupBody{
			Schemas: []string{testScimGroupSchema}, DisplayName: "casegroup-" + suffix,
		})
		assert.Equal(t, http.StatusConflict, status, "case-variant duplicate group must conflict: %s", string(body))

		assert.Equal(t, 1, scimListTotal(t, baseURL, "Groups", fmt.Sprintf(`displayName eq "CASEGROUP-%s"`, suffix), caller))
	})
}

func TestScimPutFullReplaceClearsOmittedAttributes(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	baseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), orgId)

	suffix := uuid.New().String()[:8]

	t.Run("PUT /Users without externalId and displayName clears both", func(t *testing.T) {
		userName := "put-user-" + suffix + "@test.example"
		externalId := "ext-put-" + suffix

		status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
			Schemas: []string{testScimUserSchema}, UserName: userName,
			DisplayName: "Putty McPutface", ExternalId: externalId, Active: true,
			Emails: []testScimEmail{{Value: userName, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "body: %s", string(body))
		scimId := uuid.MustParse(mustDecodeScimUser(t, body).Id)

		require.Equal(t, 1, scimListTotal(t, baseURL, "Users", fmt.Sprintf(`externalId eq "%s"`, externalId), caller))

		// Full replace with externalId and displayName omitted.
		status, body = scimDo(t, http.MethodPut, fmt.Sprintf("%s/Users/%s", baseURL, scimId), &caller, testScimUserBody{
			Schemas: []string{testScimUserSchema}, UserName: userName, Active: true,
		})
		require.Equal(t, http.StatusOK, status, "body: %s", string(body))

		assert.Equal(t, 0, scimListTotal(t, baseURL, "Users", fmt.Sprintf(`externalId eq "%s"`, externalId), caller),
			"a PUT that omits externalId must clear it")

		row, err := db.GetScimUser(t.Context(), nil, orgId, scimId)
		require.NoError(t, err)
		assert.False(t, row.ExternalId.IsSet(), "stored externalId must be cleared")

		globalUser, err := db.GetUser(t.Context(), nil, row.UserId)
		require.NoError(t, err)
		assert.Equal(t, userName, globalUser.DisplayName,
			"a PUT that omits displayName must reset it to the provisioning default (the userName)")
	})

	t.Run("PUT /Groups without externalId clears it", func(t *testing.T) {
		groupName := "put-group-" + suffix
		externalId := "grp-ext-put-" + suffix

		status, body := scimDo(t, http.MethodPost, baseURL+"/Groups", &caller, testScimGroupBody{
			Schemas: []string{testScimGroupSchema}, DisplayName: groupName, ExternalId: externalId,
		})
		require.Equal(t, http.StatusCreated, status, "body: %s", string(body))
		groupId := mustDecodeScimGroup(t, body).Id

		require.Equal(t, 1, scimListTotal(t, baseURL, "Groups", fmt.Sprintf(`externalId eq "%s"`, externalId), caller))

		status, body = scimDo(t, http.MethodPut, fmt.Sprintf("%s/Groups/%s", baseURL, groupId), &caller, testScimGroupBody{
			Schemas: []string{testScimGroupSchema}, DisplayName: groupName,
		})
		require.Equal(t, http.StatusOK, status, "body: %s", string(body))

		assert.Equal(t, 0, scimListTotal(t, baseURL, "Groups", fmt.Sprintf(`externalId eq "%s"`, externalId), caller),
			"a PUT that omits externalId must clear it")
	})
}

// TestScimMultiOrgProfileOwnership pins the design rule: the IDP-supplied
// display name and email land on the shared global user only while the
// calling organization holds the SOLE live SCIM record for that person. Two
// governing organizations means nobody renames the shared profile.
func TestScimMultiOrgProfileOwnership(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	orgAId, adminAId := mustScimOrgWithAdmin(t, client, internalClient)
	orgBId, adminBId := mustScimOrgWithAdmin(t, client, internalClient)
	callerA := mustProvisioningCaller(t, client, internalClient, orgAId, adminAId)
	callerB := mustProvisioningCaller(t, client, internalClient, orgBId, adminBId)

	baseA := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), orgAId)
	baseB := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), orgBId)

	email := "shared-person-" + uuid.New().String()[:8] + "@test.example"
	provision := func(t *testing.T, base string, caller uuid.UUID, externalId string) uuid.UUID {
		t.Helper()
		status, body := scimDo(t, http.MethodPost, base+"/Users", &caller, testScimUserBody{
			Schemas: []string{testScimUserSchema}, UserName: email,
			DisplayName: "Original Name", ExternalId: externalId, Active: true,
			Emails: []testScimEmail{{Value: email, Primary: true, Type: "work"}},
		})
		require.Equal(t, http.StatusCreated, status, "provision: %s", string(body))
		return uuid.MustParse(mustDecodeScimUser(t, body).Id)
	}

	scimIdA := provision(t, baseA, callerA, "ext-a-"+uuid.New().String()[:8])
	scimIdB := provision(t, baseB, callerB, "ext-b-"+uuid.New().String()[:8])

	rowA, err := db.GetScimUser(t.Context(), nil, orgAId, scimIdA)
	require.NoError(t, err)
	globalUserId := rowA.UserId

	patchDisplayName := func(t *testing.T, base string, caller, scimId uuid.UUID, name string) {
		t.Helper()
		status, body := scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", base, scimId), &caller, testScimPatch{
			Schemas:    []string{testScimPatchSchema},
			Operations: []testScimPatchOp{{Op: "replace", Path: "displayName", Value: name}},
		})
		require.Equal(t, http.StatusOK, status, "patch displayName: %s", string(body))
	}
	globalDisplayName := func(t *testing.T) string {
		t.Helper()
		u, err := db.GetUser(t.Context(), nil, globalUserId)
		require.NoError(t, err)
		return u.DisplayName
	}

	t.Run("rename while two orgs govern the user is skipped", func(t *testing.T) {
		patchDisplayName(t, baseB, callerB, scimIdB, "Org B Hostile Rename")
		assert.Equal(t, "Original Name", globalDisplayName(t),
			"no org's IDP may rename a person governed by more than one org")
	})

	t.Run("rename applies once the org is the sole governor", func(t *testing.T) {
		// Tombstone org A's record; org B becomes the sole live governor.
		status, body := scimDo(t, http.MethodDelete, fmt.Sprintf("%s/Users/%s", baseA, scimIdA), &callerA, nil)
		require.Equal(t, http.StatusNoContent, status, "delete in org A: %s", string(body))

		patchDisplayName(t, baseB, callerB, scimIdB, "Org B Legitimate Rename")
		assert.Equal(t, "Org B Legitimate Rename", globalDisplayName(t),
			"the sole governing org's IDP owns the shared profile")
	})
}

// TestScimExternalIdRekeyKeepsIdentityLookupWorking pins the identities
// rebinding: after the IDP changes a user's externalId, deleting and
// re-provisioning under the NEW key must resolve to the same global user via
// the identity lookup (no email in play, so nothing else can match).
func TestScimExternalIdRekeyKeepsIdentityLookupWorking(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)
	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	orgId, adminId := mustScimOrgWithAdmin(t, client, internalClient)
	caller := mustProvisioningCaller(t, client, internalClient, orgId, adminId)
	baseURL := fmt.Sprintf("%s/scim/v2/orgs/%s", mustInternalServerURL(t), orgId)

	suffix := uuid.New().String()[:8]
	// No "@" and no emails: the only way back to the global user is the
	// identity binding for the externalId.
	userName := "rekey-user-" + suffix
	oldExt := "ext-old-" + suffix
	newExt := "ext-new-" + suffix

	status, body := scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
		Schemas: []string{testScimUserSchema}, UserName: userName, ExternalId: oldExt, Active: true,
	})
	require.Equal(t, http.StatusCreated, status, "body: %s", string(body))
	scimId := uuid.MustParse(mustDecodeScimUser(t, body).Id)

	row, err := db.GetScimUser(t.Context(), nil, orgId, scimId)
	require.NoError(t, err)
	originalGlobalUserId := row.UserId

	// The IDP re-keys the user.
	status, body = scimDo(t, http.MethodPatch, fmt.Sprintf("%s/Users/%s", baseURL, scimId), &caller, testScimPatch{
		Schemas:    []string{testScimPatchSchema},
		Operations: []testScimPatchOp{{Op: "replace", Path: "externalId", Value: newExt}},
	})
	require.Equal(t, http.StatusOK, status, "rekey: %s", string(body))

	// Delete and re-provision under the NEW key only.
	status, body = scimDo(t, http.MethodDelete, fmt.Sprintf("%s/Users/%s", baseURL, scimId), &caller, nil)
	require.Equal(t, http.StatusNoContent, status, "delete: %s", string(body))

	status, body = scimDo(t, http.MethodPost, baseURL+"/Users", &caller, testScimUserBody{
		Schemas: []string{testScimUserSchema}, UserName: userName, ExternalId: newExt, Active: true,
	})
	require.Equal(t, http.StatusCreated, status, "re-provision: %s", string(body))
	newScimId := uuid.MustParse(mustDecodeScimUser(t, body).Id)

	newRow, err := db.GetScimUser(t.Context(), nil, orgId, newScimId)
	require.NoError(t, err)
	assert.Equal(t, originalGlobalUserId, newRow.UserId,
		"re-provisioning under the rebound externalId must resolve to the same global user, not mint a new one")
}
