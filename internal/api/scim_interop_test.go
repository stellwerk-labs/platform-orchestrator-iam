package api

// Tests for the external-audit interop fixes: PUT full-replace semantics,
// blank required attributes, the multi-org global profile ownership rule,
// externalId identity rebinding, and /Schemas sub-attribute completeness.
// Case-insensitive uniqueness lives in the integration tests — it is a
// database property that a mock cannot prove.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	mockmodel "github.com/stellwerk-labs/platform-orchestrator-iam/internal/model/mocks"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
)

// ------------------------------------------------------------------ PUT full replace (RFC 7644 §3.5.1)

// PUT with externalId and displayName omitted must clear both: externalId is
// dropped from the SCIM row, and the display name resets to the provisioning
// default (the userName) instead of being preserved.
func TestScimReplaceUser_OmittedAttributesAreCleared(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: globalUserId,
			UserName: "put.user@example.com", ExternalId: opt.Of("ext-put-1"), Active: true,
			CreatedAt: now, UpdatedAt: now,
		}, nil)

	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ interface{}, _ model.Tx, u model.ScimUser) error {
			assert.False(t, u.ExternalId.IsSet(), "omitted externalId must be cleared, not preserved")
			return nil
		})
	db.EXPECT().CountLiveScimUsersForUser(gomock.Any(), gomock.Not(nil), globalUserId).Return(1, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Not(nil), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Old Display Name"}, nil)
	db.EXPECT().UpdateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ interface{}, _ model.Tx, u *model.User) (*model.User, error) {
			assert.Equal(t, "put.user@example.com", u.DisplayName,
				"omitted displayName must reset to the provisioning default (the userName)")
			return u, nil
		})

	// Resource rendering after the update.
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "put.user@example.com"}, nil)

	body := ScimUserResource{
		Schemas:  []string{scimSchemaUser},
		UserName: "put.user@example.com",
		Active:   ref.Ref(boolOrString(true)),
		// externalId, displayName, emails deliberately omitted.
	}
	c, rec := scimRequest(t, e, http.MethodPut, "/", body, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimReplaceUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Empty(t, res.ExternalId, "cleared externalId must not come back in the response")
}

// PUT with a changed externalId must add the new identity binding so lookup by
// identity keeps working after the IDP re-keys the user.
func TestScimReplaceUser_ExternalIdChangeBindsNewIdentity(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: globalUserId,
			UserName: "rekey@example.com", ExternalId: opt.Of("ext-old"), Active: true,
			CreatedAt: now, UpdatedAt: now,
		}, nil)

	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ interface{}, _ model.Tx, u model.ScimUser) error {
			assert.Equal(t, opt.Of("ext-new"), u.ExternalId)
			return nil
		})
	db.EXPECT().AddUserIdentity(gomock.Any(), gomock.Not(nil), globalUserId, model.UserIdentityProviderScim, orgId+":ext-new").
		Return(nil)
	// The PUT omits displayName, so the full-replace rule also resets the
	// global display name to the userName (sole governing org).
	db.EXPECT().CountLiveScimUsersForUser(gomock.Any(), gomock.Not(nil), globalUserId).Return(1, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Not(nil), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Rekey"}, nil)
	db.EXPECT().UpdateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ interface{}, _ model.Tx, u *model.User) (*model.User, error) {
			assert.Equal(t, "rekey@example.com", u.DisplayName)
			return u, nil
		})
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "rekey@example.com"}, nil)

	body := ScimUserResource{
		Schemas:    []string{scimSchemaUser},
		UserName:   "rekey@example.com",
		ExternalId: "ext-new",
		Active:     ref.Ref(boolOrString(true)),
	}
	c, rec := scimRequest(t, e, http.MethodPut, "/", body, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimReplaceUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// PUT with an omitted externalId on a group must clear it, same rule as users.
func TestScimReplaceGroup_OmittedExternalIdIsCleared(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	groupId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimGroup(gomock.Any(), nil, orgId, groupId).
		Return(&model.ScimGroup{
			Id: groupId, OrgId: orgId, DisplayName: "Eng", ExternalId: opt.Of("grp-ext-1"),
			CreatedAt: now, UpdatedAt: now,
		}, nil)
	db.EXPECT().UpdateScimGroup(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ interface{}, _ model.Tx, g model.ScimGroup) error {
			assert.False(t, g.ExternalId.IsSet(), "omitted externalId must be cleared, not preserved")
			return nil
		})

	body := ScimGroupResource{
		Schemas:     []string{scimSchemaGroup},
		DisplayName: "Eng",
		// externalId deliberately omitted.
	}
	c, rec := scimRequest(t, e, http.MethodPut, "/", body, callerUserId, map[string]string{"orgId": orgId, "groupId": groupId.String()})
	require.NoError(t, s.handleScimReplaceGroup(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ------------------------------------------------------------------ blank required attributes

// Whitespace-only required values used to sail past the == "" checks and blow
// up on the database CHECK as a 500. They are 400 invalidValue.
func TestScimCreateUser_WhitespaceUserNameRejected(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimWriteAuth(s, callerUserId, orgId)

	body := map[string]interface{}{"schemas": []string{scimSchemaUser}, "userName": "   "}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateUser(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, scimTypeInvalidValue, errBody.ScimType)
}

func TestScimCreateGroup_WhitespaceDisplayNameRejected(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	mockScimWriteAuth(s, callerUserId, orgId)

	body := map[string]interface{}{"schemas": []string{scimSchemaGroup}, "displayName": "\t \n"}
	c, rec := scimRequest(t, e, http.MethodPost, "/", body, callerUserId, map[string]string{"orgId": orgId})
	require.NoError(t, s.handleScimCreateGroup(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, scimTypeInvalidValue, errBody.ScimType)
}

func TestScimPatchUser_WhitespaceUserNameRejected(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: userid.NewHumanUserId(),
			UserName: "ws@example.com", Active: true, CreatedAt: now, UpdatedAt: now,
		}, nil)

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "replace", Path: "userName", Value: json.RawMessage(`"   "`)}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, scimTypeInvalidValue, errBody.ScimType)
}

// userName is required: a remove op on it is invalid, not a silent no-op.
func TestScimPatchUser_RemoveUserNameRejected(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: userid.NewHumanUserId(),
			UserName: "keepme@example.com", Active: true, CreatedAt: now, UpdatedAt: now,
		}, nil)

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "remove", Path: "userName"}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errBody scimError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errBody))
	assert.Equal(t, scimTypeInvalidValue, errBody.ScimType)
}

// remove on displayName clears it: the global record resets to the userName,
// consistent with a PUT that omits it.
func TestScimPatchUser_RemoveDisplayNameResetsToUserName(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: globalUserId,
			UserName: "reset@example.com", Active: true, CreatedAt: now, UpdatedAt: now,
		}, nil)

	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Not(nil), gomock.Any()).Return(nil)
	db.EXPECT().CountLiveScimUsersForUser(gomock.Any(), gomock.Not(nil), globalUserId).Return(1, nil)
	db.EXPECT().GetUser(gomock.Any(), gomock.Not(nil), globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Custom Name"}, nil)
	db.EXPECT().UpdateUser(gomock.Any(), gomock.Not(nil), gomock.Any()).
		DoAndReturn(func(_ interface{}, _ model.Tx, u *model.User) (*model.User, error) {
			assert.Equal(t, "reset@example.com", u.DisplayName, "removed displayName must reset to the userName")
			return u, nil
		})
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "reset@example.com"}, nil)

	patchBody := scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: []scimPatchOp{{Op: "remove", Path: "displayName"}},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", patchBody, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ------------------------------------------------------------------ multi-org profile ownership

// When the user holds live SCIM records in more than one organization, no
// IDP owns the shared global profile: the write is skipped entirely (no
// GetUser/UpdateUser inside the transaction), and the SCIM row still updates.
func TestScimPatchUser_MultiOrgSkipsGlobalProfileWrite(t *testing.T) {
	e, s, fin := MockServer(t)
	defer fin()

	callerUserId := userid.NewServiceUserTokenId()
	scimUserId := uuid.New()
	globalUserId := userid.NewHumanUserId()
	now := time.Now().UTC()

	mockScimWriteAuth(s, callerUserId, orgId)

	db := s.Database.(*mockmodel.MockDatabaser)
	db.EXPECT().GetScimUser(gomock.Any(), nil, orgId, scimUserId).
		Return(&model.ScimUser{
			Id: scimUserId, OrgId: orgId, UserId: globalUserId,
			UserName: "shared@example.com", Active: true, CreatedAt: now, UpdatedAt: now,
		}, nil)

	db.EXPECT().UpdateScimUser(gomock.Any(), gomock.Not(nil), gomock.Any()).Return(nil)
	// Two orgs govern this user → the strict mock proves neither GetUser (in
	// the tx) nor UpdateUser is ever called.
	db.EXPECT().CountLiveScimUsersForUser(gomock.Any(), gomock.Not(nil), globalUserId).Return(2, nil)

	// Resource rendering after the update (outside the tx, nil Tx).
	db.EXPECT().GetUser(gomock.Any(), nil, globalUserId).
		Return(&model.User{Id: globalUserId, DisplayName: "Untouched Name"}, nil)

	body := map[string]interface{}{
		"schemas": []string{scimPatchOpSchema},
		"Operations": []map[string]interface{}{
			{"op": "replace", "path": "displayName", "value": "Org A Rename"},
		},
	}
	c, rec := scimRequest(t, e, http.MethodPatch, "/", body, callerUserId, map[string]string{"orgId": orgId, "userId": scimUserId.String()})
	require.NoError(t, s.handleScimPatchUser(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var res ScimUserResource
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "Untouched Name", res.DisplayName, "the shared profile must not be renamed by one of several governing orgs")
}

// ------------------------------------------------------------------ /Schemas sub-attributes

// Entra's SCIM validator consumes /Schemas; complex attributes must declare
// their sub-attributes or the document is useless for schema discovery.
func TestScimSchemas_ComplexAttributesDeclareSubAttributes(t *testing.T) {
	subAttrNames := func(t *testing.T, schema scimSchema, attrName string) []string {
		t.Helper()
		for _, attr := range schema.Attributes {
			if attr.Name != attrName {
				continue
			}
			require.Equal(t, scimAttrTypeComplex, attr.Type)
			names := make([]string, 0, len(attr.SubAttributes))
			for _, sub := range attr.SubAttributes {
				names = append(names, sub.Name)
				assert.NotEmpty(t, sub.Type, "sub-attribute %s.%s must declare a type", attrName, sub.Name)
				assert.NotEmpty(t, sub.Mutability, "sub-attribute %s.%s must declare mutability", attrName, sub.Name)
				assert.NotEmpty(t, sub.Returned, "sub-attribute %s.%s must declare returned", attrName, sub.Name)
				assert.NotEmpty(t, sub.Uniqueness, "sub-attribute %s.%s must declare uniqueness", attrName, sub.Name)
			}
			return names
		}
		t.Fatalf("attribute %s not found in schema %s", attrName, schema.Id)
		return nil
	}

	assert.ElementsMatch(t, []string{"value", "type", "primary", "display"},
		subAttrNames(t, staticUserSchema(), "emails"))
	assert.ElementsMatch(t, []string{"value", "$ref", "type", "display"},
		subAttrNames(t, staticGroupSchema(), "members"))
}
