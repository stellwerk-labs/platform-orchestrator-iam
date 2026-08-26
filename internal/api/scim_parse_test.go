package api

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ------------------------------------------------------------------ filter

func TestParseScimFilter_Empty(t *testing.T) {
	f, err := parseScimFilter("")
	require.NoError(t, err)
	assert.Nil(t, f)
}

func TestParseScimFilter_UserName(t *testing.T) {
	f, err := parseScimFilter(`userName eq "alice@example.com"`)
	require.NoError(t, err)
	require.NotNil(t, f)
	assert.Equal(t, "username", f.Attr)
	assert.Equal(t, "alice@example.com", f.Value)
}

func TestParseScimFilter_ExternalId(t *testing.T) {
	f, err := parseScimFilter(`externalId eq "ext-123"`)
	require.NoError(t, err)
	require.NotNil(t, f)
	assert.Equal(t, "externalid", f.Attr)
	assert.Equal(t, "ext-123", f.Value)
}

func TestParseScimFilter_CaseInsensitiveAttr(t *testing.T) {
	// Some IDPs send attribute names in different cases.
	f, err := parseScimFilter(`UserName eq "bob"`)
	require.NoError(t, err)
	require.NotNil(t, f)
	assert.Equal(t, "username", f.Attr)
}

func TestParseScimFilter_DisplayName(t *testing.T) {
	f, err := parseScimFilter(`displayName eq "Engineering"`)
	require.NoError(t, err)
	require.NotNil(t, f)
	assert.Equal(t, "displayname", f.Attr)
}

func TestParseScimFilter_RejectsAnd(t *testing.T) {
	_, err := parseScimFilter(`userName eq "a" and active eq "true"`)
	require.Error(t, err)
}

func TestParseScimFilter_RejectsComplex(t *testing.T) {
	_, err := parseScimFilter(`userName pr`)
	require.Error(t, err)
}

// ------------------------------------------------------------------ boolOrString

func TestBoolOrString_JsonBoolTrue(t *testing.T) {
	var b boolOrString
	require.NoError(t, json.Unmarshal([]byte(`true`), &b))
	assert.True(t, bool(b))
}

func TestBoolOrString_JsonBoolFalse(t *testing.T) {
	var b boolOrString
	require.NoError(t, json.Unmarshal([]byte(`false`), &b))
	assert.False(t, bool(b))
}

// Entra sends "True" / "False" without the aadOptscim062020 flag.
func TestBoolOrString_StringTrue(t *testing.T) {
	var b boolOrString
	require.NoError(t, json.Unmarshal([]byte(`"True"`), &b))
	assert.True(t, bool(b))
}

func TestBoolOrString_StringFalse(t *testing.T) {
	var b boolOrString
	require.NoError(t, json.Unmarshal([]byte(`"False"`), &b))
	assert.False(t, bool(b))
}

func TestBoolOrString_StringLowercase(t *testing.T) {
	var b boolOrString
	require.NoError(t, json.Unmarshal([]byte(`"false"`), &b))
	assert.False(t, bool(b))
}

func TestBoolOrString_InvalidString(t *testing.T) {
	var b boolOrString
	err := json.Unmarshal([]byte(`"yes"`), &b)
	require.Error(t, err)
}

// ------------------------------------------------------------------ PATCH normalization

func makePatchRequest(ops []scimPatchOp) scimPatchRequest {
	return scimPatchRequest{
		Schemas:    []string{scimPatchOpSchema},
		Operations: ops,
	}
}

// Entra sends capitalized op names.
func TestNormalizePatchOps_EntraCapitalizedOp(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "Replace", Path: "active", Value: json.RawMessage(`false`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.Equal(t, "replace", ops[0].Op)
	assert.Equal(t, "active", ops[0].Path)
	assert.False(t, *ops[0].BoolValue)
}

// Entra sends string booleans in PATCH values.
func TestNormalizePatchOps_EntraStringBoolTrue(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "Replace", Path: "active", Value: json.RawMessage(`"True"`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	bv := ops[0].BoolValue
	require.NotNil(t, bv)
	assert.True(t, *bv)
}

// Okta sends pathless replace with an object value.
func TestNormalizePatchOps_OktaPathlessObject(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "replace", Value: json.RawMessage(`{"active":false,"userName":"alice"}`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)

	byPath := map[string]normalizedScimPatchOp{}
	for _, op := range ops {
		byPath[op.Path] = op
	}

	require.Contains(t, byPath, "active")
	assert.False(t, *byPath["active"].BoolValue)

	require.Contains(t, byPath, "username")
	assert.Equal(t, "alice", *byPath["username"].StrValue)
}

// Entra bracket member remove: `members[value eq "id"]`.
func TestNormalizePatchOps_EntraBracketMemberRemove(t *testing.T) {
	memberId := uuid.New()
	path := `members[value eq "` + memberId.String() + `"]`
	req := makePatchRequest([]scimPatchOp{
		{Op: "remove", Path: path},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.Equal(t, "remove", ops[0].Op)
	assert.Equal(t, "members", ops[0].Path)
	assert.True(t, ops[0].IsBracketMemberRemove)
	require.Len(t, ops[0].MemberIds, 1)
	assert.Equal(t, memberId, ops[0].MemberIds[0])
}

// Standard member add with value list.
func TestNormalizePatchOps_MemberAdd(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()
	valJSON, _ := json.Marshal([]map[string]string{
		{"value": id1.String()},
		{"value": id2.String()},
	})
	req := makePatchRequest([]scimPatchOp{
		{Op: "add", Path: "members", Value: json.RawMessage(valJSON)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.Equal(t, "add", ops[0].Op)
	assert.ElementsMatch(t, []uuid.UUID{id1, id2}, ops[0].MemberIds)
}

// Unknown attributes in PATCH ops must be silently dropped, not errored.
func TestNormalizePatchOps_UnknownAttrIgnored(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "replace", Path: "phoneNumbers", Value: json.RawMessage(`"555-0100"`)},
		{Op: "replace", Path: "active", Value: json.RawMessage(`true`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	// phoneNumbers is silently dropped; active remains.
	require.Len(t, ops, 1)
	assert.Equal(t, "active", ops[0].Path)
}

func TestNormalizePatchOps_UnknownOpErrors(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "upsert", Path: "active", Value: json.RawMessage(`true`)},
	})
	_, err := normalizePatchOps(req)
	require.Error(t, err)
}

// A hand-built json.UnmarshalTypeError with a nil Type used to panic the
// moment anything formatted it; the replacement must be a plain error.
func TestBoolOrString_InvalidStringErrorFormatsWithoutPanic(t *testing.T) {
	var b boolOrString
	err := json.Unmarshal([]byte(`"yes"`), &b)
	require.Error(t, err)
	require.NotPanics(t, func() {
		assert.Contains(t, err.Error(), "yes")
	})
}

// A whitespace-only filter parses to (nil, nil), not an error.
func TestParseScimFilter_WhitespaceOnly(t *testing.T) {
	f, err := parseScimFilter("   ")
	require.NoError(t, err)
	assert.Nil(t, f)
}

// RFC 7644 §3.5.2.2: remove on "members" with no value removes ALL members.
func TestNormalizePatchOps_RemoveMembersNoValueIsRemoveAll(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "remove", Path: "members"},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.Equal(t, "remove", ops[0].Op)
	assert.Equal(t, "members", ops[0].Path)
	assert.True(t, ops[0].RemoveAll)
	assert.Empty(t, ops[0].MemberIds)
}

// A scalar remove with no value must still produce an op so handlers can
// clear the attribute (e.g. externalId).
func TestNormalizePatchOps_RemoveExternalIdNoValue(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "remove", Path: "externalId"},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.Equal(t, "remove", ops[0].Op)
	assert.Equal(t, "externalid", ops[0].Path)
	assert.Nil(t, ops[0].StrValue)
}

// The bracket member path selects an existing member; only remove may use it.
func TestNormalizePatchOps_BracketPathAddRejected(t *testing.T) {
	path := `members[value eq "` + uuid.New().String() + `"]`
	for _, op := range []string{"add", "replace"} {
		req := makePatchRequest([]scimPatchOp{{Op: op, Path: path}})
		_, err := normalizePatchOps(req)
		require.Error(t, err, "op %s must be rejected", op)
		var pe *scimPatchError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, "invalidPath", pe.ScimType)
	}
}

// Legacy Entra builds send a single member object instead of an array.
func TestNormalizePatchOps_LegacyEntraSingleMemberObject(t *testing.T) {
	memberId := uuid.New()
	req := makePatchRequest([]scimPatchOp{
		{Op: "add", Path: "members", Value: json.RawMessage(`{"value":"` + memberId.String() + `"}`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	require.Len(t, ops[0].MemberIds, 1)
	assert.Equal(t, memberId, ops[0].MemberIds[0])
}

// Genuinely malformed member values must still be rejected.
func TestNormalizePatchOps_MalformedMemberValueRejected(t *testing.T) {
	for _, val := range []string{`{"foo":"bar"}`, `"garbage"`, `{"value":"not-a-uuid"}`} {
		req := makePatchRequest([]scimPatchOp{
			{Op: "add", Path: "members", Value: json.RawMessage(val)},
		})
		_, err := normalizePatchOps(req)
		require.Error(t, err, "value %s must be rejected", val)
		var pe *scimPatchError
		require.ErrorAs(t, err, &pe)
		assert.Equal(t, "invalidValue", pe.ScimType)
	}
}

// ------------------------------------------------------------------ emails (D18)

// An emails-targeted PATCH with an array value takes the primary entry.
func TestNormalizePatchOps_EmailsArrayTakesPrimary(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "Replace", Path: "emails", Value: json.RawMessage(
			`[{"value":"secondary@example.com","type":"home"},{"value":"primary@example.com","type":"work","primary":true}]`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.Equal(t, scimAttrEmails, ops[0].Path)
	require.NotNil(t, ops[0].StrValue)
	assert.Equal(t, "primary@example.com", *ops[0].StrValue)
}

// Without a primary flag the first entry wins.
func TestNormalizePatchOps_EmailsArrayFallsBackToFirst(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "replace", Path: "emails", Value: json.RawMessage(
			`[{"value":"first@example.com"},{"value":"second@example.com"}]`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	require.NotNil(t, ops[0].StrValue)
	assert.Equal(t, "first@example.com", *ops[0].StrValue)
}

// A single email object (not wrapped in an array) is accepted too.
func TestNormalizePatchOps_EmailsSingleObject(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "replace", Path: "emails", Value: json.RawMessage(`{"value":"solo@example.com","type":"work"}`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	require.NotNil(t, ops[0].StrValue)
	assert.Equal(t, "solo@example.com", *ops[0].StrValue)
}

// The Entra/Okta bracket form `emails[type eq "work"].value` carries a plain string.
func TestNormalizePatchOps_EmailsBracketForm(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "Replace", Path: `emails[type eq "work"].value`, Value: json.RawMessage(`"bracket@example.com"`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.Equal(t, scimAttrEmails, ops[0].Path)
	require.NotNil(t, ops[0].StrValue)
	assert.Equal(t, "bracket@example.com", *ops[0].StrValue)
}

// Okta pathless replace carrying emails in the value object.
func TestNormalizePatchOps_OktaPathlessEmails(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "replace", Value: json.RawMessage(`{"emails":[{"value":"okta@example.com","primary":true}]}`)},
	})
	ops, err := normalizePatchOps(req)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.Equal(t, scimAttrEmails, ops[0].Path)
	require.NotNil(t, ops[0].StrValue)
	assert.Equal(t, "okta@example.com", *ops[0].StrValue)
}

// A garbage emails value must yield invalidValue, not a silent drop.
func TestNormalizePatchOps_EmailsMalformedRejected(t *testing.T) {
	req := makePatchRequest([]scimPatchOp{
		{Op: "replace", Path: "emails", Value: json.RawMessage(`12345`)},
	})
	_, err := normalizePatchOps(req)
	require.Error(t, err)
	var pe *scimPatchError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "invalidValue", pe.ScimType)
}

// ------------------------------------------------------------------ PatchOp body validation (RFC 7644 §3.5.2)

// A body whose schemas does not carry the PatchOp URN is not a PATCH request.
func TestNormalizePatchOps_MissingPatchOpSchemaRejected(t *testing.T) {
	req := scimPatchRequest{
		Schemas:    []string{scimSchemaUser},
		Operations: []scimPatchOp{{Op: "replace", Path: "active", Value: json.RawMessage(`true`)}},
	}
	_, err := normalizePatchOps(req)
	var pe *scimPatchError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, scimTypeInvalidSyntax, pe.ScimType)
}

func TestNormalizePatchOps_AbsentSchemasRejected(t *testing.T) {
	req := scimPatchRequest{
		Operations: []scimPatchOp{{Op: "replace", Path: "active", Value: json.RawMessage(`true`)}},
	}
	_, err := normalizePatchOps(req)
	var pe *scimPatchError
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, scimTypeInvalidSyntax, pe.ScimType)
}

func TestNormalizePatchOps_EmptyOperationsRejected(t *testing.T) {
	for name, ops := range map[string][]scimPatchOp{
		"absent": nil,
		"empty":  {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := normalizePatchOps(makePatchRequest(ops))
			var pe *scimPatchError
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, scimTypeInvalidValue, pe.ScimType)
		})
	}
}
