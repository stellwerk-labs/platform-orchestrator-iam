package api

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	scimContentType = "application/scim+json"

	scimSchemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimSchemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"

	scimListResponseSchema    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema           = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchOpSchema         = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimServiceProviderSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

	scimSchemaIdUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimSchemaIdGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"

	// Normalised resource type names.
	scimResourceTypeUser  = "User"
	scimResourceTypeGroup = "Group"

	// Normalised (lower-case) SCIM attribute names used in PATCH path matching.
	scimAttrActive      = "active"
	scimAttrUserName    = "username"
	scimAttrExternalId  = "externalid"
	scimAttrDisplayName = "displayname"
	scimAttrMembers     = "members"

	// PATCH op names (lower-case).
	scimOpAdd     = "add"
	scimOpReplace = "replace"
	scimOpRemove  = "remove"

	// Schema attribute property values.
	scimReturnedDefault = "default"
	scimUniquenessNone  = "none"
	scimMutabilityRW    = "readWrite"

	// Schema attribute type names.
	scimAttrTypeString  = "string"
	scimAttrTypeBoolean = "boolean"
	scimAttrTypeComplex = "complex"
)

// boolOrString handles both JSON booleans and the string "True"/"False"/"true"/"false"
// that Entra sends without the aadOptscim062020 flag.
type boolOrString bool

func (b *boolOrString) UnmarshalJSON(data []byte) error {
	// Try a plain boolean first.
	var plain bool
	if err := json.Unmarshal(data, &plain); err == nil {
		*b = boolOrString(plain)
		return nil
	}
	// Fall back to a string.
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "true":
		*b = true
	case "false":
		*b = false
	default:
		return &json.UnmarshalTypeError{Value: "string " + s, Type: nil}
	}
	return nil
}

func (b boolOrString) MarshalJSON() ([]byte, error) {
	return json.Marshal(bool(b))
}

// scimEmail represents a single email entry in a User resource.
type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// scimMeta holds the meta sub-object in every SCIM resource.
type scimMeta struct {
	ResourceType string    `json:"resourceType,omitempty"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
}

// ScimUserResource is the full SCIM User wire representation.
type ScimUserResource struct {
	Schemas     []string     `json:"schemas"`
	Id          uuid.UUID    `json:"id"`
	ExternalId  string       `json:"externalId,omitempty"`
	UserName    string       `json:"userName"`
	DisplayName string       `json:"displayName,omitempty"`
	Active      boolOrString `json:"active"`
	Emails      []scimEmail  `json:"emails,omitempty"`
	Meta        scimMeta     `json:"meta,omitempty"`
}

// scimGroupMember is one entry in a Group's members array.
type scimGroupMember struct {
	Value string `json:"value"`
}

// ScimGroupResource is the full SCIM Group wire representation.
type ScimGroupResource struct {
	Schemas     []string          `json:"schemas"`
	Id          uuid.UUID         `json:"id"`
	ExternalId  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []scimGroupMember `json:"members,omitempty"`
	Meta        scimMeta          `json:"meta,omitempty"`
}

// scimListResponse wraps paginated results per RFC 7644 §3.4.2.
type scimListResponse struct {
	Schemas      []string    `json:"schemas"`
	TotalResults int         `json:"totalResults"`
	StartIndex   int         `json:"startIndex"`
	ItemsPerPage int         `json:"itemsPerPage"`
	Resources    interface{} `json:"Resources"`
}

// scimError is the SCIM error body per RFC 7644 §3.12.
type scimError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// scimPatchOp is a single operation inside a PatchOp body.
// Op is matched case-insensitively (Entra sends capitalized: "Replace").
// Value is raw JSON so we can handle both scalar and object payloads.
type scimPatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// scimPatchRequest is the top-level PatchOp body.
type scimPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []scimPatchOp `json:"Operations"`
}

// normalizedOp returns the op name normalised to lowercase.
func (o scimPatchOp) normalizedOp() string {
	return strings.ToLower(o.Op)
}

// scimSupportedFeature describes a feature flag in ServiceProviderConfig.
type scimSupportedFeature struct {
	Supported bool `json:"supported"`
}

type scimSupportedFeatureWithMaxResults struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults,omitempty"`
}

type scimAuthScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type scimServiceProviderConfig struct {
	Schemas               []string                           `json:"schemas"`
	DocumentationURI      string                             `json:"documentationUri,omitempty"`
	Patch                 scimSupportedFeature               `json:"patch"`
	Bulk                  scimSupportedFeature               `json:"bulk"`
	Filter                scimSupportedFeatureWithMaxResults `json:"filter"`
	ChangePassword        scimSupportedFeature               `json:"changePassword"`
	Sort                  scimSupportedFeature               `json:"sort"`
	ETag                  scimSupportedFeature               `json:"etag"`
	AuthenticationSchemes []scimAuthScheme                   `json:"authenticationSchemes"`
	Meta                  scimMeta                           `json:"meta,omitempty"`
}

// staticServiceProviderConfig returns the static ServiceProviderConfig document.
func staticServiceProviderConfig() scimServiceProviderConfig {
	return scimServiceProviderConfig{
		Schemas:        []string{scimServiceProviderSchema},
		Patch:          scimSupportedFeature{Supported: true},
		Bulk:           scimSupportedFeature{Supported: false},
		Filter:         scimSupportedFeatureWithMaxResults{Supported: true, MaxResults: 200},
		ChangePassword: scimSupportedFeature{Supported: false},
		Sort:           scimSupportedFeature{Supported: false},
		ETag:           scimSupportedFeature{Supported: false},
		AuthenticationSchemes: []scimAuthScheme{
			{Type: "oauthbearertoken", Name: "OAuth Bearer Token", Description: "Authentication using an OAuth2 bearer token"},
		},
	}
}

// scimSchemaAttribute describes a single attribute in a schema document.
type scimSchemaAttribute struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	MultiValued bool   `json:"multiValued"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
	CaseExact   bool   `json:"caseExact"`
	Mutability  string `json:"mutability"`
	Returned    string `json:"returned"`
	Uniqueness  string `json:"uniqueness"`
}

type scimSchema struct {
	Schemas     []string              `json:"schemas"`
	Id          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	Attributes  []scimSchemaAttribute `json:"attributes"`
	Meta        scimMeta              `json:"meta,omitempty"`
}

const scimSchemaDefinitionSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema"

func staticUserSchema() scimSchema {
	return scimSchema{
		Schemas:     []string{scimSchemaDefinitionSchema},
		Id:          scimSchemaIdUser,
		Name:        scimResourceTypeUser,
		Description: "User Account",
		Attributes: []scimSchemaAttribute{
			{Name: "userName", Type: scimAttrTypeString, MultiValued: false, Required: true, CaseExact: false, Mutability: scimMutabilityRW, Returned: scimReturnedDefault, Uniqueness: "server"},
			{Name: "displayName", Type: scimAttrTypeString, MultiValued: false, Required: false, CaseExact: false, Mutability: scimMutabilityRW, Returned: scimReturnedDefault, Uniqueness: scimUniquenessNone},
			{Name: scimAttrActive, Type: scimAttrTypeBoolean, MultiValued: false, Required: false, CaseExact: false, Mutability: scimMutabilityRW, Returned: scimReturnedDefault, Uniqueness: scimUniquenessNone},
			{Name: "emails", Type: scimAttrTypeComplex, MultiValued: true, Required: false, CaseExact: false, Mutability: scimMutabilityRW, Returned: scimReturnedDefault, Uniqueness: scimUniquenessNone},
			{Name: "externalId", Type: scimAttrTypeString, MultiValued: false, Required: false, CaseExact: true, Mutability: scimMutabilityRW, Returned: scimReturnedDefault, Uniqueness: scimUniquenessNone},
		},
	}
}

func staticGroupSchema() scimSchema {
	return scimSchema{
		Schemas:     []string{scimSchemaDefinitionSchema},
		Id:          scimSchemaIdGroup,
		Name:        scimResourceTypeGroup,
		Description: scimResourceTypeGroup,
		Attributes: []scimSchemaAttribute{
			{Name: "displayName", Type: scimAttrTypeString, MultiValued: false, Required: true, CaseExact: false, Mutability: scimMutabilityRW, Returned: scimReturnedDefault, Uniqueness: "server"},
			{Name: scimAttrMembers, Type: scimAttrTypeComplex, MultiValued: true, Required: false, CaseExact: false, Mutability: scimMutabilityRW, Returned: scimReturnedDefault, Uniqueness: scimUniquenessNone},
			{Name: "externalId", Type: scimAttrTypeString, MultiValued: false, Required: false, CaseExact: true, Mutability: scimMutabilityRW, Returned: scimReturnedDefault, Uniqueness: scimUniquenessNone},
		},
	}
}

type scimResourceType struct {
	Schemas     []string `json:"schemas"`
	Id          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Endpoint    string   `json:"endpoint"`
	Schema      string   `json:"schema"`
	Meta        scimMeta `json:"meta,omitempty"`
}

const scimResourceTypeSchema = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"

func staticUserResourceType() scimResourceType {
	return scimResourceType{
		Schemas:     []string{scimResourceTypeSchema},
		Id:          scimResourceTypeUser,
		Name:        scimResourceTypeUser,
		Description: "User Account",
		Endpoint:    "/Users",
		Schema:      scimSchemaIdUser,
	}
}

func staticGroupResourceType() scimResourceType {
	return scimResourceType{
		Schemas:     []string{scimResourceTypeSchema},
		Id:          scimResourceTypeGroup,
		Name:        scimResourceTypeGroup,
		Description: scimResourceTypeGroup,
		Endpoint:    "/Groups",
		Schema:      scimSchemaIdGroup,
	}
}
