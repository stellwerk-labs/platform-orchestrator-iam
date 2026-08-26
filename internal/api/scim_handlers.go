package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/opt"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	sharedauthz "github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
)

// registerScimRoutes attaches SCIM routes to the given Echo group.
// It is called from MapRoutes after RegisterHandlers.
func (s *Server) registerScimRoutes(e *echo.Echo) {
	base := e.Group("/scim/v2/orgs/:orgId", scimErrorEnvelopeMiddleware)

	// Discovery endpoints are static documents containing no tenant data.
	// RFC 7644 §4 permits serving them unauthenticated, and Entra's SCIM
	// Validator probes them without a token, so they skip scimAuthMiddleware
	// and carry no permission check.
	base.GET("/ServiceProviderConfig", s.handleScimServiceProviderConfig)
	base.GET("/Schemas", s.handleScimSchemas)
	base.GET("/Schemas/:schemaId", s.handleScimSchema)
	base.GET("/ResourceTypes", s.handleScimResourceTypes)
	base.GET("/ResourceTypes/:typeId", s.handleScimResourceType)

	// Everything below carries tenant data and stays authenticated + authorized.
	g := base.Group("", s.scimAuthMiddleware)

	g.GET("/Users", s.handleScimListUsers)
	g.POST("/Users", s.handleScimCreateUser)
	g.GET("/Users/:userId", s.handleScimGetUser)
	g.PUT("/Users/:userId", s.handleScimReplaceUser)
	g.PATCH("/Users/:userId", s.handleScimPatchUser)
	g.DELETE("/Users/:userId", s.handleScimDeleteUser)

	g.GET("/Groups", s.handleScimListGroups)
	g.POST("/Groups", s.handleScimCreateGroup)
	g.GET("/Groups/:groupId", s.handleScimGetGroup)
	g.PUT("/Groups/:groupId", s.handleScimReplaceGroup)
	g.PATCH("/Groups/:groupId", s.handleScimPatchGroup)
	g.DELETE("/Groups/:groupId", s.handleScimDeleteGroup)
}

// scimAuthMiddleware reads the authenticated user id from the `From` header
// (already set by Envoy ext-auth / the internal/authenticate path) and stores
// it in the Echo context via hecho.ContextKeyUserID so that GetAuthenticatedUserId
// works just like it does in the generated strict handlers.
//
// Authorization (provisioning_read / provisioning_write) is checked per-handler
// because the required permission differs by HTTP method.
func (s *Server) scimAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		fromHeader := c.Request().Header.Get(authenticatedUserIdHeader)
		if fromHeader == "" {
			return scimErrorResp(c, http.StatusUnauthorized, "", "missing authentication header")
		}
		if _, err := uuid.Parse(fromHeader); err != nil {
			return scimErrorResp(c, http.StatusUnauthorized, "", "invalid authentication header")
		}
		c.SetRequest(c.Request().WithContext(
			context.WithValue(c.Request().Context(), hecho.ContextKeyUserID, fromHeader),
		))
		return next(c)
	}
}

// scimCheckAuth extracts the calling user id and enforces the given Casbin permission
// on the org identified by the `:orgId` path param.
//
// Returns (uid, true) on success. On failure it writes the SCIM error body and
// returns (uuid.Nil, false) — callers must return nil immediately (the response is
// already committed; there is nothing more to write).
func (s *Server) scimCheckAuth(c echo.Context, permission string) (uuid.UUID, bool) {
	uid, err := GetAuthenticatedUserId(c.Request().Context())
	if err != nil {
		_ = scimErrorResp(c, http.StatusUnauthorized, "", "unauthenticated")
		return uuid.Nil, false
	}
	orgId := c.Param("orgId")
	if err := s.checkOrgAuthorization(c.Request().Context(), uid, orgId, permission); err != nil {
		_ = scimErrorResp(c, http.StatusForbidden, "", "insufficient permissions")
		return uuid.Nil, false
	}
	return uid, true
}

// scimErrorEnvelopeMiddleware converts errors bubbling out of SCIM handlers into
// a SCIM Error envelope (RFC 7644 §3.12) instead of echo's default {"message":...}
// body. The error is still returned so the server's error handler logs it as
// usual (it skips writing once the response is committed).
func scimErrorEnvelopeMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err != nil && !c.Response().Committed {
			_ = scimErrorResp(c, http.StatusInternalServerError, "", "internal server error")
		}
		return err
	}
}

// scimErrorResp writes a SCIM-compliant error body and returns the error so callers
// can `return scimErrorResp(...)` in one line.
func scimErrorResp(c echo.Context, status int, scimType, detail string) error {
	body := scimError{
		Schemas:  []string{scimErrorSchema},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	}
	c.Response().Header().Set(echo.HeaderContentType, scimContentType)
	return c.JSON(status, body)
}

// scimJSON is a tiny helper that sets the SCIM content-type and writes JSON.
func scimJSON(c echo.Context, status int, body interface{}) error {
	c.Response().Header().Set(echo.HeaderContentType, scimContentType)
	return c.JSON(status, body)
}

// scimPatchErrorResp maps a normalizePatchOps failure onto the scimType it
// carries; plain errors are malformed request structure → invalidSyntax.
func scimPatchErrorResp(c echo.Context, err error) error {
	var pe *scimPatchError
	if errors.As(err, &pe) {
		return scimErrorResp(c, http.StatusBadRequest, pe.ScimType, pe.Detail)
	}
	return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidSyntax, err.Error())
}

// ------------------------------------------------------------------ static
//
// The discovery handlers below deliberately perform NO authentication or
// authorization: they serve fixed protocol documents with no tenant data
// (see registerScimRoutes).

func (s *Server) handleScimServiceProviderConfig(c echo.Context) error {
	return scimJSON(c, http.StatusOK, staticServiceProviderConfig())
}

func (s *Server) handleScimSchemas(c echo.Context) error {
	schemas := []scimSchema{staticUserSchema(), staticGroupSchema()}
	return scimJSON(c, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: len(schemas),
		StartIndex:   1,
		ItemsPerPage: len(schemas),
		Resources:    schemas,
	})
}

func (s *Server) handleScimSchema(c echo.Context) error {
	schemaId := c.Param("schemaId")
	switch schemaId {
	case scimSchemaIdUser:
		return scimJSON(c, http.StatusOK, staticUserSchema())
	case scimSchemaIdGroup:
		return scimJSON(c, http.StatusOK, staticGroupSchema())
	default:
		return scimErrorResp(c, http.StatusNotFound, "", "schema not found")
	}
}

func (s *Server) handleScimResourceTypes(c echo.Context) error {
	types := []scimResourceType{staticUserResourceType(), staticGroupResourceType()}
	return scimJSON(c, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: len(types),
		StartIndex:   1,
		ItemsPerPage: len(types),
		Resources:    types,
	})
}

func (s *Server) handleScimResourceType(c echo.Context) error {
	switch c.Param("typeId") {
	case scimResourceTypeUser:
		return scimJSON(c, http.StatusOK, staticUserResourceType())
	case scimResourceTypeGroup:
		return scimJSON(c, http.StatusOK, staticGroupResourceType())
	default:
		return scimErrorResp(c, http.StatusNotFound, "", "resource type not found")
	}
}

// ------------------------------------------------------------------ Users

func (s *Server) handleScimListUsers(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	startIndex, count := scimPageParams(c)

	if filterStr := c.QueryParam("filter"); filterStr != "" {
		f, err := parseScimFilter(filterStr)
		if err != nil {
			return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidFilter, err.Error())
		}
		// A whitespace-only filter parses to nil; treat it as no filter.
		if f != nil {
			return s.handleScimListUsersFiltered(c, orgId, f)
		}
	}

	total, err := s.Database.CountScimUsers(c.Request().Context(), nil, orgId)
	if err != nil {
		return errors.Wrap(err, "count scim users")
	}
	users, err := s.Database.ListScimUsers(c.Request().Context(), nil, orgId, count, startIndex-1)
	if err != nil {
		return errors.Wrap(err, "list scim users")
	}
	globalUsers, err := s.globalUsersForScimUsers(c.Request().Context(), users)
	if err != nil {
		return errors.Wrap(err, "load global users for scim list")
	}
	resources := make([]ScimUserResource, 0, len(users))
	for _, u := range users {
		resources = append(resources, scimUserResource(c, orgId, u, globalUsers[u.UserId]))
	}
	return scimJSON(c, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (s *Server) handleScimListUsersFiltered(c echo.Context, orgId string, f *scimFilterResult) error {
	ctx := c.Request().Context()
	var user *model.ScimUser
	var err error
	switch f.Attr {
	case scimAttrUserName:
		user, err = s.Database.FindScimUserByUserName(ctx, nil, orgId, f.Value)
	case scimAttrExternalId:
		user, err = s.Database.FindScimUserByExternalId(ctx, nil, orgId, f.Value)
	default:
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidFilter, fmt.Sprintf("unsupported filter attribute %q", f.Attr))
	}
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimJSON(c, http.StatusOK, scimListResponse{
				Schemas:      []string{scimListResponseSchema},
				TotalResults: 0,
				StartIndex:   1,
				ItemsPerPage: 0,
				Resources:    []ScimUserResource{},
			})
		}
		return err
	}
	return scimJSON(c, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: 1,
		StartIndex:   1,
		ItemsPerPage: 1,
		Resources:    []ScimUserResource{s.scimUserToResource(c, orgId, *user)},
	})
}

func (s *Server) handleScimCreateUser(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	logger := scimLogger(s, c.Request().Context())

	var body ScimUserResource
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidSyntax, "invalid JSON body")
	}
	// Whitespace-only would slip past an == "" check and blow up on the
	// database CHECK as a 500; reject it here as the 400 it is.
	if strings.TrimSpace(body.UserName) == "" {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, "userName is required and must not be blank")
	}

	active := true
	if body.Active != nil {
		active = bool(*body.Active)
	}
	input := scimProvisionUserInput{
		OrgId:       orgId,
		UserName:    body.UserName,
		DisplayName: body.DisplayName,
		ExternalId:  body.ExternalId,
		Active:      active,
		Email:       scimPrimaryEmail(body.Emails),
	}

	scimUser, err := s.scimProvisionUser(c.Request().Context(), logger, input)
	if err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, scimTypeUniqueness, err.Error())
		}
		return err
	}
	return scimJSON(c, http.StatusCreated, s.scimUserToResource(c, orgId, *scimUser))
}

func (s *Server) handleScimGetUser(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		return scimErrorResp(c, http.StatusNotFound, "", "user not found")
	}
	user, err := s.Database.GetScimUser(c.Request().Context(), nil, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "user not found")
		}
		return err
	}
	return scimJSON(c, http.StatusOK, s.scimUserToResource(c, orgId, *user))
}

func (s *Server) handleScimReplaceUser(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	logger := scimLogger(s, c.Request().Context())

	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		return scimErrorResp(c, http.StatusNotFound, "", "user not found")
	}
	existing, err := s.Database.GetScimUser(c.Request().Context(), nil, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "user not found")
		}
		return err
	}

	var body ScimUserResource
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidSyntax, "invalid JSON body")
	}
	if strings.TrimSpace(body.UserName) == "" {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, "userName is required and must not be blank")
	}

	// PUT is a full replace (RFC 7644 §3.5.1): writable attributes the IDP
	// omits are cleared, not preserved.
	updated := *existing
	updated.UserName = body.UserName
	updated.Active = true
	if body.Active != nil {
		updated.Active = bool(*body.Active)
	}
	updated.ExternalId = opt.Empty[string]()
	if body.ExternalId != "" {
		updated.ExternalId = opt.Of(body.ExternalId)
	}
	// displayName follows the full-replace rule too: an omitted (or blank)
	// value clears it, which applyGlobalUserFields resolves to the same
	// default used at provisioning time (the userName). Whether the write
	// lands at all is decided by the multi-org ownership rule there.
	global := scimGlobalUserFields{DisplayName: &body.DisplayName}
	// Emails are the deliberate exception to full-replace: the primary email
	// identifies the person for the email-match dedup path and SSO linking,
	// so an omitted emails array leaves it untouched instead of blanking it.
	if email := scimPrimaryEmail(body.Emails); email != "" {
		global.Email = &email
	}

	result, err := s.scimUpdateUser(c.Request().Context(), logger, existing, updated, global)
	if err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, scimTypeUniqueness, err.Error())
		}
		return err
	}
	return scimJSON(c, http.StatusOK, s.scimUserToResource(c, orgId, *result))
}

func (s *Server) handleScimPatchUser(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	logger := scimLogger(s, c.Request().Context())

	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		return scimErrorResp(c, http.StatusNotFound, "", "user not found")
	}
	existing, err := s.Database.GetScimUser(c.Request().Context(), nil, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "user not found")
		}
		return err
	}

	var req scimPatchRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidSyntax, "invalid JSON body")
	}

	ops, err := normalizePatchOps(req)
	if err != nil {
		return scimPatchErrorResp(c, err)
	}

	updated := *existing
	var newDisplayName *string
	var newEmail *string
	for _, op := range ops {
		switch op.Path {
		case scimAttrActive:
			if op.BoolValue != nil {
				updated.Active = *op.BoolValue
			}
		case scimAttrUserName:
			// userName is required (RFC 7643 §4.1.1): it can be replaced but
			// never removed or blanked.
			if op.Op == scimOpRemove {
				return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, "userName is required and cannot be removed")
			}
			if op.StrValue != nil {
				if strings.TrimSpace(*op.StrValue) == "" {
					return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, "userName must not be blank")
				}
				updated.UserName = *op.StrValue
			}
		case scimAttrExternalId:
			// A remove (or an explicit empty string) clears the stored externalId.
			if op.Op == scimOpRemove || (op.StrValue != nil && *op.StrValue == "") {
				updated.ExternalId = opt.Empty[string]()
			} else if op.StrValue != nil {
				updated.ExternalId = opt.Of(*op.StrValue)
			}
		case scimAttrDisplayName:
			// A remove clears the display name, same as an explicit blank:
			// applyGlobalUserFields resolves a cleared value to the
			// provisioning default (the userName).
			if op.Op == scimOpRemove {
				newDisplayName = ref.Ref("")
			} else if op.StrValue != nil {
				newDisplayName = op.StrValue
			}
		case scimAttrEmails:
			// Same authority rule as PUT: an email the IDP sends wins.
			// A remove (or empty value) is ignored — we never blank the
			// primary email, it identifies the user for the email-match path.
			if op.StrValue != nil && *op.StrValue != "" {
				newEmail = op.StrValue
			}
		}
	}

	result, err := s.scimUpdateUser(c.Request().Context(), logger, existing, updated, scimGlobalUserFields{DisplayName: newDisplayName, Email: newEmail})
	if err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, scimTypeUniqueness, err.Error())
		}
		return err
	}
	return scimJSON(c, http.StatusOK, s.scimUserToResource(c, orgId, *result))
}

func (s *Server) handleScimDeleteUser(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	logger := scimLogger(s, c.Request().Context())

	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		return scimErrorResp(c, http.StatusNotFound, "", "user not found")
	}
	scimUser, err := s.Database.GetScimUser(c.Request().Context(), nil, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "user not found")
		}
		return err
	}

	if err := s.scimDeleteUser(c.Request().Context(), logger, scimUser); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ------------------------------------------------------------------ Groups

func (s *Server) handleScimListGroups(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	startIndex, count := scimPageParams(c)

	if filterStr := c.QueryParam("filter"); filterStr != "" {
		f, err := parseScimFilter(filterStr)
		if err != nil {
			return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidFilter, err.Error())
		}
		// A whitespace-only filter parses to nil; treat it as no filter.
		if f != nil {
			return s.handleScimListGroupsFiltered(c, orgId, f)
		}
	}

	total, err := s.Database.CountScimGroups(c.Request().Context(), nil, orgId)
	if err != nil {
		return err
	}
	groups, err := s.Database.ListScimGroups(c.Request().Context(), nil, orgId, count, startIndex-1)
	if err != nil {
		return err
	}
	resources := make([]ScimGroupResource, 0, len(groups))
	for _, g := range groups {
		resources = append(resources, scimGroupToResource(c, orgId, g))
	}
	return scimJSON(c, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (s *Server) handleScimListGroupsFiltered(c echo.Context, orgId string, f *scimFilterResult) error {
	ctx := c.Request().Context()
	var group *model.ScimGroup
	var err error
	switch f.Attr {
	case scimAttrDisplayName:
		group, err = s.Database.FindScimGroupByDisplayName(ctx, nil, orgId, f.Value)
	case scimAttrExternalId:
		// Entra probes this when its group matching attribute is externalId;
		// a 400 here quarantines the whole provisioning job.
		group, err = s.Database.FindScimGroupByExternalId(ctx, nil, orgId, f.Value)
	default:
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidFilter, fmt.Sprintf("unsupported filter attribute %q", f.Attr))
	}
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimJSON(c, http.StatusOK, scimListResponse{
				Schemas:      []string{scimListResponseSchema},
				TotalResults: 0,
				StartIndex:   1,
				ItemsPerPage: 0,
				Resources:    []ScimGroupResource{},
			})
		}
		return err
	}
	return scimJSON(c, http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: 1,
		StartIndex:   1,
		ItemsPerPage: 1,
		Resources:    []ScimGroupResource{scimGroupToResource(c, orgId, *group)},
	})
}

func (s *Server) handleScimCreateGroup(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")

	var body ScimGroupResource
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidSyntax, "invalid JSON body")
	}
	// Whitespace-only would slip past an == "" check and blow up on the
	// database CHECK as a 500; reject it here as the 400 it is.
	if strings.TrimSpace(body.DisplayName) == "" {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, "displayName is required and must not be blank")
	}

	memberIds, err := parseMemberResourceIds(body.Members)
	if err != nil {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, err.Error())
	}

	now := time.Now().UTC()
	externalIdOpt := opt.Empty[string]()
	if body.ExternalId != "" {
		externalIdOpt = opt.Of(body.ExternalId)
	}
	group := model.ScimGroup{
		Id:          uuid.Must(uuid.NewV7()),
		OrgId:       orgId,
		DisplayName: body.DisplayName,
		ExternalId:  externalIdOpt,
		MemberIds:   memberIds,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	// One transaction: the group row and its member rows must land together,
	// otherwise a failed member insert leaves a memberless group behind and the
	// IDP's retry hits a uniqueness conflict.
	tx, err := s.Database.BeginTx(c.Request().Context(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.Database.CreateScimGroup(c.Request().Context(), tx, group); err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, scimTypeUniqueness, "group displayName already exists in org")
		}
		if _, ok := model.IsErrBadRequest(err); ok {
			return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, err.Error())
		}
		return err
	}
	// The new group may carry a role mapping; its members' roles change with it.
	if err := s.reconcileScimUsersById(c.Request().Context(), scimLogger(s, c.Request().Context()), tx, orgId, memberIds); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.reloadAuthorizationPolicy(); err != nil {
		return err
	}
	return scimJSON(c, http.StatusCreated, scimGroupToResource(c, orgId, group))
}

func (s *Server) handleScimGetGroup(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	id, err := uuid.Parse(c.Param("groupId"))
	if err != nil {
		return scimErrorResp(c, http.StatusNotFound, "", "group not found")
	}
	group, err := s.Database.GetScimGroup(c.Request().Context(), nil, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "group not found")
		}
		return err
	}
	return scimJSON(c, http.StatusOK, scimGroupToResource(c, orgId, *group))
}

func (s *Server) handleScimReplaceGroup(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	id, err := uuid.Parse(c.Param("groupId"))
	if err != nil {
		return scimErrorResp(c, http.StatusNotFound, "", "group not found")
	}
	existing, err := s.Database.GetScimGroup(c.Request().Context(), nil, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "group not found")
		}
		return err
	}

	var body ScimGroupResource
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidSyntax, "invalid JSON body")
	}
	if strings.TrimSpace(body.DisplayName) == "" {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, "displayName is required and must not be blank")
	}

	memberIds, err := parseMemberResourceIds(body.Members)
	if err != nil {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, err.Error())
	}

	// PUT is a full replace (RFC 7644 §3.5.1): an externalId the IDP omits is
	// cleared, not preserved.
	updated := *existing
	updated.DisplayName = body.DisplayName
	updated.MemberIds = memberIds
	updated.UpdatedAt = time.Now().UTC()
	updated.ExternalId = opt.Empty[string]()
	if body.ExternalId != "" {
		updated.ExternalId = opt.Of(body.ExternalId)
	}

	tx, err := s.Database.BeginTx(c.Request().Context(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.Database.UpdateScimGroup(c.Request().Context(), tx, updated); err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, scimTypeUniqueness, "group displayName already exists in org")
		}
		if _, ok := model.IsErrBadRequest(err); ok {
			return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, err.Error())
		}
		return err
	}
	// Anyone who joined or left the group (and stayers, whose mapping may have
	// changed with a rename) gets their SCIM-managed roles reconciled.
	if err := s.reconcileScimUsersById(c.Request().Context(), scimLogger(s, c.Request().Context()), tx, orgId, append(existing.MemberIds, updated.MemberIds...)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.reloadAuthorizationPolicy(); err != nil {
		return err
	}
	return scimJSON(c, http.StatusOK, scimGroupToResource(c, orgId, updated))
}

func (s *Server) handleScimPatchGroup(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	id, err := uuid.Parse(c.Param("groupId"))
	if err != nil {
		return scimErrorResp(c, http.StatusNotFound, "", "group not found")
	}
	var req scimPatchRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidSyntax, "invalid JSON body")
	}

	ops, err := normalizePatchOps(req)
	if err != nil {
		return scimPatchErrorResp(c, err)
	}

	// The member set is read-modify-written, so the read has to happen inside
	// the transaction behind a row lock. Reading it beforehand lets two
	// concurrent PATCHes compute from the same baseline and lose one change.
	tx, err := s.Database.BeginTx(c.Request().Context(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.Database.LockScimGroup(c.Request().Context(), tx, orgId, id); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "group not found")
		}
		return err
	}
	existing, err := s.Database.GetScimGroup(c.Request().Context(), tx, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "group not found")
		}
		return err
	}

	updated := *existing
	memberSet := uuidSet(existing.MemberIds)

	for _, op := range ops {
		switch op.Path {
		case scimAttrDisplayName:
			// A group's displayName is required (RFC 7643 §4.2): it can be
			// replaced but never removed or blanked.
			if op.Op == scimOpRemove {
				return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, "displayName is required and cannot be removed")
			}
			if op.StrValue != nil {
				if strings.TrimSpace(*op.StrValue) == "" {
					return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, "displayName must not be blank")
				}
				updated.DisplayName = *op.StrValue
			}
		case scimAttrExternalId:
			// Entra sets externalId via PATCH right after group create.
			if op.Op == scimOpRemove || (op.StrValue != nil && *op.StrValue == "") {
				updated.ExternalId = opt.Empty[string]()
			} else if op.StrValue != nil {
				updated.ExternalId = opt.Of(*op.StrValue)
			}
		case scimAttrMembers:
			switch op.Op {
			case scimOpAdd:
				for _, id := range op.MemberIds {
					memberSet[id] = struct{}{}
				}
			case scimOpRemove:
				if op.RemoveAll {
					memberSet = map[uuid.UUID]struct{}{}
				}
				for _, id := range op.MemberIds {
					delete(memberSet, id)
				}
			case scimOpReplace:
				memberSet = uuidSet(op.MemberIds)
			}
		}
	}

	updated.MemberIds = setToSlice(memberSet)
	updated.UpdatedAt = time.Now().UTC()

	if err := s.Database.UpdateScimGroup(c.Request().Context(), tx, updated); err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, scimTypeUniqueness, "group displayName already exists in org")
		}
		if _, ok := model.IsErrBadRequest(err); ok {
			return scimErrorResp(c, http.StatusBadRequest, scimTypeInvalidValue, err.Error())
		}
		return err
	}
	// Anyone who joined or left the group (and stayers, whose mapping may have
	// changed with a rename) gets their SCIM-managed roles reconciled.
	if err := s.reconcileScimUsersById(c.Request().Context(), scimLogger(s, c.Request().Context()), tx, orgId, append(existing.MemberIds, updated.MemberIds...)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.reloadAuthorizationPolicy(); err != nil {
		return err
	}
	return scimJSON(c, http.StatusOK, scimGroupToResource(c, orgId, updated))
}

func (s *Server) handleScimDeleteGroup(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")
	id, err := uuid.Parse(c.Param("groupId"))
	if err != nil {
		return scimErrorResp(c, http.StatusNotFound, "", "group not found")
	}
	// Deleting a group removes every member from it, so the former members'
	// mapped roles must be reconciled away — same rule as any other membership
	// change. Fetch the member list before the cascade wipes it.
	existing, err := s.Database.GetScimGroup(c.Request().Context(), nil, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "group not found")
		}
		return err
	}
	tx, err := s.Database.BeginTx(c.Request().Context(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.Database.DeleteScimGroup(c.Request().Context(), tx, orgId, id); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "group not found")
		}
		return err
	}
	if err := s.reconcileScimUsersById(c.Request().Context(), scimLogger(s, c.Request().Context()), tx, orgId, existing.MemberIds); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.reloadAuthorizationPolicy(); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ------------------------------------------------------------------ helpers

// scimUserToResource converts a model.ScimUser to the SCIM wire representation,
// loading the global user record for display name and email. Fine for
// single-resource responses; list responses must prefetch the global users via
// globalUsersForScimUsers instead of paying one query per row.
func (s *Server) scimUserToResource(c echo.Context, orgId string, u model.ScimUser) ScimUserResource {
	// Best-effort: fetch the global user; if it fails just omit name and email.
	globalUser, err := s.Database.GetUser(c.Request().Context(), nil, u.UserId)
	if err != nil {
		globalUser = nil
	}
	return scimUserResource(c, orgId, u, globalUser)
}

// globalUsersForScimUsers batch-loads the global user records behind the given
// SCIM users, keyed by user id. Best-effort like the single-row path: a user
// missing from the map just renders without display name and email.
func (s *Server) globalUsersForScimUsers(ctx context.Context, scimUsers []model.ScimUser) (map[uuid.UUID]*model.User, error) {
	if len(scimUsers) == 0 {
		return map[uuid.UUID]*model.User{}, nil
	}
	userIds := make([]uuid.UUID, 0, len(scimUsers))
	seen := make(map[uuid.UUID]struct{}, len(scimUsers))
	for _, u := range scimUsers {
		if _, dup := seen[u.UserId]; dup {
			continue
		}
		seen[u.UserId] = struct{}{}
		userIds = append(userIds, u.UserId)
	}
	users, err := s.Database.GetUsersByIds(ctx, nil, userIds)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]*model.User, len(users))
	for i := range users {
		out[users[i].Id] = &users[i]
	}
	return out, nil
}

// scimUserResource renders the SCIM wire representation from already-loaded
// records. A nil globalUser omits display name and email.
func scimUserResource(c echo.Context, orgId string, u model.ScimUser, globalUser *model.User) ScimUserResource {
	loc := scimResourceLocation(c, fmt.Sprintf("/scim/v2/orgs/%s/Users/%s", orgId, u.Id))
	resource := ScimUserResource{
		Schemas:  []string{scimSchemaUser},
		Id:       u.Id,
		UserName: u.UserName,
		Active:   ref.Ref(boolOrString(u.Active)),
		Meta: scimMeta{
			ResourceType: scimResourceTypeUser,
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     loc,
		},
	}
	if u.ExternalId.IsSet() {
		resource.ExternalId = *u.ExternalId.Ref()
	}
	if globalUser != nil {
		resource.DisplayName = globalUser.DisplayName
		if globalUser.PrimaryEmailAddress.IsSet() {
			resource.Emails = []scimEmail{
				{Value: *globalUser.PrimaryEmailAddress.Ref(), Primary: true, Type: "work"},
			}
		}
	}
	return resource
}

func scimGroupToResource(c echo.Context, orgId string, g model.ScimGroup) ScimGroupResource {
	loc := scimResourceLocation(c, fmt.Sprintf("/scim/v2/orgs/%s/Groups/%s", orgId, g.Id))
	members := make([]scimGroupMember, 0, len(g.MemberIds))
	for _, id := range g.MemberIds {
		members = append(members, scimGroupMember{Value: id.String()})
	}
	resource := ScimGroupResource{
		Schemas:     []string{scimSchemaGroup},
		Id:          g.Id,
		DisplayName: g.DisplayName,
		Members:     members,
		Meta: scimMeta{
			ResourceType: scimResourceTypeGroup,
			Created:      g.CreatedAt,
			LastModified: g.UpdatedAt,
			Location:     loc,
		},
	}
	if g.ExternalId.IsSet() {
		resource.ExternalId = *g.ExternalId.Ref()
	}
	return resource
}

// scimResourceLocation builds the absolute URL for a SCIM resource.
// c.Scheme() honors X-Forwarded-Proto, so TLS termination at Envoy still
// yields https:// locations.
func scimResourceLocation(c echo.Context, path string) string {
	return fmt.Sprintf("%s://%s%s", c.Scheme(), c.Request().Host, path)
}

// scimPrimaryEmail extracts the primary (or first) email from a SCIM emails array.
func scimPrimaryEmail(emails []scimEmail) string {
	for _, e := range emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}

// scimMaxPageSize caps `count` at the filter.maxResults=200 that
// ServiceProviderConfig advertises.
const scimMaxPageSize = 200

// scimPageParams reads SCIM pagination query params.
// startIndex is 1-based (default 1); count defaults to 100. Per RFC 7644
// §3.4.2.4 a count of 0 returns no resources (with an honest totalResults)
// and a negative count is treated as 0.
func scimPageParams(c echo.Context) (startIndex, count int) {
	startIndex = 1
	count = 100
	if v := c.QueryParam("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			startIndex = n
		}
	}
	if v := c.QueryParam("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			switch {
			case n < 0:
				count = 0
			case n > scimMaxPageSize:
				count = scimMaxPageSize
			default:
				count = n
			}
		}
	}
	return
}

// parseMemberResourceIds converts a slice of scimGroupMember to a slice of UUIDs.
func parseMemberResourceIds(members []scimGroupMember) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		id, err := uuid.Parse(m.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid member id %q: %w", m.Value, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func uuidSet(ids []uuid.UUID) map[uuid.UUID]struct{} {
	s := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		s[id] = struct{}{}
	}
	return s
}

func setToSlice(s map[uuid.UUID]struct{}) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(s))
	for id := range s {
		out = append(out, id)
	}
	return out
}
