package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
	g := e.Group("/scim/v2/orgs/:orgId", s.scimAuthMiddleware)

	g.GET("/ServiceProviderConfig", s.handleScimServiceProviderConfig)
	g.GET("/Schemas", s.handleScimSchemas)
	g.GET("/Schemas/:schemaId", s.handleScimSchema)
	g.GET("/ResourceTypes", s.handleScimResourceTypes)
	g.GET("/ResourceTypes/:typeId", s.handleScimResourceType)

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

// ------------------------------------------------------------------ static

func (s *Server) handleScimServiceProviderConfig(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
	return scimJSON(c, http.StatusOK, staticServiceProviderConfig())
}

func (s *Server) handleScimSchemas(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
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
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
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
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
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
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningRead); !ok {
		return nil
	}
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

	filterStr := c.QueryParam("filter")
	if filterStr != "" {
		f, err := parseScimFilter(filterStr)
		if err != nil {
			return scimErrorResp(c, http.StatusBadRequest, "invalidFilter", err.Error())
		}
		return s.handleScimListUsersFiltered(c, orgId, f)
	}

	total, err := s.Database.CountScimUsers(c.Request().Context(), nil, orgId)
	if err != nil {
		return errors.Wrap(err, "count scim users")
	}
	users, err := s.Database.ListScimUsers(c.Request().Context(), nil, orgId, count, startIndex-1)
	if err != nil {
		return errors.Wrap(err, "list scim users")
	}
	resources := make([]ScimUserResource, 0, len(users))
	for _, u := range users {
		resources = append(resources, s.scimUserToResource(c, orgId, u))
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
		return scimErrorResp(c, http.StatusBadRequest, "invalidFilter", fmt.Sprintf("unsupported filter attribute %q", f.Attr))
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
		return scimErrorResp(c, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
	}
	if body.UserName == "" {
		return scimErrorResp(c, http.StatusBadRequest, "invalidValue", "userName is required")
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
			return scimErrorResp(c, http.StatusConflict, "uniqueness", err.Error())
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
		return scimErrorResp(c, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
	}
	if body.UserName == "" {
		return scimErrorResp(c, http.StatusBadRequest, "invalidValue", "userName is required")
	}

	updated := *existing
	updated.UserName = body.UserName
	updated.Active = true
	if body.Active != nil {
		updated.Active = bool(*body.Active)
	}
	if body.ExternalId != "" {
		updated.ExternalId = opt.Of(body.ExternalId)
	}
	var newDisplayName *string
	if body.DisplayName != "" {
		newDisplayName = &body.DisplayName
	}

	result, err := s.scimUpdateUser(c.Request().Context(), logger, existing, updated, newDisplayName)
	if err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, "uniqueness", err.Error())
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
		return scimErrorResp(c, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
	}

	ops, err := normalizePatchOps(req)
	if err != nil {
		return scimErrorResp(c, http.StatusBadRequest, "invalidSyntax", err.Error())
	}

	updated := *existing
	var newDisplayName *string
	for _, op := range ops {
		switch op.Path {
		case scimAttrActive:
			if op.BoolValue != nil {
				updated.Active = *op.BoolValue
			}
		case scimAttrUserName:
			if op.StrValue != nil {
				updated.UserName = *op.StrValue
			}
		case scimAttrExternalId:
			if op.StrValue != nil {
				updated.ExternalId = opt.Of(*op.StrValue)
			}
		case scimAttrDisplayName:
			if op.StrValue != nil {
				newDisplayName = op.StrValue
			}
		}
	}

	result, err := s.scimUpdateUser(c.Request().Context(), logger, existing, updated, newDisplayName)
	if err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, "uniqueness", err.Error())
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

	filterStr := c.QueryParam("filter")
	if filterStr != "" {
		f, err := parseScimFilter(filterStr)
		if err != nil {
			return scimErrorResp(c, http.StatusBadRequest, "invalidFilter", err.Error())
		}
		if f != nil && f.Attr == scimAttrDisplayName {
			group, err := s.Database.FindScimGroupByDisplayName(c.Request().Context(), nil, orgId, f.Value)
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
		return scimErrorResp(c, http.StatusBadRequest, "invalidFilter", "unsupported filter attribute")
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

func (s *Server) handleScimCreateGroup(c echo.Context) error {
	if _, ok := s.scimCheckAuth(c, sharedauthz.PermissionProvisioningWrite); !ok {
		return nil
	}
	orgId := c.Param("orgId")

	var body ScimGroupResource
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
		return scimErrorResp(c, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
	}
	if body.DisplayName == "" {
		return scimErrorResp(c, http.StatusBadRequest, "invalidValue", "displayName is required")
	}

	memberIds, err := parseMemberResourceIds(body.Members)
	if err != nil {
		return scimErrorResp(c, http.StatusBadRequest, "invalidValue", err.Error())
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
			return scimErrorResp(c, http.StatusConflict, "uniqueness", "group displayName already exists in org")
		}
		if _, ok := model.IsErrBadRequest(err); ok {
			return scimErrorResp(c, http.StatusBadRequest, "invalidValue", err.Error())
		}
		return err
	}
	if err := tx.Commit(); err != nil {
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
		return scimErrorResp(c, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
	}
	if body.DisplayName == "" {
		return scimErrorResp(c, http.StatusBadRequest, "invalidValue", "displayName is required")
	}

	memberIds, err := parseMemberResourceIds(body.Members)
	if err != nil {
		return scimErrorResp(c, http.StatusBadRequest, "invalidValue", err.Error())
	}

	updated := *existing
	updated.DisplayName = body.DisplayName
	updated.MemberIds = memberIds
	updated.UpdatedAt = time.Now().UTC()
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
			return scimErrorResp(c, http.StatusConflict, "uniqueness", "group displayName already exists in org")
		}
		if _, ok := model.IsErrBadRequest(err); ok {
			return scimErrorResp(c, http.StatusBadRequest, "invalidValue", err.Error())
		}
		return err
	}
	if err := tx.Commit(); err != nil {
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
	existing, err := s.Database.GetScimGroup(c.Request().Context(), nil, orgId, id)
	if err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "group not found")
		}
		return err
	}

	var req scimPatchRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return scimErrorResp(c, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
	}

	ops, err := normalizePatchOps(req)
	if err != nil {
		return scimErrorResp(c, http.StatusBadRequest, "invalidSyntax", err.Error())
	}

	updated := *existing
	memberSet := uuidSet(existing.MemberIds)

	for _, op := range ops {
		switch op.Path {
		case scimAttrDisplayName:
			if op.StrValue != nil {
				updated.DisplayName = *op.StrValue
			}
		case scimAttrMembers:
			switch op.Op {
			case scimOpAdd:
				for _, id := range op.MemberIds {
					memberSet[id] = struct{}{}
				}
			case scimOpRemove:
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

	tx, err := s.Database.BeginTx(c.Request().Context(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.Database.UpdateScimGroup(c.Request().Context(), tx, updated); err != nil {
		if _, ok := model.IsErrConflict(err); ok {
			return scimErrorResp(c, http.StatusConflict, "uniqueness", "group displayName already exists in org")
		}
		if _, ok := model.IsErrBadRequest(err); ok {
			return scimErrorResp(c, http.StatusBadRequest, "invalidValue", err.Error())
		}
		return err
	}
	if err := tx.Commit(); err != nil {
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
	if err := s.Database.DeleteScimGroup(c.Request().Context(), nil, orgId, id); err != nil {
		if _, ok := model.IsErrNotFound(err); ok {
			return scimErrorResp(c, http.StatusNotFound, "", "group not found")
		}
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ------------------------------------------------------------------ helpers

// scimUserToResource converts a model.ScimUser to the SCIM wire representation.
// It loads the global user's email from the database to populate the emails array.
func (s *Server) scimUserToResource(c echo.Context, orgId string, u model.ScimUser) ScimUserResource {
	loc := scimResourceLocation(c, fmt.Sprintf("/scim/v2/orgs/%s/Users/%s", orgId, u.Id))
	resource := ScimUserResource{
		Schemas:  []string{scimSchemaUser},
		Id:       u.Id,
		UserName: u.UserName,
		Active:   ref.Ref(boolOrString(u.Active)),
		Meta: scimMeta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     loc,
		},
	}
	if u.ExternalId.IsSet() {
		resource.ExternalId = *u.ExternalId.Ref()
	}

	// Best-effort: fetch the global user's email; if it fails just omit it.
	if globalUser, err := s.Database.GetUser(c.Request().Context(), nil, u.UserId); err == nil {
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
			ResourceType: "Group",
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
func scimResourceLocation(c echo.Context, path string) string {
	scheme := "https"
	if c.Request().TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s", scheme, c.Request().Host, path)
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

// scimPageParams reads SCIM pagination query params.
// startIndex is 1-based (default 1); count defaults to 100.
func scimPageParams(c echo.Context) (startIndex, count int) {
	startIndex = 1
	count = 100
	if v := c.QueryParam("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			startIndex = n
		}
	}
	if v := c.QueryParam("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			count = n
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
