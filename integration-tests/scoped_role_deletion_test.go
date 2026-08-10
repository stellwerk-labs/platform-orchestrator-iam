package integrationtests

import (
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/authz"
	serverclient "github.com/stellwerk-labs/platform-orchestrator-iam/shared/genclient"
)

// TestProjectScopedRoleDeletion tests that scoped roles at the project level are properly deleted
// from both the database and SpiceDB when a project is deleted.
func TestProjectScopedRoleDeletion(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)
	cpClient := MustControlPlaneClient(t)
	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	// Setup: Create org, users, project, and environment
	user := MustRegisterTestUser(client, t)
	org := MustCreateTestOrg(cpInternalClient, t)
	adminRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user.Id, adminRoleId)

	otherUser := MustRegisterTestUser(client, t)
	deployerRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultDeployerRoleName)
	viewerRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultViewerRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, otherUser.Id, viewerRoleId)

	project := MustCreateProject(t, cpClient, org.Id, "pg-"+strings.ToLower(rand.Text()))
	env := MustCreateEnv(t, cpClient, org.Id, project.Id, "env-"+strings.ToLower(rand.Text()))

	t.Run("create project scoped role for user", func(t *testing.T) {
		res, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, otherUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     deployerRoleId.String(),
					Scope:       ref.Ref("project:" + project.Uuid.String()),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), "unexpected status %d %s", res.StatusCode(), string(res.Body))
	})

	t.Run("verify user has scoped permissions on project", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: otherUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanWriteProjectCheck(project.Uuid),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}, 30*time.Second, 1*time.Second, "user should have write permissions on project scope")
	})

	t.Run("emit ProjectDeleted event to NATS", func(t *testing.T) {
		// Emit the ProjectDeleted event to JetStream.
		// This will be consumed by the projectdeletedhandler which will delete the scoped roles
		MustPublishProjectDeletedEvent(t, org.Id, project.Id, project.Uuid)

		// Give the event handler time to process the event
		// The worker needs to consume the message and process it
		time.Sleep(3 * time.Second)
	})

	t.Run("verify scoped roles are deleted from database", func(t *testing.T) {
		projectScope := "project:" + project.Uuid.String()

		// Check memberships
		memberships, err := db.ListMemberships(t.Context(), nil, model.ListMembershipsParams{
			OrgId: &org.Id,
		})
		require.NoError(t, err)
		// Filter to check for project scope
		var projectScopedMemberships []model.MembershipWithUserMetadata
		for _, m := range memberships {
			if m.Scope == projectScope {
				projectScopedMemberships = append(projectScopedMemberships, m)
			}
		}
		assert.Empty(t, projectScopedMemberships, "should have no memberships with project scope")

		// Check scoped_roles table
		scopedRoles, err := db.ListScopedRoles(t.Context(), nil, model.ScopedRoleListParams{
			OrgId: org.Id,
			Scope: &projectScope,
		})
		require.NoError(t, err)
		assert.Empty(t, scopedRoles, "should have no scoped roles with project scope")
	})

	t.Run("verify scoped roles are deleted from SpiceDB", func(t *testing.T) {
		spicedbClient := MustSpiceDBClient(t)

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := spicedbClient.ReadRelationships(t.Context(), &v1.ReadRelationshipsRequest{
				RelationshipFilter: &v1.RelationshipFilter{
					ResourceType:     "scoped_role",
					OptionalRelation: "member",
					OptionalSubjectFilter: &v1.SubjectFilter{
						SubjectType:       "user",
						OptionalSubjectId: otherUser.Id.String(),
					},
				},
			})
			if !assert.NoError(collect, err) {
				return
			}

			// Collect all scoped_role member relationships for this user
			var userScopedRoles []string
			if resp != nil {
				for {
					rel, err := resp.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						break
					}
					userScopedRoles = append(userScopedRoles, rel.Relationship.Resource.ObjectId)
				}
			}

			// Verify none of these scoped roles belong to the project scope
			if len(userScopedRoles) > 0 {
				scopedRoles, err := db.ListScopedRoles(t.Context(), nil, model.ScopedRoleListParams{
					OrgId: org.Id,
				})
				assert.NoError(collect, err)

				projectScope := "project:" + project.Uuid.String()
				for _, sr := range scopedRoles {
					for _, userRoleId := range userScopedRoles {
						if sr.Id.String() == userRoleId && sr.Scope == projectScope {
							collect.Errorf("Found scoped role %s with project scope that should have been deleted", userRoleId)
						}
					}
				}
			}
		}, 30*time.Second, 3*time.Second, "user should not have project scoped roles anymore")
	})

	t.Run("user still has base viewer permissions on org", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: otherUser.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanReadOrgCheck(org.Id),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})
}

// TestEnvScopedRoleDeletion tests that scoped roles at the environment level are properly deleted
// from both the database and SpiceDB when an environment is deleted.
func TestEnvScopedRoleDeletion(t *testing.T) {
	t.Parallel()

	client, err := serverclient.NewClientWithResponses(mustServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	internalClient, err := serverclient.NewClientWithResponses(mustInternalServerURL(t), serverclient.WithHTTPClient(testHttpClient))
	require.NoError(t, err)

	cpInternalClient := MustInternalControlPlaneClient(t)
	cpClient := MustControlPlaneClient(t)
	db := MustDatabase(t)
	defer func() { _ = db.Close() }()

	// Setup: Create org, users, project, and environment
	user := MustRegisterTestUser(client, t)
	org := MustCreateTestOrg(cpInternalClient, t)
	adminRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultAdminRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, user.Id, adminRoleId)

	otherUser := MustRegisterTestUser(client, t)
	deployerRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultDeployerRoleName)
	viewerRoleId := MustObtainRoleIdByName(t, internalClient, org.Id, DefaultViewerRoleName)
	_ = MustAddUserToOrgWithRoleAndEnsurePermissions(internalClient, t, org.Id, otherUser.Id, viewerRoleId)

	project := MustCreateProject(t, cpClient, org.Id, "pg-"+strings.ToLower(rand.Text()))
	env := MustCreateEnv(t, cpClient, org.Id, project.Id, "env-"+strings.ToLower(rand.Text()))

	t.Run("create environment scoped role for user", func(t *testing.T) {
		res, err := client.ReplaceOrgUserMembershipsWithResponse(t.Context(), org.Id, otherUser.Id, serverclient.ReplaceOrgUserMembershipsJSONRequestBody{
			Memberships: []serverclient.UserMembershipRequest{
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     viewerRoleId.String(),
				},
				{
					SubjectType: serverclient.SubjectTypeRole,
					Subject:     deployerRoleId.String(),
					Scope:       ref.Ref("env:" + env.Uuid.String()),
				},
			},
		}, WithAuthenticatedUserId(user.Id))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), "unexpected status %d %s", res.StatusCode(), string(res.Body))
	})

	t.Run("verify user has scoped permissions on environment", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
				UserId: otherUser.Id,
				Checks: []serverclient.ResourcePermissionCheck{
					authz.CanReadOrgCheck(org.Id),
					authz.CanWriteEnvironmentCheck(env.Uuid),
				},
			})
			require.NoError(t, err)
			assert.Equal(collect, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
		}, 30*time.Second, 1*time.Second, "user should have write permissions on environment scope")
	})

	t.Run("emit EnvironmentDeleted event to NATS", func(t *testing.T) {
		// Emit the EnvironmentDeleted event to JetStream.
		// This will be consumed by the envdeletedhandler which will delete the scoped roles
		MustPublishEnvironmentDeletedEvent(t, org.Id, project.Id, env.Id, project.Uuid, env.Uuid)

		// Give the event handler time to process the event
		// The worker needs to consume the message and process it
		time.Sleep(3 * time.Second)
	})

	t.Run("verify scoped roles are deleted from database", func(t *testing.T) {
		envScope := "env:" + env.Uuid.String()

		// Check memberships
		memberships, err := db.ListMemberships(t.Context(), nil, model.ListMembershipsParams{
			OrgId: &org.Id,
		})
		require.NoError(t, err)
		// Filter to check for env scope
		var envScopedMemberships []model.MembershipWithUserMetadata
		for _, m := range memberships {
			if m.Scope == envScope {
				envScopedMemberships = append(envScopedMemberships, m)
			}
		}
		assert.Empty(t, envScopedMemberships, "should have no memberships with env scope")

		// Check scoped_roles table
		scopedRoles, err := db.ListScopedRoles(t.Context(), nil, model.ScopedRoleListParams{
			OrgId: org.Id,
			Scope: &envScope,
		})
		require.NoError(t, err)
		assert.Empty(t, scopedRoles, "should have no scoped roles with env scope")
	})

	t.Run("verify scoped roles are deleted from SpiceDB", func(t *testing.T) {
		spicedbClient := MustSpiceDBClient(t)

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			resp, err := spicedbClient.ReadRelationships(t.Context(), &v1.ReadRelationshipsRequest{
				RelationshipFilter: &v1.RelationshipFilter{
					ResourceType:     "scoped_role",
					OptionalRelation: "member",
					OptionalSubjectFilter: &v1.SubjectFilter{
						SubjectType:       "user",
						OptionalSubjectId: otherUser.Id.String(),
					},
				},
			})
			if !assert.NoError(collect, err) {
				return
			}

			// Collect all scoped_role member relationships for this user
			var userScopedRoles []string
			if resp != nil {
				for {
					rel, err := resp.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						break
					}
					userScopedRoles = append(userScopedRoles, rel.Relationship.Resource.ObjectId)
				}
			}

			// Verify none of these scoped roles belong to the environment scope
			if len(userScopedRoles) > 0 {
				scopedRoles, err := db.ListScopedRoles(t.Context(), nil, model.ScopedRoleListParams{
					OrgId: org.Id,
				})
				assert.NoError(collect, err)

				envScope := "env:" + env.Uuid.String()
				for _, sr := range scopedRoles {
					for _, userRoleId := range userScopedRoles {
						if sr.Id.String() == userRoleId && sr.Scope == envScope {
							collect.Errorf("Found scoped role %s with env scope that should have been deleted", userRoleId)
						}
					}
				}
			}
		}, 30*time.Second, 3*time.Second, "user should not have environment scoped roles anymore")
	})

	t.Run("user still has base viewer permissions on org", func(t *testing.T) {
		r, err := internalClient.InternalAuthorizeWithResponse(t.Context(), serverclient.InternalAuthorizeBody{
			UserId: otherUser.Id,
			Checks: []serverclient.ResourcePermissionCheck{
				authz.CanReadOrgCheck(org.Id),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, r.StatusCode(), "unexpected status %d %s", r.StatusCode(), string(r.Body))
	})
}
