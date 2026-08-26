package model

import (
	"context"
	"database/sql"
	"embed"
	"sync"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/golib/hmessaging/reliableoutbox"
	"github.com/stellwerk-labs/golib/hpostgresconnect"
	"github.com/stellwerk-labs/golib/hstandardoutbox"
)

//go:generate go tool mockgen  -destination mocks/databaser.go github.com/stellwerk-labs/platform-orchestrator-iam/internal/model Databaser,TxWithCommit

//go:embed migrations/*.sql
var embedMigrations embed.FS

// Model is the underlying type for the entire model.
type databaser struct {
	*sql.DB
	logger *zap.Logger
}

type gooseZapLogger struct {
	*zap.SugaredLogger
}

func (g *gooseZapLogger) Printf(format string, v ...interface{}) {
	g.Infof(format, v...)
}

var registerMigrationOnce sync.Once

// NewDatabaser creates a new database provider instance
func NewDatabaser(ctx context.Context, logger *zap.Logger, connStr string) (Databaser, error) {
	if inner, err := hpostgresconnect.InitDatabase(ctx, &hpostgresconnect.Config{
		Logger:  logger,
		ConnStr: connStr,
	}); err != nil {
		return nil, err
	} else if err := MigrateUp(ctx, logger, inner.DB); err != nil {
		return nil, err
	} else {
		return &databaser{DB: inner.DB, logger: logger}, nil
	}
}

func configureMigrations(logger *zap.Logger) {
	goose.SetLogger(&gooseZapLogger{SugaredLogger: logger.Named("goose").Sugar()})
	goose.SetBaseFS(embedMigrations)
	goose.SetVerbose(logger.Level() <= zap.DebugLevel)

	// Register the migration only once to avoid conflicts in parallel run
	registerMigrationOnce.Do(func() {
		goose.AddNamedMigrationContext("000018_pending_event_messages.go", hstandardoutbox.MigrateUp01, hstandardoutbox.MigrateDown01)
	})
}

// MigrateUp applies all embedded database migrations. It is exported for the
// authorization migration utility, which runs the schema cutover while the IAM
// deployment is stopped.
func MigrateUp(ctx context.Context, logger *zap.Logger, db *sql.DB) error {
	configureMigrations(logger)
	return goose.UpContext(ctx, db, "migrations")
}

// MigrateDownTo rolls the embedded migrations back to targetVersion. Operators
// should only call this through the guarded authorization migration utility.
func MigrateDownTo(ctx context.Context, logger *zap.Logger, db *sql.DB, targetVersion int64) error {
	configureMigrations(logger)
	return goose.DownToContext(ctx, db, "migrations", targetVersion)
}

// Databaser provides an interface which can be used to mock the model
type Databaser interface {
	Close() error
	BeginTx(ctx context.Context, opts *sql.TxOptions) (TxWithCommit, error)

	AsReliableOutboxStore() reliableoutbox.Store[*hstandardoutbox.PendingEventMessage]
	InsertPendingEventMessages(ctx context.Context, optionalTx Tx, messages []*hstandardoutbox.PendingEventMessage) ([]*hstandardoutbox.PendingEventMessage, error)

	CreateUser(ctx context.Context, tx Tx, request *User) (*User, error)
	GetUser(ctx context.Context, optionalTx Tx, id uuid.UUID) (*User, error)
	UpdateUser(ctx context.Context, optionalTx Tx, request *User) (*User, error)
	DeleteUser(ctx context.Context, optionalTx Tx, id uuid.UUID) error
	GetUserIdByIdentity(ctx context.Context, optionalTx Tx, identity UserIdentityProvider, identityId string) (*uuid.UUID, error)
	DismissUserPrompt(ctx context.Context, optionalTx Tx, userId uuid.UUID, promptId string) error
	FindUserByPrimaryEmail(ctx context.Context, optionalTx Tx, email string) (*User, error)

	CreateSessionToken(ctx context.Context, optionalTx Tx, request *SessionToken) (*SessionToken, error)
	ListSessionTokenByUserId(ctx context.Context, optionalTx Tx, userId uuid.UUID, params ListSessionTokensParams) ([]SessionToken, error)
	GetSessionTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) (*SessionToken, error)
	DeleteSessionTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) error
	DeleteSessionTokensByUserId(ctx context.Context, optionalTx Tx, userId uuid.UUID) (int64, error)
	DeleteExpiredSessionTokens(ctx context.Context, optionalTx Tx) (int64, error)

	CreateMembership(ctx context.Context, optionalTx Tx, request *Membership) (*Membership, error)
	GetMembership(ctx context.Context, optionalTx Tx, id uuid.UUID) (*Membership, error)
	HasMemberships(ctx context.Context, optionalTx Tx, orgId string) (bool, error)
	ListMemberships(ctx context.Context, optionalTx Tx, params ListMembershipsParams) ([]MembershipWithUserMetadata, error)
	ListMembersWithIdentities(ctx context.Context, optionalTx Tx, params ListMembershipsParams) ([]MembershipWithIdentityProvider, string, error)
	DeleteMembership(ctx context.Context, optionalTx Tx, id uuid.UUID) error
	BulkDeleteMemberships(ctx context.Context, optionalTx Tx, params BulkDeleteMembershipsParams) (int64, error)

	CreateServiceUserToken(ctx context.Context, optionalTx Tx, orgId string, request *ServiceUserToken) (*ServiceUserToken, error)
	ListServiceUserTokens(ctx context.Context, optionalTx Tx, orgId string) ([]ServiceUserToken, error)
	GetServiceUserToken(ctx context.Context, optionalTx Tx, id uuid.UUID) (*ServiceUserToken, error)
	GetServiceUserTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) (*ServiceUserToken, error)
	UpdateServiceUserToken(ctx context.Context, optionalTx Tx, request *ServiceUserToken) (*ServiceUserToken, error)
	DeleteServiceUserToken(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error
	BulkExpireAllServiceUserTokens(ctx context.Context, optionalTx Tx, orgId string) (int64, error)

	CreateInvitation(ctx context.Context, optionalTx Tx, request *Invitation) (*Invitation, error)
	GetInvitation(ctx context.Context, optionalTx Tx, id uuid.UUID) (*Invitation, error)
	ListInvitations(ctx context.Context, optionalTx Tx, orgId string) ([]Invitation, error)
	DeleteInvitation(ctx context.Context, optionalTx Tx, id uuid.UUID) error
	DeleteExpiredInvitations(ctx context.Context, optionalTx Tx) (int64, error)

	CreateDeviceLoginRequest(ctx context.Context, optionalTx Tx, request *DeviceLoginRequest) (*DeviceLoginRequest, error)
	GetDeviceLoginRequest(ctx context.Context, optionalTx Tx, requestId uuid.UUID) (*DeviceLoginRequest, error)
	GetDeviceLoginRequestByCodeHash(ctx context.Context, optionalTx Tx, codeSha256Hash []byte) (*DeviceLoginRequest, error)
	UpdateDeviceLoginRequest(ctx context.Context, optionalTx Tx, request *DeviceLoginRequest) (*DeviceLoginRequest, error)
	DeleteDeviceLoginRequest(ctx context.Context, optionalTx Tx, requestId uuid.UUID) error

	GetRole(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) (*Role, error)
	ListRoles(ctx context.Context, optionalTx Tx, orgId string) ([]Role, error)
	CreateRole(ctx context.Context, optionalTx Tx, role *Role) (*Role, error)
	UpdateRole(ctx context.Context, optionalTx Tx, role *Role) (*Role, error)
	DeleteRole(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error
	SeedRoles(ctx context.Context, optionalTx Tx, orgId string, roles []Role) error

	ListAuthorizationPolicies(ctx context.Context, optionalTx Tx) ([]AuthorizationPolicy, error)
	ListAuthorizationResourceRelations(ctx context.Context, optionalTx Tx) ([]AuthorizationResourceRelation, error)
	ListKnownAuthorizationPermissions(ctx context.Context, optionalTx Tx, checks []AuthorizationPermissionCheck) ([]AuthorizationPermissionCheck, error)
	UpsertAuthorizationResource(ctx context.Context, optionalTx Tx, resource *AuthorizationResource) error
	DeleteAuthorizationResource(ctx context.Context, optionalTx Tx, resource string) error
	ListEffectiveRoleBindings(ctx context.Context, optionalTx Tx, resource string) ([]EffectiveRoleBinding, error)

	CreateServiceUserRoles(ctx context.Context, optionalTx Tx, request []ServiceUserRole) error
	ListServiceUserRoles(ctx context.Context, optionalTx Tx, params ListServiceUserRolesParams) ([]ServiceUserRole, error)
	BulkDeleteServiceUserRoles(ctx context.Context, optionalTx Tx, params BulkDeleteServiceUserRolesParams) (int64, error)

	GetSsoConfiguration(ctx context.Context, optionalTx Tx, orgId string) (*SsoConfiguration, error)
	UpsertSsoConfiguration(ctx context.Context, optionalTx Tx, orgId string, request *SsoConfiguration) (*SsoConfiguration, error)

	CreateScimUser(ctx context.Context, optionalTx Tx, u ScimUser) error
	GetScimUser(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) (*ScimUser, error)
	FindScimUserByUserName(ctx context.Context, optionalTx Tx, orgId string, userName string) (*ScimUser, error)
	FindScimUserByExternalId(ctx context.Context, optionalTx Tx, orgId string, externalId string) (*ScimUser, error)
	FindScimUserByUserId(ctx context.Context, optionalTx Tx, orgId string, userId uuid.UUID) (*ScimUser, error)
	ListScimUsers(ctx context.Context, optionalTx Tx, orgId string, limit int, offset int) ([]ScimUser, error)
	CountScimUsers(ctx context.Context, optionalTx Tx, orgId string) (int, error)
	UpdateScimUser(ctx context.Context, optionalTx Tx, u ScimUser) error
	DeleteScimUser(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error

	CreateScimGroup(ctx context.Context, optionalTx Tx, g ScimGroup) error
	GetScimGroup(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) (*ScimGroup, error)
	FindScimGroupByDisplayName(ctx context.Context, optionalTx Tx, orgId string, displayName string) (*ScimGroup, error)
	ListScimGroups(ctx context.Context, optionalTx Tx, orgId string, limit int, offset int) ([]ScimGroup, error)
	CountScimGroups(ctx context.Context, optionalTx Tx, orgId string) (int, error)
	UpdateScimGroup(ctx context.Context, optionalTx Tx, g ScimGroup) error
	DeleteScimGroup(ctx context.Context, optionalTx Tx, orgId string, id uuid.UUID) error
}

type Tx interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

type TxWithCommit interface {
	Tx
	Commit() error
	Rollback() error
}

func (d *databaser) txOrDb(optionalTx Tx) Tx {
	if optionalTx == nil {
		return d
	}
	return optionalTx
}

func (d *databaser) BeginTx(ctx context.Context, opts *sql.TxOptions) (TxWithCommit, error) {
	return d.DB.BeginTx(ctx, opts)
}

func (d *databaser) AsReliableOutboxStore() reliableoutbox.Store[*hstandardoutbox.PendingEventMessage] {
	return hstandardoutbox.SQLContextAsReliableOutbox(d.DB)
}

func (d *databaser) InsertPendingEventMessages(ctx context.Context, optionalTx Tx, messages []*hstandardoutbox.PendingEventMessage) ([]*hstandardoutbox.PendingEventMessage, error) {
	return hstandardoutbox.InsertPendingEventMessages(ctx, d.txOrDb(optionalTx), messages)
}
