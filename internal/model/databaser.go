package model

import (
	"context"
	"database/sql"
	"embed"
	"sync"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/golib/hpostgresconnect"
	"github.com/stellwerk-labs/golib/hrabbitmq/reliableoutbox"
	"github.com/stellwerk-labs/golib/hstandardreliableoutbox"
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
	goose.SetLogger(&gooseZapLogger{SugaredLogger: logger.Named("goose").Sugar()})
	goose.SetBaseFS(embedMigrations)
	goose.SetVerbose(logger.Level() <= zap.DebugLevel)

	// Register the migration only once to avoid conflicts in parallel run
	registerMigrationOnce.Do(func() {
		goose.AddNamedMigrationContext("000018_pending_event_messages.go", hstandardreliableoutbox.MigrateUp01, hstandardreliableoutbox.MigrateDown01)
	})

	if inner, err := hpostgresconnect.InitDatabase(ctx, &hpostgresconnect.Config{
		Logger:  logger,
		ConnStr: connStr,
	}); err != nil {
		return nil, err
	} else if err := goose.Up(inner.DB, "migrations"); err != nil {
		return nil, err
	} else {
		return &databaser{DB: inner.DB, logger: logger}, nil
	}
}

// Databaser provides an interface which can be used to mock the model
type Databaser interface {
	Close() error
	BeginTx(ctx context.Context, opts *sql.TxOptions) (TxWithCommit, error)

	AsReliableOutboxStore() reliableoutbox.Store[*hstandardreliableoutbox.PendingEventMessage]
	InsertPendingEventMessages(ctx context.Context, optionalTx Tx, messages []*hstandardreliableoutbox.PendingEventMessage) ([]*hstandardreliableoutbox.PendingEventMessage, error)

	CreateUser(ctx context.Context, tx Tx, request *User) (*User, error)
	GetUser(ctx context.Context, optionalTx Tx, id uuid.UUID) (*User, error)
	UpdateUser(ctx context.Context, optionalTx Tx, request *User) (*User, error)
	DeleteUser(ctx context.Context, optionalTx Tx, id uuid.UUID) error
	GetUserIdByIdentity(ctx context.Context, optionalTx Tx, identity UserIdentityProvider, identityId string) (*uuid.UUID, error)
	DismissUserPrompt(ctx context.Context, optionalTx Tx, userId uuid.UUID, promptId string) error

	CreateSessionToken(ctx context.Context, optionalTx Tx, request *SessionToken) (*SessionToken, error)
	ListSessionTokenByUserId(ctx context.Context, optionalTx Tx, userId uuid.UUID, params ListSessionTokensParams) ([]SessionToken, error)
	GetSessionTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) (*SessionToken, error)
	DeleteSessionTokenByHash(ctx context.Context, optionalTx Tx, hash []byte) error
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
	SeedRoles(ctx context.Context, optionalTx Tx, orgId string, roles []Role) error

	UpsertScopedRole(ctx context.Context, optionalTx Tx, request *ScopedRole) (*ScopedRole, error)
	BatchUpsertScopedRoles(ctx context.Context, optionalTx Tx, requests []ScopedRole) ([]ScopedRole, error)
	ListScopedRoles(ctx context.Context, optionalTx Tx, params ScopedRoleListParams) ([]ScopedRole, error)
	BulkDeleteScopedRoles(ctx context.Context, optionalTx Tx, params BulkDeleteScopedRolesParams) (int64, error)

	CreateServiceUserRoles(ctx context.Context, optionalTx Tx, request []ServiceUserRole) error
	ListServiceUserRoles(ctx context.Context, optionalTx Tx, params ListServiceUserRolesParams) ([]ServiceUserRole, error)
	BulkDeleteServiceUserRoles(ctx context.Context, optionalTx Tx, params BulkDeleteServiceUserRolesParams) (int64, error)

	UpsertOrgZedToken(ctx context.Context, optionalTx Tx, orgId string, request *OrgZedTokens) (*OrgZedTokens, error)
	GetOrgZedToken(ctx context.Context, optionalTx Tx, orgId string) (*OrgZedTokens, error)

	GetSsoConfiguration(ctx context.Context, optionalTx Tx, orgId string) (*SsoConfiguration, error)
	UpsertSsoConfiguration(ctx context.Context, optionalTx Tx, orgId string, request *SsoConfiguration) (*SsoConfiguration, error)
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

func (d *databaser) AsReliableOutboxStore() reliableoutbox.Store[*hstandardreliableoutbox.PendingEventMessage] {
	return hstandardreliableoutbox.SqlContextAsReliableOutbox(d.DB)
}

func (d *databaser) InsertPendingEventMessages(ctx context.Context, optionalTx Tx, messages []*hstandardreliableoutbox.PendingEventMessage) ([]*hstandardreliableoutbox.PendingEventMessage, error) {
	return hstandardreliableoutbox.InsertPendingEventMessages(ctx, d.txOrDb(optionalTx), messages)
}
