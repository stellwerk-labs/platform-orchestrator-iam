package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"runtime/debug"
	"strings"
	"time"

	"github.com/labstack/echo/v4/middleware"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/pkg/errors"
	"github.com/stellwerk-labs/golib/hconfig"
	"github.com/stellwerk-labs/golib/hecho"
	"github.com/stellwerk-labs/golib/hlogger"
	"github.com/stellwerk-labs/golib/hmessaging"
	"github.com/stellwerk-labs/golib/hmessaging/reliableoutbox"
	"github.com/stellwerk-labs/golib/hnats"
	"github.com/stellwerk-labs/golib/hstandardoutbox"
	htelemetry "github.com/stellwerk-labs/golib/htelemetry"
	cpclient "github.com/stellwerk-labs/platform-orchestrator-cp/shared/genclient"
	"github.com/stellwerk-labs/platform-orchestrator-iam/shared/userid"
	"github.com/workos/workos-go/v6/pkg/sso"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"

	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/api/identity"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/authorization"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/config"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/emailprovider"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/model"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ref"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/ssoprovider"
	"github.com/stellwerk-labs/platform-orchestrator-iam/internal/worker"
)

const (
	runtimeMetricsInterval = 5 * time.Second
	samplingRatio          = 1
)

var buildInfo *debug.BuildInfo

var cfg = &config.Configuration{
	Port:                       8080,
	DatabaseHost:               "localhost",
	DatabasePort:               "5432",
	OTELEnabled:                false,
	LogLevel:                   "INFO",
	ShutdownDelay:              10 * time.Second,
	ExpiredDataCleanupInterval: 5 * time.Minute,
}

func init() {
	buildInfo, _ = debug.ReadBuildInfo()
}

// sharedDependencies holds all shared resources across tasks
type sharedDependencies struct {
	Config              *config.Configuration
	DB                  model.Databaser
	Authorizer          authorization.Authorizer
	NATSConn            *nats.Conn
	JetStream           jetstream.JetStream
	Publisher           hmessaging.Publisher
	DeadLetterPublisher hmessaging.Publisher
	CpClient            cpclient.ClientWithResponsesInterface
}

func main() {
	logw, err := hlogger.NewHLogger("INFO", false, "json")
	if err != nil {
		log.Fatalf("Error building logger: %v (%s %s)", err, path.Base(buildInfo.Main.Path), buildInfo.Main.Version)
	}
	defer hlogger.OnExit(logw.Logger)
	zap.ReplaceGlobals(logw.Logger)
	zap.S().Infow("Starting", "app", path.Base(buildInfo.Main.Path), "version", buildInfo.Main.Version)

	if err := hconfig.LoadConfigWithoutRetag(cfg); err != nil {
		zap.S().Fatalw("failed to load config", "err", err)
	}
	if err := logw.ChangeLevel(cfg.LogLevel); err != nil {
		log.Fatalf("Error setting log level: %v", err)
	}

	ctx := context.Background()

	deps := initSharedDependencies(ctx, cfg)
	defer closeSharedDependencies(deps)

	if cfg.OTELEnabled {
		_, shutdown, err := htelemetry.StartOTel(ctx, htelemetry.OTelConfig{
			ServiceName:    path.Base(buildInfo.Main.Path),
			ServiceVersion: buildInfo.Main.Version,
			Logger:         zap.L(),

			// Custom TracerProvider options (e.g., sampling)
			TracerProviderOptions: []trace.TracerProviderOption{
				trace.WithSampler(trace.TraceIDRatioBased(samplingRatio)),
			},
			RuntimeMetrics:         ref.Ref(true),
			RuntimeMetricsInterval: runtimeMetricsInterval,
		})

		if err != nil {
			zap.L().Fatal("failed to start otel tracing", zap.Error(err))
		}
		defer func() {
			if err := shutdown(ctx); err != nil {
				zap.L().Error("failed to shutdown otel tracing", zap.Error(err))
			}
		}()
	}

	runner := NewRunner(cfg.ShutdownDelay, zap.L())
	err = runner.RunAndHandleShutdown(ctx,
		runEchoServer(cfg, deps),
		runScheduledFlush(deps),
		runWorkerConsumer(deps),
		runExpiredDataCleanup(cfg, deps),
	)
	if err != nil {
		zap.L().Fatal("Runner failed", zap.Error(err))
	}
}

func initSharedDependencies(ctx context.Context, cfg *config.Configuration) *sharedDependencies {
	// Initialize database
	dbConnStr := fmt.Sprintf(
		"dbname=%s user=%s password=%s host=%s port=%s connect_timeout=5 sslmode=disable",
		cfg.DatabaseName, cfg.DatabaseUser, cfg.DatabasePassword, cfg.DatabaseHost, cfg.DatabasePort)
	db, err := model.NewDatabaser(ctx, zap.L(), dbConnStr)
	if err != nil {
		zap.S().Fatalw("Failed to initialize database", "err", err)
	}

	// Initialize the durable NATS transport before accepting API traffic.
	conn, err := hnats.Connect(hnats.ConnectionConfig{
		URLs:            []string{cfg.NatsURL},
		Name:            "platform-orchestrator-iam",
		Token:           cfg.NatsToken,
		CredentialsFile: cfg.NatsCredentialsFile,
		NKeySeedFile:    cfg.NatsNKeySeedFile,
		CAFile:          cfg.NatsCAFile,
		ClientCertFile:  cfg.NatsClientCertFile,
		ClientKeyFile:   cfg.NatsClientKeyFile,
		TLSServerName:   cfg.NatsTLSServerName,
		ConnectTimeout:  10 * time.Second,
		ReconnectWait:   2 * time.Second,
		MaxReconnects:   -1,
	}, zap.L())
	if err != nil {
		zap.L().Fatal("failed to connect to NATS", zap.Error(err))
	}
	js, err := hnats.NewJetStream(conn)
	if err != nil {
		conn.Close()
		zap.L().Fatal("failed to initialize JetStream", zap.Error(err))
	}
	if cfg.NatsBootstrapStreams {
		if err := hnats.EnsureStandardStreams(ctx, js, cfg.NatsStreamReplicas); err != nil {
			conn.Close()
			zap.L().Fatal("failed to initialize JetStream topology", zap.Error(err))
		}
	}
	publisher := hnats.NewPublisher(js, hmessaging.EventsStreamName, zap.L())
	deadLetterPublisher := hnats.NewPublisher(js, hmessaging.DeadLettersStreamName, zap.L())

	// We need to distinguish our outbox messages from those produced by the CP or DP so
	// that components can deduplicate messages using the message id. So we tack on a prefix.
	hstandardoutbox.MessageIDPrefix = "platform-orchestrator-iam-"

	// Initialize control plane client
	cpClient, err := cpclient.NewClientWithResponses(
		cfg.ControlPlaneUrl,
		cpclient.WithHTTPClient(http.DefaultClient),
		cpclient.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("From", userid.InternalSystemUuid.String())
			return nil
		}),
	)
	if err != nil {
		zap.L().Fatal("failed to setup control plane client", zap.Error(err))
	}

	return &sharedDependencies{
		Config:              cfg,
		DB:                  db,
		Authorizer:          authorization.New(db),
		NATSConn:            conn,
		JetStream:           js,
		Publisher:           publisher,
		DeadLetterPublisher: deadLetterPublisher,
		CpClient:            cpClient,
	}
}

func closeSharedDependencies(deps *sharedDependencies) {
	if deps.NATSConn != nil {
		if err := deps.NATSConn.Drain(); err != nil {
			zap.L().Error("failed to drain NATS connection", zap.Error(err))
		}
	}
}

func runEchoServer(cfg *config.Configuration, deps *sharedDependencies) RunnableTask {
	// Initialize identity providers
	identityProviders := map[model.UserIdentityProvider]identity.Provider{}
	if cfg.AllowedGoogleClientIds != "" {
		googleLoginProvider := identity.NewGoogleProvider(http.DefaultClient, strings.Split(cfg.AllowedGoogleClientIds, ","))
		identityProviders[model.UserIdentityProviderGoogle] = googleLoginProvider
	}
	if cfg.AllowedMicrosoftClientIds != "" {
		microsoftLoginProvider := identity.NewMicrosoftProvider(http.DefaultClient, strings.Split(cfg.AllowedMicrosoftClientIds, ","))
		identityProviders[model.UserIdentityProviderMicrosoft] = microsoftLoginProvider
	}
	if cfg.TestUserProviderAgeIdentity != "" {
		zap.L().Info("Configuring test user provider")
		testUserProvider, err := identity.NewTestUserProvider(cfg.TestUserProviderAgeIdentity)
		if err != nil {
			zap.L().Fatal("failed to setup test user provider", zap.Error(err))
		}
		identityProviders[model.UserIdentityProviderTestUser] = testUserProvider
	}

	// Initialize email provider if it's enabled via env variables
	var emailProvider emailprovider.Provider
	if cfg.SendGridApiKey == "mock" {
		emailProvider = &emailprovider.MockEmailProvider{WriteDirectory: "/tmp/mock-emails"}
	} else if cfg.SendGridApiKey != "" {
		emailProvider = emailprovider.NewSendGrid(http.DefaultClient, cfg.SendGridApiKey, cfg.SendGridSenderName, cfg.SendGridSenderAddress, cfg.ProductName)
	}

	var ssoProvider ssoprovider.Provider
	ssoCallbackUrl, err := url.JoinPath(cfg.UiHostUrl, cfg.SsoCallbackUrlPath)
	if err != nil {
		zap.L().Fatal("failed to construct SSO callback URL", zap.Error(err))
	}
	if cfg.WorkosApiKey != "" && cfg.WorkosClientId != "" {
		// Initialize WorkOS SSO if configured, used in the SaaS version
		if cfg.SsoStateSecret == "" {
			zap.L().Fatal("SSO state secret is required when using WorkOS SSO")
		}
		sso.Configure(cfg.WorkosApiKey, cfg.WorkosClientId)
		ssoProvider = ssoprovider.NewWorkOs(ssoCallbackUrl)
	} else if cfg.KeycloakUrl != "" && cfg.KeycloakRealm != "" && cfg.KeycloakClientId != "" && cfg.KeycloakClientSecret != "" {
		// Initialize Keycloak client if configured, used in the self-hosted version
		if cfg.SsoStateSecret == "" {
			zap.L().Fatal("SSO state secret is required when using Keycloak SSO")
		}
		var err error
		if ssoProvider, err = ssoprovider.NewKeycloak(context.Background(), http.DefaultClient, cfg.KeycloakUrl, cfg.KeycloakInternalUrl, cfg.KeycloakRealm, cfg.KeycloakClientId, cfg.KeycloakClientSecret, ssoCallbackUrl); err != nil {
			zap.L().Fatal("failed to initialize Keycloak SSO provider", zap.Error(err))
		}
	}

	// Create API server
	server := api.Server{
		Publisher:                deps.Publisher,
		Database:                 deps.DB,
		Logger:                   zap.L(),
		SessionTokenCookieDomain: cfg.SessionTokenCookieDomain,
		UserIdentityProviders:    identityProviders,
		TokenByHashCache:         api.NewGetTokenByHashCache(deps.DB),
		UiHostUrl:                cfg.UiHostUrl,
		EmailProvider:            emailProvider,
		SsoProvider:              ssoProvider,
		SsoCallbackUrlPath:       cfg.SsoCallbackUrlPath,
		SsoStateSecret:           cfg.SsoStateSecret,
		CpClient:                 deps.CpClient,
		Authorizer:               deps.Authorizer,
	}
	if cfg.SuperUserToken != "" {
		h := sha256.Sum256([]byte(cfg.SuperUserToken))
		server.SuperUserTokenHash = h[:]
		zap.L().Info("Super user token configured")
	}

	// Create Echo server
	e, err := hecho.DefaultEchoServerWithValidation(&hecho.ValidatedServerConfig{
		AppName:          path.Base(buildInfo.Main.Path),
		Logger:           server.Logger,
		OpenAPIRawSchema: api.MustDecodeOpenApiSpec(),
		Tracing:          hecho.TracingOTel,
		OpenAPISkipperFn: api.OpenApiValidatorSkipper,
	})
	if err != nil {
		zap.S().Fatalw("Failed to setup schema validation", "err", err)
	}

	e.Use(middleware.RequestID())
	server.MapRoutes(e)

	return RunnableTask{
		Run: func(ctx context.Context) error {
			// Start server
			addr := fmt.Sprintf(":%d", cfg.Port)
			zap.S().Infow("Starting server", "addr", addr)
			if err := e.Start(addr); err != nil {
				if !errors.Is(err, http.ErrServerClosed) {
					return errors.Wrap(err, "failed to start server")
				}
			}
			return nil
		},
		Shutdown: func(ctx context.Context) {
			zap.L().Info("Gracefully shutting down webserver")
			if err := e.Shutdown(ctx); err != nil {
				zap.L().Warn("failed to gracefully shutdown webserver, forcing close", zap.Error(err))
				if err := e.Close(); err != nil {
					zap.L().Error("failed to terminate the echo server", zap.Error(err))
				}
			} else {
				zap.L().Info("webserver shutdown")
			}
		},
	}
}

func runScheduledFlush(deps *sharedDependencies) RunnableTask {
	return RunnableTask{
		Run: func(ctx context.Context) error {
			zap.L().Info("Starting scheduled flush of pending messages")
			store := deps.DB.AsReliableOutboxStore()
			reliableoutbox.ScheduledFlushPendingMessages(ctx, store, deps.Publisher, reliableoutbox.DefaultScheduledFlushPeriodFunc)
			zap.L().Info("Stopped scheduled flush of pending messages")
			return nil
		},
		Shutdown: nil,
	}
}

func runWorkerConsumer(deps *sharedDependencies) RunnableTask {
	var consumer *hnats.Consumer

	return RunnableTask{
		Run: func(ctx context.Context) error {
			wrk := &worker.Worker{
				JetStream:           deps.JetStream,
				Publisher:           deps.Publisher,
				DeadLetterPublisher: deps.DeadLetterPublisher,
				DB:                  deps.DB,
				RetryTimeout:        time.Minute,
				Logger:              zap.L().Named("worker"),
				CpClient:            deps.CpClient,
			}

			var err error
			consumer, err = wrk.BuildMainConsumer(ctx)
			if err != nil {
				zap.L().Fatal("failed to setup main consumer", zap.Error(err))
			}

			zap.L().Info("Starting main consumer")
			if err := consumer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return errors.Wrap(err, "failed to run main consumer")
			}
			return nil
		},
		Shutdown: func(ctx context.Context) {
			zap.L().Info("Shutting down main consumer")
			if err := consumer.Close(ctx); err != nil && !errors.Is(err, context.Canceled) {
				zap.L().Warn("failed to close main consumer cleanly", zap.Error(err))
			}
			zap.L().Info("main consumer shutdown")
		},
	}
}

func runExpiredDataCleanup(cfg *config.Configuration, deps *sharedDependencies) RunnableTask {
	return RunnableTask{
		Run: func(ctx context.Context) error {
			return api.ScheduleExpiredDataCleanup(ctx, cfg.ExpiredDataCleanupInterval, zap.L(), deps.DB)
		},
		Shutdown: nil,
	}
}
