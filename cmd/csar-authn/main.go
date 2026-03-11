// csar-authn is a standalone OAuth authentication service.
//
// It handles multi-provider OAuth login (via Goth), maps social identities
// to internal user UUIDs, issues JWT session tokens, and exposes a JWKS
// endpoint for the csar router to validate sessions.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/ledatu/csar-core/configload"
	"github.com/ledatu/csar-core/configsource"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/health"
	"github.com/ledatu/csar-core/httpmiddleware"
	"github.com/ledatu/csar-core/httpserver"
	"github.com/ledatu/csar-core/logutil"
	"github.com/ledatu/csar-core/observe"
	"github.com/ledatu/csar-core/tlsx"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/handler"
	"github.com/ledatu/csar-authn/internal/oauth"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/postgres"
	"github.com/ledatu/csar-authn/internal/sts"

	"github.com/redis/go-redis/v9"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	srcParams, refreshInterval, metricsAddr, otlpEndpoint, otlpInsecure := parseFlags()

	inner := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(logutil.NewRedactingHandler(inner))

	if err := run(srcParams, refreshInterval, metricsAddr, otlpEndpoint, otlpInsecure, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func parseFlags() (configsource.SourceParams, string, string, string, bool) {
	p := configsource.SourceParams{
		Source:        envOrDefault("CONFIG_SOURCE", "file"),
		File:          envOrDefault("CONFIG_FILE", "config.yaml"),
		S3Bucket:      envOrDefault("CONFIG_S3_BUCKET", ""),
		S3Key:         envOrDefault("CONFIG_S3_KEY", "config.yaml"),
		S3Endpoint:    envOrDefault("CONFIG_S3_ENDPOINT", "https://storage.yandexcloud.net"),
		S3Region:      envOrDefault("CONFIG_S3_REGION", "ru-central1"),
		S3AuthMode:    envOrDefault("CONFIG_S3_AUTH_MODE", "static"),
		S3AccessKeyID: envOrDefault("CONFIG_S3_ACCESS_KEY_ID", ""),
		S3SecretKey:   envOrDefault("CONFIG_S3_SECRET_ACCESS_KEY", ""),
		S3IAMToken:    envOrDefault("CONFIG_S3_IAM_TOKEN", ""),
		S3OAuthToken:  envOrDefault("CONFIG_S3_OAUTH_TOKEN", ""),
		S3SAKeyFile:   envOrDefault("CONFIG_S3_SA_KEY_FILE", ""),
	}
	refreshInterval := envOrDefault("CONFIG_REFRESH_INTERVAL", "0")
	metricsAddr := ""
	otlpEndpoint := ""
	otlpInsecure := false

	flag.StringVar(&p.Source, "config-source", p.Source, `config source: "file" or "s3"`)
	flag.StringVar(&p.File, "config", p.File, "path to config file (file source)")
	flag.StringVar(&p.S3Bucket, "config-s3-bucket", p.S3Bucket, "S3 bucket for config")
	flag.StringVar(&p.S3Key, "config-s3-key", p.S3Key, "S3 object key for config")
	flag.StringVar(&p.S3Endpoint, "config-s3-endpoint", p.S3Endpoint, "S3 endpoint")
	flag.StringVar(&p.S3Region, "config-s3-region", p.S3Region, "S3 region")
	flag.StringVar(&p.S3AuthMode, "config-s3-auth-mode", p.S3AuthMode, "S3 auth mode")
	flag.StringVar(&p.S3AccessKeyID, "config-s3-access-key-id", p.S3AccessKeyID, "S3 access key ID")
	flag.StringVar(&p.S3SecretKey, "config-s3-secret-access-key", p.S3SecretKey, "S3 secret access key")
	flag.StringVar(&p.S3IAMToken, "config-s3-iam-token", p.S3IAMToken, "S3 IAM token")
	flag.StringVar(&p.S3OAuthToken, "config-s3-oauth-token", p.S3OAuthToken, "S3 OAuth token")
	flag.StringVar(&p.S3SAKeyFile, "config-s3-sa-key-file", p.S3SAKeyFile, "S3 service account key file")
	flag.StringVar(&refreshInterval, "config-refresh-interval", refreshInterval, "config polling interval (e.g. 60s); 0 disables")
	flag.StringVar(&metricsAddr, "metrics-addr", metricsAddr, "Prometheus metrics listen address (empty to disable)")
	flag.StringVar(&otlpEndpoint, "otlp-endpoint", otlpEndpoint, "OTLP gRPC endpoint for tracing (empty to disable)")
	flag.BoolVar(&otlpInsecure, "otlp-insecure", otlpInsecure, "use insecure connection for OTLP")

	flag.Parse()
	return p, refreshInterval, metricsAddr, otlpEndpoint, otlpInsecure
}

func run(
	p configsource.SourceParams,
	refreshInterval, metricsAddr, otlpEndpoint string,
	otlpInsecure bool,
	logger *slog.Logger,
) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := configload.LoadInitial(ctx, &p, logger, config.LoadFromBytes)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	logger.Info("config loaded",
		"listen_addr", cfg.ListenAddr,
		"database_driver", cfg.Database.Driver,
		"providers", len(cfg.OAuth.Providers),
	)

	// Use config-level metrics_addr if CLI flag is empty.
	if metricsAddr == "" {
		metricsAddr = cfg.MetricsAddr
	}

	// --- Observability ---
	tp, err := observe.InitTracer(ctx, observe.TraceConfig{
		ServiceName:    "csar-authn",
		ServiceVersion: Version,
		Endpoint:       otlpEndpoint,
		Insecure:       otlpInsecure,
	})
	if err != nil {
		return fmt.Errorf("initializing tracer: %w", err)
	}
	defer tp.Close()

	reg := observe.NewRegistry()

	// --- Database ---
	var st store.Store
	switch cfg.Database.Driver {
	case "postgres":
		pgStore, err := postgres.New(ctx, cfg.Database.DSN, postgres.WithLogger(logger))
		if err != nil {
			return fmt.Errorf("connecting to postgres: %w", err)
		}
		st = pgStore
	default:
		return fmt.Errorf("unsupported database driver: %s", cfg.Database.Driver)
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	logger.Info("migrations applied")

	// --- JWT keys ---
	keys, err := session.LoadOrGenerateKeys(
		cfg.JWT.Algorithm,
		cfg.JWT.PrivateKeyFile,
		cfg.JWT.PublicKeyFile,
		cfg.JWT.KeyDir,
		cfg.JWT.AutoGenerate,
		logger,
	)
	if err != nil {
		return fmt.Errorf("loading keys: %w", err)
	}
	logger.Info("signing keys ready", "kid", keys.KID, "algorithm", keys.Algorithm)

	sessionMgr := session.NewManager(keys, cfg.JWT)

	oauthMgr, err := oauth.NewManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("initializing oauth: %w", err)
	}

	var stsHandler *sts.Handler
	if cfg.STS.Enabled {
		stsHandler, err = initSTS(ctx, cfg, st, sessionMgr, logger)
		if err != nil {
			return err
		}
	}

	// Optional authz client for permissions endpoints.
	var authzClient *handler.AuthzClient
	if cfg.Authz.Enabled {
		authzClient, err = handler.NewAuthzClient(cfg.Authz.Endpoint, cfg.Authz.TLS, logger.With("component", "authz_client"))
		if err != nil {
			return fmt.Errorf("connecting to authz service: %w", err)
		}
		defer authzClient.Close()
		logger.Info("authz client connected", "endpoint", cfg.Authz.Endpoint)
	}

	// --- Routes ---
	mux := http.NewServeMux()
	h := handler.New(st, sessionMgr, oauthMgr, stsHandler, authzClient, logger, cfg)
	h.RegisterRoutes(mux)

	// Health and readiness endpoints.
	mux.Handle("GET /health", health.Handler(Version))
	rc := health.NewReadinessChecker(Version, true)
	if pgStore, ok := st.(*postgres.Store); ok {
		pool := pgStore.Pool()
		rc.Register("postgres", func() health.CheckStatus {
			if err := pool.Ping(context.Background()); err != nil {
				return health.CheckStatus{Status: "fail", Detail: err.Error()}
			}
			return health.CheckStatus{Status: "ok"}
		})
	}
	mux.Handle("GET /readiness", rc.Handler())

	// --- Middleware ---
	stack := httpmiddleware.Chain(
		httpmiddleware.RequestID,
		httpmiddleware.AccessLog(logger),
		httpmiddleware.Recover(logger),
		httpmiddleware.MaxBodySize(1<<20),
		gatewayctx.Middleware,
		observe.HTTPMiddleware(otel.GetTracerProvider(), "csar-authn"),
	)
	appHandler := stack(mux)

	// --- Config watcher ---
	if interval := parseInterval(refreshInterval); interval > 0 {
		src, err := configsource.BuildSource(&p, logger)
		if err != nil {
			return fmt.Errorf("building config source for watcher: %w", err)
		}
		validate := func(data []byte) error {
			_, err := config.LoadFromBytes(data)
			return err
		}
		watcher := configload.NewValidatingWatcher(
			src,
			logger.With("component", "config_watcher"),
			validate,
			configsource.WithHashPolicy(configsource.HashTOFU),
		)
		go watcher.RunPeriodicWatch(ctx, interval)
		logger.Info("config watcher started (validation-only; config changes require restart)", "interval", interval)
	}

	// --- Metrics sidecar ---
	if metricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", observe.MetricsHandler(reg))
		metricsMux.Handle("/health", health.Handler(Version))
		metricsMux.Handle("/readiness", rc.Handler())

		metricsSrv, err := httpserver.New(&httpserver.Config{
			Addr:         metricsAddr,
			Handler:      metricsMux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}, logger.With("component", "metrics"))
		if err != nil {
			return fmt.Errorf("creating metrics server: %w", err)
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil {
				logger.Error("metrics server error", "error", err)
			}
		}()
		logger.Info("metrics server started", "addr", metricsAddr)
	}

	// --- Main HTTP server ---
	var tlsCfg *tlsx.ServerConfig
	if cfg.TLS.IsEnabled() {
		tlsCfg = &tlsx.ServerConfig{
			CertFile:     cfg.TLS.CertFile,
			KeyFile:      cfg.TLS.KeyFile,
			ClientCAFile: cfg.TLS.ClientCAFile,
			MinVersion:   cfg.TLS.MinVersion,
		}
	}

	srv, err := httpserver.New(&httpserver.Config{
		Addr:    cfg.ListenAddr,
		Handler: appHandler,
		TLS:     tlsCfg,
	}, logger)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	return srv.Run(ctx)
}

func initSTS(
	ctx context.Context,
	cfg *config.Config,
	st store.Store,
	sessionMgr *session.Manager,
	logger *slog.Logger,
) (*sts.Handler, error) {
	var replayStore sts.ReplayStore
	if cfg.Redis != nil && cfg.Redis.Address != "" {
		redisClient := redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Address,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})
		if err := redisClient.Ping(ctx).Err(); err != nil {
			return nil, fmt.Errorf("connecting to redis: %w", err)
		}
		replayStore = sts.NewRedisReplayStore(redisClient)
		logger.Info("STS replay protection: redis", "address", cfg.Redis.Address)
	} else if pgStore, ok := st.(*postgres.Store); ok {
		replayStore = sts.NewPostgresReplayStore(pgStore.Pool())
		logger.Info("STS replay protection: postgres")
	}

	stsHandler, err := sts.New(cfg.STS, cfg.JWT, sessionMgr, replayStore, logger)
	if err != nil {
		return nil, fmt.Errorf("initializing STS: %w", err)
	}
	logger.Info("STS enabled", "service_accounts", len(cfg.STS.ServiceAccounts))
	return stsHandler, nil
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func parseInterval(s string) time.Duration {
	if s == "" || s == "0" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
