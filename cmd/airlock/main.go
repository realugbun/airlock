package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/realugbun/airlock/internal/auth"
	"github.com/realugbun/airlock/internal/config"
	"github.com/realugbun/airlock/internal/middleware"
	"github.com/realugbun/airlock/internal/proxy"
	"github.com/realugbun/airlock/internal/telemetry"
	airlocklog "github.com/realugbun/airlock/pkg/log"
	"github.com/realugbun/airlock/pkg/secrets"
	"golang.org/x/time/rate"
)

// Set at build time via -ldflags -X.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	healthcheck := flag.Bool("healthcheck", false, "run healthcheck and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("airlock %s (%s) built %s\n", version, commit, buildTime)
		return
	}

	if *healthcheck {
		runHealthcheck(*configPath)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := airlocklog.NewLogger(os.Stdout, cfg.Service, cfg.AgentID)

	ctx := context.Background()

	// Initialize telemetry
	if cfg.Telemetry.Endpoint != "" {
		shutdown, err := telemetry.Init(ctx, telemetry.Config{
			Endpoint:    cfg.Telemetry.Endpoint,
			ServiceName: cfg.Telemetry.ServiceName,
			AgentID:     cfg.AgentID,
			Insecure:    cfg.Telemetry.Insecure,
		})
		if err != nil {
			logger.Error("failed to initialize telemetry", "error", err.Error())
		} else {
			defer func() {
				if err := shutdown(ctx); err != nil {
					logger.Error("telemetry shutdown error", "error", err.Error())
				}
			}()
		}
	}

	// Initialize secret providers
	registry := secrets.NewRegistry()
	if err := initProviders(ctx, cfg, registry); err != nil {
		logger.Error("failed to initialize secret providers", "error", err.Error())
		os.Exit(1)
	}

	// Build router
	router := proxy.NewRouter(proxy.RouterConfig{
		AgentID: cfg.AgentID,
		Logger:  logger,
	})

	routes, err := buildRoutes(cfg, registry, logger)
	if err != nil {
		logger.Error("failed to build routes", "error", err.Error())
		os.Exit(1)
	}
	router.SetRoutes(routes)

	// Handler chain: correlation → request logger → router
	var handler http.Handler = router
	handler = middleware.RequestLogger(logger)(handler)
	handler = middleware.Correlation(handler)

	server := &http.Server{
		Addr:    cfg.Listen,
		Handler: handler,
	}

	// Signal handling: SIGHUP reloads config, SIGINT/SIGTERM shuts down
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				logger.Info("SIGHUP received, reloading config", "path", *configPath)
				reloadConfig(*configPath, router, logger)
				continue
			}
			logger.Info("shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				logger.Error("server shutdown error", "error", err.Error())
			}
			return
		}
	}()

	logger.Info("gateway started",
		"listen_addr", cfg.Listen,
		"route_count", len(cfg.Routes),
		"version", version,
		"commit", commit,
		"build_time", buildTime,
	)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("server error", "error", err.Error())
		os.Exit(1)
	}
}

func reloadConfig(configPath string, router *proxy.Router, logger *slog.Logger) {
	newCfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("reload failed: invalid config", "error", err.Error())
		return
	}

	// Reinitialize providers from the new config so that changes to
	// Vault address, token path, envfile path, etc. take effect without
	// a full process restart.  Old routes (serving in-flight requests)
	// retain their own registry reference until they are GC'd.
	newRegistry := secrets.NewRegistry()
	if err := initProviders(context.Background(), newCfg, newRegistry); err != nil {
		logger.Error("reload failed: provider init error", "error", err.Error())
		return
	}

	routes, err := buildRoutes(newCfg, newRegistry, logger)
	if err != nil {
		logger.Error("reload failed: invalid routes", "error", err.Error())
		return
	}

	router.SetRoutes(routes)
	logger.Info("config reloaded", "route_count", len(routes))
}

func buildRoutes(cfg *config.Config, registry *secrets.Registry, logger *slog.Logger) ([]*proxy.Route, error) {
	var routes []*proxy.Route

	for _, routeCfg := range cfg.Routes {
		upstream, err := url.Parse(routeCfg.Upstream)
		if err != nil {
			return nil, fmt.Errorf("route %s: invalid upstream URL: %w", routeCfg.PathPrefix, err)
		}

		authProvider := buildAuthProvider(registry, routeCfg)

		ruleInputs := make([]proxy.AccessRuleInput, len(routeCfg.AccessRules))
		for j, r := range routeCfg.AccessRules {
			ruleInputs[j] = proxy.AccessRuleInput{Action: r.Action, Method: r.Method, Path: r.Path, PathRegex: r.PathRegex}
		}
		// Explicit empty access_rules: [] means deny all; omitted means allow all.
		denyAll := routeCfg.AccessRules != nil && len(routeCfg.AccessRules) == 0
		access, err := proxy.NewAccessPolicy(ruleInputs, denyAll)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", routeCfg.PathPrefix, err)
		}

		var limiter *rate.Limiter
		if routeCfg.RateLimit != nil {
			limiter = rate.NewLimiter(
				rate.Limit(routeCfg.RateLimit.RPS),
				routeCfg.RateLimit.Burst,
			)
		}

		timeout, err := parseDurationWithDefault(routeCfg.Timeout, 300*time.Second)
		if err != nil {
			return nil, fmt.Errorf("route %s: invalid timeout: %w", routeCfg.PathPrefix, err)
		}
		idleTimeout, err := parseDurationWithDefault(routeCfg.IdleTimeout, 60*time.Second)
		if err != nil {
			return nil, fmt.Errorf("route %s: invalid idle_timeout: %w", routeCfg.PathPrefix, err)
		}

		var mcpRules *proxy.MCPToolPolicy
		if routeCfg.MCPRules != nil {
			mcpRules, err = proxy.NewMCPToolPolicy(&proxy.MCPToolPolicyConfig{
				AllowedTools: routeCfg.MCPRules.AllowedTools,
				DeniedTools:  routeCfg.MCPRules.DeniedTools,
			})
			if err != nil {
				return nil, fmt.Errorf("route %s: %w", routeCfg.PathPrefix, err)
			}
		}

		routes = append(routes, &proxy.Route{
			PathPrefix:           routeCfg.PathPrefix,
			StripPrefix:          routeCfg.StripPrefix,
			Upstream:             upstream,
			Auth:                 authProvider,
			Access:               access,
			Limiter:              limiter,
			StripResponseHeaders: routeCfg.StripResponseHeaders,
			Timeout:              timeout,
			IdleTimeout:          idleTimeout,
			StripAgentAuth:       routeCfg.StripAgentAuth,
			StripForwardHeaders:  routeCfg.StripForwardHeaders,
			ExtraHeaders:         routeCfg.ExtraHeaders,
			MCPRules:             mcpRules,
		})
	}

	return routes, nil
}

func initProviders(ctx context.Context, cfg *config.Config, registry *secrets.Registry) error {
	if cfg.Providers.Env != nil {
		registry.Register("env", secrets.NewEnvProvider())
	}

	if cfg.Providers.File != nil {
		registry.Register("file", secrets.NewFileProvider())
	}

	if cfg.Providers.EnvFile != nil {
		p, err := secrets.NewEnvFileProvider(secrets.EnvFileConfig{
			Path: cfg.Providers.EnvFile.Path,
		})
		if err != nil {
			return fmt.Errorf("envfile provider: %w", err)
		}
		registry.Register("envfile", p)
	}

	if cfg.Providers.Vault != nil {
		ttl, err := cfg.Providers.Vault.ParseCacheTTL()
		if err != nil {
			return fmt.Errorf("vault cache_ttl: %w", err)
		}
		p, err := secrets.NewVaultProvider(secrets.VaultConfig{
			Address:    cfg.Providers.Vault.Address,
			TokenPath:  cfg.Providers.Vault.TokenPath,
			SkipVerify: cfg.Providers.Vault.SkipVerify,
			CacheTTL:   ttl,
		})
		if err != nil {
			return fmt.Errorf("vault provider: %w", err)
		}
		registry.Register("vault", p)
	}

	if cfg.Providers.AWSSM != nil {
		p, err := secrets.NewAWSSmProvider(ctx, secrets.AWSSmConfig{
			Region: cfg.Providers.AWSSM.Region,
		})
		if err != nil {
			return fmt.Errorf("aws_sm provider: %w", err)
		}
		registry.Register("aws_sm", p)
	}

	return nil
}

func buildAuthProvider(registry *secrets.Registry, routeCfg config.RouteConfig) auth.AuthProvider {
	switch routeCfg.Auth.Type {
	case "static":
		return auth.NewStaticAuth(registry, auth.StaticAuthConfig{
			Token:  *routeCfg.Auth.Token,
			Header: routeCfg.Auth.Header,
			Prefix: routeCfg.Auth.Prefix,
		})
	case "oauth2":
		return auth.NewOAuth2Auth(registry, auth.OAuth2AuthConfig{
			ClientID:     *routeCfg.Auth.ClientID,
			ClientSecret: *routeCfg.Auth.ClientSecret,
			RefreshToken: *routeCfg.Auth.RefreshToken,
			TokenURL:     routeCfg.Auth.TokenURL,
			Scopes:       routeCfg.Auth.Scopes,
			Header:       routeCfg.Auth.Header,
			Prefix:       routeCfg.Auth.Prefix,
		})
	case "none":
		return auth.NewNoneAuth()
	default:
		return nil
	}
}

func runHealthcheck(configPath string) {
	port := "8080"
	cfg, err := config.Load(configPath)
	if err == nil {
		_, p, err := net.SplitHostPort(cfg.Listen)
		if err == nil {
			port = p
		}
	}

	resp, err := http.Get("http://localhost:" + port + "/healthz")
	if err != nil {
		os.Exit(1)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}

// parseDurationWithDefault parses a Go duration string, returning the default
// if the string is empty. A value of "0" or "0s" disables the timeout.
func parseDurationWithDefault(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}
