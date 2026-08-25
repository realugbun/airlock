package config

import (
	"fmt"
	"os"
	"time"

	"github.com/realugbun/airlock/pkg/secrets"
	"gopkg.in/yaml.v3"
)

// Config is the top-level gateway configuration.
type Config struct {
	Listen    string          `yaml:"listen"`
	Service   string          `yaml:"service"`
	AgentID   string          `yaml:"agent_id"`
	Strict    *bool           `yaml:"strict,omitempty"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Providers ProvidersConfig `yaml:"providers"`
	Routes    []RouteConfig   `yaml:"routes"`
}

// IsStrict returns true if strict mode is enabled (the default).
// In strict mode, every route must have access_rules defined.
func (c *Config) IsStrict() bool {
	if c.Strict == nil {
		return true
	}
	return *c.Strict
}

// TelemetryConfig defines the OTel export settings.
type TelemetryConfig struct {
	Endpoint    string `yaml:"endpoint"`
	ServiceName string `yaml:"service_name"`
	Insecure    bool   `yaml:"insecure"`
}

// ProvidersConfig holds configuration for each secret provider.
type ProvidersConfig struct {
	Vault   *VaultProviderConfig   `yaml:"vault,omitempty"`
	Env     *EnvProviderConfig     `yaml:"env,omitempty"`
	EnvFile *EnvFileProviderConfig `yaml:"envfile,omitempty"`
	File    *FileProviderConfig    `yaml:"file,omitempty"`
	AWSSM   *AWSSmProviderConfig   `yaml:"aws_sm,omitempty"`
}

// VaultProviderConfig holds Vault-specific settings.
type VaultProviderConfig struct {
	Address    string `yaml:"address"`
	TokenPath  string `yaml:"token_path"`
	SkipVerify bool   `yaml:"skip_verify"`
	CacheTTL   string `yaml:"cache_ttl"`
}

// ParseCacheTTL parses the cache TTL duration string, defaulting to 5m.
func (v *VaultProviderConfig) ParseCacheTTL() (time.Duration, error) {
	if v.CacheTTL == "" {
		return 5 * time.Minute, nil
	}
	return time.ParseDuration(v.CacheTTL)
}

// EnvProviderConfig holds env provider settings (currently empty).
type EnvProviderConfig struct{}

// EnvFileProviderConfig holds envfile provider settings.
type EnvFileProviderConfig struct {
	Path string `yaml:"path"`
}

// FileProviderConfig holds file provider settings (currently empty).
type FileProviderConfig struct{}

// AWSSmProviderConfig holds AWS Secrets Manager settings.
type AWSSmProviderConfig struct {
	Region string `yaml:"region"`
}

// RouteConfig defines a single proxy route.
type RouteConfig struct {
	PathPrefix           string             `yaml:"path_prefix"`
	Upstream             string             `yaml:"upstream"`
	StripPrefix          string             `yaml:"strip_prefix"`
	Auth                 AuthConfig         `yaml:"auth"`
	RateLimit            *RateLimitConfig   `yaml:"rate_limit,omitempty"`
	AccessRules          []AccessRuleConfig `yaml:"access_rules,omitempty"`
	StripResponseHeaders []string           `yaml:"strip_response_headers,omitempty"`
	Timeout              string             `yaml:"timeout,omitempty"`
	IdleTimeout          string             `yaml:"idle_timeout,omitempty"`
	StripAgentAuth       bool               `yaml:"strip_agent_auth,omitempty"`
	StripForwardHeaders  bool               `yaml:"strip_forwarding_headers,omitempty"`
	ExtraHeaders         map[string]string  `yaml:"extra_headers,omitempty"`
	MCPRules             *MCPRulesConfig    `yaml:"mcp_rules,omitempty"`
}

// AccessRuleConfig is a single firewall-style access rule.
//
// Exactly one of Path or PathRegex must be set:
//   - Path: glob pattern (segment-based; * matches one segment, ** matches zero or more)
//   - PathRegex: Go RE2 regex (full-match anchored automatically; no lookahead/backrefs)
type AccessRuleConfig struct {
	Action    string `yaml:"action"`                // ALLOW or DENY
	Method    string `yaml:"method"`                // GET, POST, DELETE, ALL, etc.
	Path      string `yaml:"path,omitempty"`        // glob pattern: /users/*/detail, /repos/**
	PathRegex string `yaml:"path_regex,omitempty"`  // RE2 regex: /rest/api/3/issue/AI-\d+
}

// MaxPathRegexLen caps the length of a path_regex pattern at config load.
// RE2 prevents catastrophic backtracking, but a multi-kilobyte regex is almost
// certainly a config mistake or an attempt to abuse the loader.
const MaxPathRegexLen = 512

// AuthConfig defines authentication for a route.
type AuthConfig struct {
	Type         string            `yaml:"type"`
	Token        *secrets.SecretRef `yaml:"token,omitempty"`
	ClientID     *secrets.SecretRef `yaml:"client_id,omitempty"`
	ClientSecret *secrets.SecretRef `yaml:"client_secret,omitempty"`
	RefreshToken *secrets.SecretRef `yaml:"refresh_token,omitempty"`
	TokenURL     string            `yaml:"token_url,omitempty"`
	Scopes       string            `yaml:"scopes,omitempty"`
	Header       string            `yaml:"header"`
	Prefix       string            `yaml:"prefix"`
}

// RateLimitConfig defines per-route rate limiting.
type RateLimitConfig struct {
	RPS   float64 `yaml:"rps"`
	Burst int     `yaml:"burst"`
}

// MCPRulesConfig defines MCP tool-level access control for a route.
// When set (even empty), enables MCP-aware body inspection.
// Only one of AllowedTools or DeniedTools may be set.
type MCPRulesConfig struct {
	AllowedTools []string `yaml:"allowed_tools,omitempty"`
	DeniedTools  []string `yaml:"denied_tools,omitempty"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Service == "" {
		return fmt.Errorf("service is required")
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route is required")
	}

	for i, r := range c.Routes {
		if r.PathPrefix == "" {
			return fmt.Errorf("route %d: path_prefix is required", i)
		}
		if r.Upstream == "" {
			return fmt.Errorf("route %d: upstream is required", i)
		}
		if r.Auth.Type == "" {
			return fmt.Errorf("route %d: auth.type is required", i)
		}
		switch r.Auth.Type {
		case "static":
			if r.Auth.Token == nil {
				return fmt.Errorf("route %d: auth.token is required for static auth", i)
			}
		case "oauth2":
			if r.Auth.ClientID == nil || r.Auth.ClientSecret == nil || r.Auth.RefreshToken == nil {
				return fmt.Errorf("route %d: client_id, client_secret, and refresh_token are required for oauth2 auth", i)
			}
			if r.Auth.TokenURL == "" {
				return fmt.Errorf("route %d: auth.token_url is required for oauth2 auth", i)
			}
		default:
			return fmt.Errorf("route %d: unknown auth type %q", i, r.Auth.Type)
		}
		if r.Auth.Header == "" {
			return fmt.Errorf("route %d: auth.header is required", i)
		}
		if r.MCPRules != nil && len(r.MCPRules.AllowedTools) > 0 && len(r.MCPRules.DeniedTools) > 0 {
			return fmt.Errorf("route %d: mcp_rules cannot have both allowed_tools and denied_tools", i)
		}
		if c.IsStrict() && r.AccessRules == nil {
			return fmt.Errorf("route %d (%s): access_rules required when strict mode is enabled (default); set strict: false to allow routes without access rules", i, r.PathPrefix)
		}
		for j, ar := range r.AccessRules {
			hasPath := ar.Path != ""
			hasRegex := ar.PathRegex != ""
			if hasPath && hasRegex {
				return fmt.Errorf("route %d (%s) access_rules[%d]: only one of path or path_regex may be set", i, r.PathPrefix, j)
			}
			if !hasPath && !hasRegex {
				return fmt.Errorf("route %d (%s) access_rules[%d]: one of path or path_regex is required", i, r.PathPrefix, j)
			}
			if hasRegex && len(ar.PathRegex) > MaxPathRegexLen {
				return fmt.Errorf("route %d (%s) access_rules[%d]: path_regex exceeds %d characters", i, r.PathPrefix, j, MaxPathRegexLen)
			}
		}
	}

	return nil
}
