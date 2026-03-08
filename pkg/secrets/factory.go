package secrets

import (
	"context"
	"time"

	awssm "github.com/realugbun/airlock/pkg/secrets/internal/aws_sm"
	"github.com/realugbun/airlock/pkg/secrets/internal/env"
	"github.com/realugbun/airlock/pkg/secrets/internal/envfile"
	"github.com/realugbun/airlock/pkg/secrets/internal/file"
	"github.com/realugbun/airlock/pkg/secrets/internal/vault"
)

// VaultConfig holds settings for the Vault secret provider.
type VaultConfig struct {
	Address    string
	TokenPath  string
	SkipVerify bool
	CacheTTL   time.Duration
}

// EnvFileConfig holds settings for the envfile secret provider.
type EnvFileConfig struct {
	Path string
}

// AWSSmConfig holds settings for the AWS Secrets Manager provider.
type AWSSmConfig struct {
	Region string
}

// NewEnvProvider creates a provider that reads from environment variables.
func NewEnvProvider() SecretProvider {
	return env.New()
}

// NewFileProvider creates a provider that reads from raw files.
func NewFileProvider() SecretProvider {
	return file.New()
}

// NewEnvFileProvider creates a provider that reads from a KEY=VALUE file.
func NewEnvFileProvider(cfg EnvFileConfig) (SecretProvider, error) {
	return envfile.New(cfg.Path)
}

// NewVaultProvider creates a provider that reads from HashiCorp Vault KV v2.
func NewVaultProvider(cfg VaultConfig) (SecretProvider, error) {
	return vault.New(vault.Config{
		Address:    cfg.Address,
		TokenPath:  cfg.TokenPath,
		SkipVerify: cfg.SkipVerify,
		CacheTTL:   cfg.CacheTTL,
	})
}

// NewAWSSmProvider creates a provider that reads from AWS Secrets Manager.
func NewAWSSmProvider(ctx context.Context, cfg AWSSmConfig) (SecretProvider, error) {
	return awssm.New(ctx, awssm.Config{Region: cfg.Region})
}
