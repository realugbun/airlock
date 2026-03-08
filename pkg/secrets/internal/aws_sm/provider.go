package awssm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// Config holds AWS Secrets Manager provider settings.
type Config struct {
	Region string
}

// Provider reads secrets from AWS Secrets Manager.
type Provider struct {
	client *secretsmanager.Client
}

// New creates an AWS Secrets Manager provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(awsCfg)
	return &Provider{client: client}, nil
}

// GetSecret fetches a secret from AWS Secrets Manager.
// If key is non-empty, the secret value is parsed as JSON and the key is extracted.
func (p *Provider) GetSecret(ctx context.Context, path, key string) (string, error) {
	out, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &path,
	})
	if err != nil {
		return "", fmt.Errorf("getting AWS secret %s: %w", path, err)
	}

	if out.SecretString == nil {
		return "", fmt.Errorf("AWS secret %s has no string value", path)
	}

	if key == "" {
		return *out.SecretString, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(*out.SecretString), &data); err != nil {
		return "", fmt.Errorf("parsing AWS secret %s as JSON: %w", path, err)
	}

	val, ok := data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in AWS secret %s", key, path)
	}

	valStr, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("AWS secret %s key %q is not a string", path, key)
	}

	return valStr, nil
}
