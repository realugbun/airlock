package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/realugbun/airlock/pkg/secrets"
)

// OAuth2AuthConfig configures an OAuth2 refresh-token auth provider.
type OAuth2AuthConfig struct {
	ClientID     secrets.SecretRef
	ClientSecret secrets.SecretRef
	RefreshToken secrets.SecretRef
	TokenURL     string
	Scopes       string
	Header       string
	Prefix       string
	HTTPClient   *http.Client
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// OAuth2Auth manages the full OAuth2 refresh-token lifecycle.
type OAuth2Auth struct {
	registry     *secrets.Registry
	clientIDRef  secrets.SecretRef
	clientSecRef secrets.SecretRef
	refreshRef   secrets.SecretRef
	tokenURL     string
	scopes       string
	header       string
	prefix       string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	expiry      time.Time
}

// NewOAuth2Auth creates an OAuth2 auth provider.
func NewOAuth2Auth(registry *secrets.Registry, cfg OAuth2AuthConfig) *OAuth2Auth {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &OAuth2Auth{
		registry:     registry,
		clientIDRef:  cfg.ClientID,
		clientSecRef: cfg.ClientSecret,
		refreshRef:   cfg.RefreshToken,
		tokenURL:     cfg.TokenURL,
		scopes:       cfg.Scopes,
		header:       cfg.Header,
		prefix:       cfg.Prefix,
		httpClient:   client,
	}
}

// AddAuth resolves the access token and sets the header on the request.
// Returns the credential values for response redaction.
func (o *OAuth2Auth) AddAuth(ctx context.Context, req *http.Request) ([]string, error) {
	token, err := o.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	headerValue := o.prefix + token
	req.Header.Set(o.header, headerValue)
	redact := []string{token}
	if headerValue != token {
		redact = append(redact, headerValue)
	}
	return redact, nil
}

func (o *OAuth2Auth) getAccessToken(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Use cached token if still valid with 30s buffer
	if o.accessToken != "" && time.Now().Add(30*time.Second).Before(o.expiry) {
		return o.accessToken, nil
	}

	return o.refresh(ctx)
}

func (o *OAuth2Auth) refresh(ctx context.Context) (string, error) {
	ctx, span := tracer.Start(ctx, "auth.oauth2.refresh")
	defer span.End()

	clientID, err := o.clientIDRef.Resolve(ctx, o.registry)
	if err != nil {
		return "", fmt.Errorf("resolving client_id: %w", err)
	}

	clientSecret, err := o.clientSecRef.Resolve(ctx, o.registry)
	if err != nil {
		return "", fmt.Errorf("resolving client_secret: %w", err)
	}

	refreshToken, err := o.refreshRef.Resolve(ctx, o.registry)
	if err != nil {
		return "", fmt.Errorf("resolving refresh_token: %w", err)
	}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if o.scopes != "" {
		data.Set("scope", o.scopes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	o.accessToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		o.expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		o.expiry = time.Now().Add(1 * time.Hour)
	}

	return o.accessToken, nil
}
