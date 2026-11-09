package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/realugbun/airlock/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// credUpstream is an upstream that knows which credential belongs to it and
// counts every request it receives that carries a different one.
type credUpstream struct {
	server     *httptest.Server
	name       string
	want       string
	hits       atomic.Int32
	mismatches atomic.Int32
	seen       sync.Map // credential value -> struct{}
}

func newCredUpstream(t *testing.T, name, want string) *credUpstream {
	t.Helper()
	u := &credUpstream{name: name, want: want}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		u.hits.Add(1)
		u.seen.Store(got, struct{}{})
		if got != u.want {
			u.mismatches.Add(1)
		}
		w.Header().Set("X-Upstream", u.name)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(u.name))
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *credUpstream) credentials() []string {
	var out []string
	u.seen.Range(func(k, _ any) bool {
		out = append(out, k.(string))
		return true
	})
	return out
}

// snapshotConfig is a one-route config pointing at upstream with a token read
// from tokenEnv, plus any extra routes appended verbatim.
func snapshotConfig(upstream, tokenEnv, extraRoutes string) string {
	return `
service: test
agent_id: test-agent
strict: false
providers:
  env: {}
routes:
  - path_prefix: /api
    upstream: ` + upstream + `
    strip_prefix: /api
    strip_agent_auth: true
    auth:
      type: static
      token:
        from: env
        key: ` + tokenEnv + `
      header: Authorization
      prefix: "Bearer "
    access_rules:
      - action: ALLOW
        method: ALL
        path: "/**"
` + extraRoutes
}

// writeConfigAtomic replaces the config file in one step, so a reload never
// reads a half-written file.
func writeConfigAtomic(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0600))
	require.NoError(t, os.Rename(tmp, path))
}

// get issues a request through the gateway and returns status and body.
func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp.StatusCode, string(body)
}

// A reload that fails validation leaves the routes that were already serving
// in place; it does not partially apply the new config.
func TestReloadConfig_ShadowedRoute_KeepsPreviousRoutes(t *testing.T) {
	t.Setenv("TOKEN_A", "token-a")
	t.Setenv("TOKEN_B", "token-b")

	a := newCredUpstream(t, "A", "Bearer token-a")
	b := newCredUpstream(t, "B", "Bearer token-b")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeConfigAtomic(t, path, snapshotConfig(a.server.URL, "TOKEN_A", ""))

	router := proxy.NewRouter(proxy.RouterConfig{AgentID: "test-agent", Logger: testLogger()})
	reloadConfig(path, router, testLogger())

	gw := httptest.NewServer(router)
	defer gw.Close()

	status, body := get(t, gw.URL+"/api/v1/thing")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "A", body)

	// A config whose second route can never match: it also switches the
	// upstream and credential, so a reload that wrongly went through would
	// be visible on upstream B.
	shadowed := snapshotConfig(b.server.URL, "TOKEN_B", `  - path_prefix: /api/v2
    upstream: `+b.server.URL+`
    auth:
      type: none
    access_rules:
      - action: ALLOW
        method: ALL
        path: "/**"
`)
	writeConfigAtomic(t, path, shadowed)
	reloadConfig(path, router, testLogger())

	status, body = get(t, gw.URL+"/api/v1/thing")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "A", body, "the previous routes must stay active after a failed reload")
	assert.Equal(t, int32(2), a.hits.Load())
	assert.Zero(t, b.hits.Load())
	assert.Zero(t, a.mismatches.Load())

	// A valid reload with the same upstream switch does take effect, which
	// shows the assertion above is not vacuous.
	writeConfigAtomic(t, path, snapshotConfig(b.server.URL, "TOKEN_B", ""))
	reloadConfig(path, router, testLogger())

	status, body = get(t, gw.URL+"/api/v1/thing")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "B", body)
	assert.Equal(t, int32(1), b.hits.Load())
	assert.Zero(t, b.mismatches.Load())
}

// Every request is served entirely by one configuration snapshot: the
// upstream it is sent to and the credential it carries always come from the
// same config, even while reloads replace both.
func TestReloadConfig_RequestUsesSingleSnapshot(t *testing.T) {
	t.Setenv("TOKEN_A", "token-a")
	t.Setenv("TOKEN_B", "token-b")

	a := newCredUpstream(t, "A", "Bearer token-a")
	b := newCredUpstream(t, "B", "Bearer token-b")

	cfgA := snapshotConfig(a.server.URL, "TOKEN_A", "")
	cfgB := snapshotConfig(b.server.URL, "TOKEN_B", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeConfigAtomic(t, path, cfgA)

	logger := testLogger()
	router := proxy.NewRouter(proxy.RouterConfig{AgentID: "test-agent", Logger: logger})
	reloadConfig(path, router, logger)

	gw := httptest.NewServer(router)
	defer gw.Close()

	// Bounded: 8 workers x 60 requests, interleaved with 120 reloads.
	const (
		workers         = 8
		perWorker       = 60
		reloadsPerRound = 120
	)

	var (
		wg       sync.WaitGroup
		statuses sync.Map // status code -> *atomic.Int32
		stop     = make(chan struct{})
	)
	countStatus := func(code int) {
		v, _ := statuses.LoadOrStore(code, new(atomic.Int32))
		v.(*atomic.Int32).Add(1)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < reloadsPerRound; i++ {
			select {
			case <-stop:
				return
			default:
			}
			cfg := cfgA
			if i%2 == 0 {
				cfg = cfgB
			}
			tmp := path + ".reload.tmp"
			if err := os.WriteFile(tmp, []byte(cfg), 0600); err != nil {
				return
			}
			if err := os.Rename(tmp, path); err != nil {
				return
			}
			reloadConfig(path, router, logger)
		}
	}()

	client := &http.Client{}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				resp, err := client.Get(gw.URL + "/api/v1/thing")
				if err != nil {
					countStatus(-1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				countStatus(resp.StatusCode)
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	<-done
	close(stop)

	total := 0
	statuses.Range(func(k, v any) bool {
		code := k.(int)
		n := int(v.(*atomic.Int32).Load())
		assert.Equal(t, http.StatusOK, code, "unexpected status %d on %d requests", code, n)
		total += n
		return true
	})
	assert.Equal(t, workers*perWorker, total)

	assert.Zero(t, a.mismatches.Load(),
		"upstream A received a credential that is not its own: %v", a.credentials())
	assert.Zero(t, b.mismatches.Load(),
		"upstream B received a credential that is not its own: %v", b.credentials())
	assert.Equal(t, int32(workers*perWorker), a.hits.Load()+b.hits.Load())
	// Both snapshots must have served traffic, or the test proved nothing.
	assert.Positive(t, a.hits.Load(), "no request was served by the first config")
	assert.Positive(t, b.hits.Load(), "no request was served by the second config")
}
