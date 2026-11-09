package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizePathPrefix(t *testing.T) {
	assert.Equal(t, "/git", NormalizePathPrefix("/git"))
	assert.Equal(t, "/git", NormalizePathPrefix("/git/"))
	assert.Equal(t, "/git", NormalizePathPrefix("/git///"))
	assert.Equal(t, "/", NormalizePathPrefix("/"))
	assert.Equal(t, "/", NormalizePathPrefix("///"))
	assert.Equal(t, "", NormalizePathPrefix(""))
}

func TestPathPrefixMatches(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		path   string
		want   bool
	}{
		{"/git", "/git", true},
		{"/git", "/git/", true},
		{"/git", "/git/repo", true},
		{"/git", "/github", false},
		{"/git", "/github/repos", false},
		{"/git", "/git.", false},
		{"/git", "/gitlab", false},
		{"/git/", "/git", true},
		{"/git/", "/git/repo", true},
		{"/git/", "/github", false},
		{"/github", "/github/repos", true},
		{"/api/v2", "/api/v2/users", true},
		{"/api/v2", "/api/v20", false},
		{"/", "/anything/at/all", true},
		{"/", "/", true},
		{"", "/anything", true},
	} {
		assert.Equal(t, tc.want, PathPrefixMatches(tc.prefix, tc.path),
			"prefix %q path %q", tc.prefix, tc.path)
	}
}

func TestPathPrefixShadows(t *testing.T) {
	for _, tc := range []struct {
		earlier string
		later   string
		want    bool
	}{
		{"/api", "/api/v2", true},
		{"/api", "/api", true},
		{"/api/", "/api", true},
		{"/api", "/api/", true},
		{"/", "/api", true},
		{"/api/v2", "/api", false},
		{"/git", "/github", false},
		{"/openai", "/anthropic", false},
	} {
		assert.Equal(t, tc.want, PathPrefixShadows(tc.earlier, tc.later),
			"earlier %q later %q", tc.earlier, tc.later)
	}
}

func TestStripRoutePrefix(t *testing.T) {
	for _, tc := range []struct {
		path  string
		strip string
		want  string
	}{
		{"/api/v1/users", "/api", "/v1/users"},
		{"/api", "/api", "/"},
		{"/api/", "/api", "/"},
		{"/api/v1", "/api/", "/v1"},
		{"/api", "/api/", "/"},
		{"/apifoo/x", "/api", "/apifoo/x"},
		{"/api/v1/users", "", "/api/v1/users"},
		{"/api/v1/users", "/", "/api/v1/users"},
		{"/other/x", "/api", "/other/x"},
	} {
		assert.Equal(t, tc.want, stripRoutePrefix(tc.path, tc.strip),
			"path %q strip %q", tc.path, tc.strip)
	}
}
