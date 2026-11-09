package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every gateway config shipped in the repo must load. In particular the
// route-shadowing check runs at load, so a sample whose routes are ordered
// such that a later route can never match would fail here.
func TestShippedConfigsLoad(t *testing.T) {
	// Files in these directories that are not standalone gateway configs
	// (they embed one inside a Helm or Compose document instead).
	skip := map[string]bool{
		"helm-values.yaml":            true,
		"docker-compose.yaml":         true,
		"docker_compose.example.yaml": true,
	}

	var files []string
	for _, dir := range []string{"../../config", "../../examples"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Skipf("cannot read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" || skip[e.Name()] {
				continue
			}
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	assert.NotEmpty(t, files, "no shipped configs found")

	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			_, err := Load(f)
			assert.NoError(t, err)
		})
	}
}
