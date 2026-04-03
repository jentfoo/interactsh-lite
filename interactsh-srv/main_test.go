package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunHealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network")
	}
	t.Parallel()

	t.Run("system_info", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		runHealthCheck(&buf, "1.0.0", "/nonexistent", false)
		output := buf.String()

		assert.Contains(t, output, "interactsh-srv 1.0.0")
		assert.Contains(t, output, runtime.GOOS)
		assert.Contains(t, output, runtime.GOARCH)
		assert.Contains(t, output, runtime.Version())
	})

	t.Run("config_readable", func(t *testing.T) {
		t.Parallel()

		cfgFile := filepath.Join(t.TempDir(), "config.yaml")
		err := os.WriteFile(cfgFile, []byte("domain:\n  - test.com\n"), 0644)
		if err != nil {
			t.Fatal(err)
		}

		var buf bytes.Buffer
		runHealthCheck(&buf, "1.0.0", cfgFile, true)
		assert.Contains(t, buf.String(), "readable")
	})

	t.Run("config_missing_default", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		runHealthCheck(&buf, "1.0.0", "/nonexistent/config.yaml", false)
		output := buf.String()
		assert.Contains(t, output, "not found")
		assert.NotContains(t, output, "ERROR")
	})

	t.Run("config_missing_explicit", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		runHealthCheck(&buf, "1.0.0", "/nonexistent/config.yaml", true)
		assert.Contains(t, buf.String(), "ERROR")
	})
}
