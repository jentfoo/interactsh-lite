package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/interactsh-lite/interactsh-srv/oobsrv"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	t.Run("missing_file_returns_defaults", func(t *testing.T) {
		cfg, err := LoadConfig("/nonexistent/path/config.yaml", false)
		require.NoError(t, err)
		assert.Equal(t, oobsrv.DefaultConfig(), cfg)
	})

	t.Run("explicit_missing_errors", func(t *testing.T) {
		_, err := LoadConfig("/nonexistent/path/config.yaml", true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config file not found")
	})

	t.Run("valid_yaml", func(t *testing.T) {
		cfgFile := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte("domain:\n  - test.com\neviction: 15\n"), 0644))

		cfg, err := LoadConfig(cfgFile, false)
		require.NoError(t, err)
		assert.Equal(t, []string{"test.com"}, cfg.Domains)
		assert.Equal(t, 15, cfg.Eviction)
		assert.Equal(t, "0.0.0.0", cfg.ListenIP)
	})

	t.Run("scalar_string_slices", func(t *testing.T) {
		cfgFile := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte("domain: oscar.example.com\nip: 172.233.0.1\n"), 0644))

		cfg, err := LoadConfig(cfgFile, false)
		require.NoError(t, err)
		assert.Equal(t, []string{"oscar.example.com"}, cfg.Domains)
		assert.Equal(t, []string{"172.233.0.1"}, cfg.IPs)
	})

	t.Run("comma_separated_slices", func(t *testing.T) {
		cfgFile := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte("domain: a.com,b.com\nip: 1.2.3.4,5.6.7.8\n"), 0644))

		cfg, err := LoadConfig(cfgFile, false)
		require.NoError(t, err)
		assert.Equal(t, []string{"a.com", "b.com"}, cfg.Domains)
		assert.Equal(t, []string{"1.2.3.4", "5.6.7.8"}, cfg.IPs)
	})

	t.Run("overrides_defaults", func(t *testing.T) {
		cfgFile := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte("listen-ip: \"::\"\nacao-url: https://example.com\n"), 0644))

		cfg, err := LoadConfig(cfgFile, false)
		require.NoError(t, err)
		assert.Equal(t, "::", cfg.ListenIP)
		assert.Equal(t, "https://example.com", cfg.ACAOUrl)
	})

	t.Run("invalid_yaml", func(t *testing.T) {
		cfgFile := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte("domain: [unclosed"), 0644))

		_, err := LoadConfig(cfgFile, false)
		assert.Error(t, err)
	})

	t.Run("unreadable_file", func(t *testing.T) {
		dir := t.TempDir()
		cfgFile := filepath.Join(dir, "noperm.yaml")
		require.NoError(t, os.WriteFile(cfgFile, []byte("domain:\n  - test.com\n"), 0644))
		require.NoError(t, os.Chmod(cfgFile, 0000))
		t.Cleanup(func() { _ = os.Chmod(cfgFile, 0644) })

		_, err := LoadConfig(cfgFile, false)
		assert.Error(t, err)
	})
}

func TestSaveConfig(t *testing.T) {
	t.Parallel()

	t.Run("writes_yaml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.yaml")
		cfg := oobsrv.DefaultConfig()
		cfg.Domains = []string{"example.com"}

		require.NoError(t, SaveConfig(path, cfg))

		loaded, err := LoadConfig(path, true)
		require.NoError(t, err)
		assert.Equal(t, []string{"example.com"}, loaded.Domains)
	})

	t.Run("creates_parent_dirs", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "a", "b", "config.yaml")
		cfg := oobsrv.DefaultConfig()

		require.NoError(t, SaveConfig(path, cfg))

		_, err := os.Stat(path)
		assert.NoError(t, err)
	})
}

func TestExpandResolvers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		fileContent string
		input       []string
		expected    []string
	}{
		{
			name:     "literal_entries",
			input:    []string{"dns1.com", "dns2.com"},
			expected: []string{"dns1.com", "dns2.com"},
		},
		{
			name:        "reads_from_file",
			fileContent: "dns1.com,dns2.com\ndns3.com\n",
			expected:    []string{"dns1.com", "dns2.com", "dns3.com"},
		},
		{
			name:        "mixed_file_and_plain",
			fileContent: "dns1.com\n",
			input:       []string{"dns2.com"},
			expected:    []string{"dns1.com", "dns2.com"},
		},
		{
			name: "nil_input",
		},
		{
			name:     "directory_treated_as_literal",
			input:    []string{os.TempDir()},
			expected: []string{os.TempDir()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input
			if tt.fileContent != "" {
				f := filepath.Join(t.TempDir(), "resolvers.txt")
				require.NoError(t, os.WriteFile(f, []byte(tt.fileContent), 0644))
				input = append([]string{f}, input...)
			}

			result, err := ExpandResolvers(input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
