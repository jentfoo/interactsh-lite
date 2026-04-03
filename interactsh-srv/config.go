package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/go-appsec/interactsh-lite/interactsh-srv/oobsrv"
)

// LoadConfig loads server configuration from YAML, applying defaults.
// When mustExist is true, a missing file is an error; otherwise defaults are returned.
func LoadConfig(path string, mustExist bool) (oobsrv.Config, error) {
	cfg := oobsrv.DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if mustExist {
				return cfg, fmt.Errorf("config file not found: %s", path)
			}
			return cfg, nil
		}
		return cfg, err
	}

	err = yaml.Unmarshal(data, &cfg)
	return cfg, err
}

// SaveConfig writes cfg as YAML to path, creating parent directories as needed.
func SaveConfig(path string, cfg oobsrv.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}
	return os.WriteFile(path, data, 0644)
}

// DefaultConfigPath returns the platform config file path.
func DefaultConfigPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(configDir, "interactsh-server", "config.yaml")
}

// ExpandResolvers expands resolver entries. File paths are read line-by-line
// (supporting comma-separated values). Otherwise the entry is kept as-is.
func ExpandResolvers(resolvers []string) ([]string, error) {
	var result []string
	for _, r := range resolvers {
		info, err := os.Stat(r)
		if err == nil && !info.IsDir() {
			data, readErr := os.ReadFile(r)
			if readErr != nil {
				return nil, readErr
			}
			for _, line := range strings.Split(string(data), "\n") {
				for _, part := range strings.Split(line, ",") {
					if p := strings.TrimSpace(part); p != "" {
						result = append(result, p)
					}
				}
			}
		} else {
			result = append(result, r)
		}
	}
	return result, nil
}
