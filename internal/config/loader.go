package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Load reads configuration from the following sources, in increasing
// precedence:
//
//  1. Built-in defaults applied in code (see defaults.go).
//  2. The YAML file at the given path (or auto-discovered).
//  3. Environment variables with prefix MIRRORS_WAF_ and separator __.
//     e.g. MIRRORS_WAF_SERVER__LISTEN -> server.listen,
//          MIRRORS_WAF_POW__DRY_RUN   -> pow.dry_run
//
// The returned Config has already had defaults applied and passed
// Validate(). Callers that want a raw, unvalidated object should use
// LoadRaw.
func Load(path string) (*Config, error) {
	cfg, err := LoadRaw(path)
	if err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadRaw reads + unmarshals configuration without applying defaults or
// running validation.
func LoadRaw(path string) (*Config, error) {
	v := viper.New()

	if path != "" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("config: resolve path %q: %w", path, err)
		}
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("config: stat %q: %w", path, err)
		}
		v.SetConfigFile(abs)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		// Look in a few well-known locations.
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/mirrors-waf")
	}

	// Environment overrides.
	v.SetEnvPrefix("MIRRORS_WAF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "__"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		// Config file is optional when the path is empty and env is enough.
		if path == "" && isConfigFileNotFoundError(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("config: read: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return &cfg, nil
}

// LoadRawFromBytes parses a config from raw YAML/JSON bytes.
func LoadRawFromBytes(b []byte) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("config: read bytes: %w", err)
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return &cfg, nil
}

// isConfigFileNotFoundError reports whether err is one of viper's
// "no such file" errors.
func isConfigFileNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// viper.ConfigFileNotFoundError has these substrings in its Error().
	s := err.Error()
	return strings.Contains(s, "no such file") ||
		strings.Contains(s, "While parsing config") ||
		strings.Contains(s, "ConfigFileNotFound")
}
