package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Loaded carries the effective config together with the source metadata needed
// by the local config manager (the garmr CLI).
type Loaded struct {
	Config   *Config
	Path     string
	Raw      []byte
	Explicit bool
	Managed  bool
}

// LoadWithSource loads configuration and preserves the exact source bytes.
// Managed is true only for an explicit, non-empty regular file path; callers
// may use it to gate write operations without accepting a path from the API.
func LoadWithSource(path string, explicit bool) (*Loaded, error) {
	if explicit && strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("config: explicit --config path must not be empty")
	}
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	loaded := &Loaded{Config: cfg, Explicit: explicit}
	if strings.TrimSpace(path) == "" {
		return loaded, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve path %q: %w", path, err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("config: stat %q: %w", path, err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: read source %q: %w", path, err)
	}
	loaded.Path = abs
	loaded.Raw = append([]byte(nil), raw...)
	loaded.Managed = explicit && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
	return loaded, nil
}

// Load reads configuration from the following sources, in increasing
// precedence:
//
//  1. Built-in defaults applied in code (see defaults.go).
//  2. The YAML file at the given path (or auto-discovered).
//  3. Environment variables with prefix MIRRORS_WAF_ and separator __.
//
// Environment variables map onto config keys by replacing __ with a dot
// and lowercasing, so MIRRORS_WAF_SERVER__LISTEN sets server.listen and
// MIRRORS_WAF_POW__DRY_RUN sets pow.dry_run.
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
	if err := v.UnmarshalExact(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return &cfg, nil
}

// LoadRawFromBytes parses a config from raw YAML/JSON bytes.
func LoadRawFromBytes(b []byte) (*Config, error) {
	if err := ValidateYAMLStructure(b); err != nil {
		return nil, err
	}
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("config: read bytes: %w", err)
	}
	var cfg Config
	if err := v.UnmarshalExact(&cfg); err != nil {
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
