package config

// Exported so the admin API's config.validate can run the same defaults
// pipeline against a candidate config without applying it.
func ApplyDefaults(c *Config) {
	applyDefaults(c)
}

func applyDefaults(c *Config) {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:8080"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = parseDur("2s")
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = parseDur("2s")
	}
	if c.Server.IdleTimeout == 0 {
		c.Server.IdleTimeout = parseDur("30s")
	}
	if c.Server.ShutdownTimeout == 0 {
		c.Server.ShutdownTimeout = parseDur("5s")
	}

	if c.Pow.TokenParam == "" {
		c.Pow.TokenParam = "token"
	}
	if c.Pow.SignParam == "" {
		c.Pow.SignParam = "sign"
	}
	if c.Pow.MaxTokenLength == 0 {
		c.Pow.MaxTokenLength = 4096
	}
	if c.Pow.MaxSignLength == 0 {
		c.Pow.MaxSignLength = 128
	}
	if c.Pow.Algorithm == "" {
		c.Pow.Algorithm = "sha256"
	}

	if c.Pow.Modes.IPBound.MinDifficulty == 0 {
		c.Pow.Modes.IPBound.MinDifficulty = 22
	}
	if c.Pow.Modes.IPBound.MaxDifficulty == 0 {
		c.Pow.Modes.IPBound.MaxDifficulty = 28
	}
	if c.Pow.Modes.IPBound.MaxTTLSeconds == 0 {
		c.Pow.Modes.IPBound.MaxTTLSeconds = 86400
	}

	if c.Pow.Modes.Generic.MinDifficulty == 0 {
		c.Pow.Modes.Generic.MinDifficulty = 22
	}
	if c.Pow.Modes.Generic.MaxDifficulty == 0 {
		c.Pow.Modes.Generic.MaxDifficulty = 28
	}
	if c.Pow.Modes.Generic.MaxTTLSeconds == 0 {
		c.Pow.Modes.Generic.MaxTTLSeconds = 1800
	}
	if c.Pow.Modes.Generic.MaxUses == 0 {
		c.Pow.Modes.Generic.MaxUses = 5
	}

	if c.Storage.Driver == "" {
		c.Storage.Driver = "memory"
	}
	if c.Storage.CounterDriver == "" {
		c.Storage.CounterDriver = "memory"
	}
	if c.Storage.Postgres.MaxOpenConns == 0 {
		c.Storage.Postgres.MaxOpenConns = 20
	}
	if c.Storage.Postgres.MaxIdleConns == 0 {
		c.Storage.Postgres.MaxIdleConns = 5
	}
	if c.Storage.Redis.Addr == "" {
		c.Storage.Redis.Addr = "127.0.0.1:6379"
	}
	if c.Storage.Redis.KeyPrefix == "" {
		c.Storage.Redis.KeyPrefix = "mirrors-waf"
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}

	if c.Admin.Listen == "" {
		c.Admin.Listen = "127.0.0.1:8081"
	}

	if c.Cleanup.Interval == 0 {
		c.Cleanup.Interval = parseDur("10m")
	}
	if c.Cleanup.ExpiredGracePeriod == 0 {
		c.Cleanup.ExpiredGracePeriod = parseDur("24h")
	}
}
