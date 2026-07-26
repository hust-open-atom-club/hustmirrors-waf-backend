package config

import "time"

type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Pow         PowConfig         `mapstructure:"pow"`
	Protection  ProtectionConfig  `mapstructure:"protection"`
	Storage     StorageConfig     `mapstructure:"storage"`
	RiskControl RiskControlConfig `mapstructure:"risk_control"`
	Admin       AdminConfig       `mapstructure:"admin"`
	Logging     LoggingConfig     `mapstructure:"logging"`
	Cleanup     CleanupConfig     `mapstructure:"cleanup"`
}

type ServerConfig struct {
	Listen          string        `mapstructure:"listen"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

type PowConfig struct {
	Enabled   bool `mapstructure:"enabled"`
	DryRun    bool `mapstructure:"dry_run"`
	BypassAll bool `mapstructure:"bypass_all"`

	TokenParam string `mapstructure:"token_param"`
	SignParam  string `mapstructure:"sign_param"`

	MaxTokenLength int `mapstructure:"max_token_length"`
	MaxSignLength  int `mapstructure:"max_sign_length"`

	Algorithm            string   `mapstructure:"algorithm"`
	PublicSalt           string   `mapstructure:"public_salt"`
	AllowEmptySalt       bool     `mapstructure:"allow_empty_salt"`
	AllowedPreviousSalts []string `mapstructure:"allowed_previous_salts"`

	Modes ModesConfig `mapstructure:"modes"`
}

type ModesConfig struct {
	IPBound ModeConfig `mapstructure:"ip_bound"`
	Generic ModeConfig `mapstructure:"generic"`
}

type ModeConfig struct {
	Enabled          bool `mapstructure:"enabled"`
	MinDifficulty    int  `mapstructure:"min_difficulty"`
	MaxDifficulty    int  `mapstructure:"max_difficulty"`
	MaxTTLSeconds    int  `mapstructure:"max_ttl_seconds"`
	RequireIP        bool `mapstructure:"require_ip"`
	CountUsage       bool `mapstructure:"count_usage"`
	MaxUses          int  `mapstructure:"max_uses"`
	CountHeadRequest bool `mapstructure:"count_head_request"`
}

type ProtectionConfig struct {
	ProtectedExtensions []string `mapstructure:"protected_extensions"`
	ProtectedPaths      []string `mapstructure:"protected_paths"`
	ExcludedPaths       []string `mapstructure:"excluded_paths"`
}

type StorageConfig struct {
	Driver        string         `mapstructure:"driver"`         // memory | postgres
	CounterDriver string         `mapstructure:"counter_driver"` // memory | redis
	Postgres      PostgresConfig `mapstructure:"postgres"`
	Redis         RedisConfig    `mapstructure:"redis"`
}

type PostgresConfig struct {
	DSN          string `mapstructure:"dsn"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
}

type RedisConfig struct {
	Addr      string `mapstructure:"addr"`
	Password  string `mapstructure:"password"`
	DB        int    `mapstructure:"db"`
	KeyPrefix string `mapstructure:"key_prefix"`
}

// When Enabled is false the service runs only the base PoW verification logic.
type RiskControlConfig struct {
	Enabled  bool                     `mapstructure:"enabled"`
	Counters map[string]CounterConfig `mapstructure:"counters"`
	Chains   map[string]ChainConfig   `mapstructure:"chains"`
}

type CounterConfig struct {
	Key     string            `mapstructure:"key"` // ip | path | ...
	Window  time.Duration     `mapstructure:"window"`
	When    CounterWhenConfig `mapstructure:"when"`
	Storage string            `mapstructure:"storage"` // memory | redis
}

// Empty fields mean "always increment".
type CounterWhenConfig struct {
	IsProtected    *bool  `mapstructure:"is_protected"`
	IsRangeRequest *bool  `mapstructure:"is_range_request"`
	PowStatus      string `mapstructure:"pow_status"`
	PowMode        string `mapstructure:"pow_mode"`
}

type ChainConfig struct {
	Policy PolicyConfig `mapstructure:"policy"`
	Rules  []RuleConfig `mapstructure:"rules"`
}

type PolicyConfig struct {
	Target    string `mapstructure:"target"`
	Status    int    `mapstructure:"status"`
	LimitRate string `mapstructure:"limit_rate"`
	Reason    string `mapstructure:"reason"`
}

// RuleConfig is a single rule within a chain.
type RuleConfig struct {
	Name      string      `mapstructure:"name"`
	Match     MatchConfig `mapstructure:"match"`
	Target    string      `mapstructure:"target"`
	Chain     string      `mapstructure:"chain"` // for JUMP
	Status    int         `mapstructure:"status"`
	LimitRate string      `mapstructure:"limit_rate"`
	Reason    string      `mapstructure:"reason"`
	Mark      string      `mapstructure:"mark"`
}

// First non-empty match field wins; multiple non-empty fields are AND-ed
// together (see risk/matcher.go).
type MatchConfig struct {
	PathRegex      string        `mapstructure:"path_regex"`
	PathPrefix     string        `mapstructure:"path_prefix"`
	ExtensionIn    []string      `mapstructure:"extension_in"`
	MethodIn       []string      `mapstructure:"method_in"`
	IPCIDRIn       []string      `mapstructure:"ip_cidr_in"`
	UserAgentRegex string        `mapstructure:"user_agent_regex"`
	PowStatus      string        `mapstructure:"pow_status"`
	PowStatusIn    []string      `mapstructure:"pow_status_in"`
	PowMode        string        `mapstructure:"pow_mode"`
	IsProtected    *bool         `mapstructure:"is_protected"`
	IsRangeRequest *bool         `mapstructure:"is_range_request"`
	Counter        *CounterMatch `mapstructure:"counter"`
	// RiskScoreGte is retained purely so validation can reject configs
	// that use it. Nothing populates a risk score, so a rule with this
	// field set would silently never match. See checkRiskControl.
	RiskScoreGte *int `mapstructure:"risk_score_gte"`
}

type CounterMatch struct {
	Name  string `mapstructure:"name"`
	Op    string `mapstructure:"op"` // >= | > | == | <= | <
	Value int64  `mapstructure:"value"`
}

type AdminConfig struct {
	Enabled    bool       `mapstructure:"enabled"`
	Listen     string     `mapstructure:"listen"`
	Auth       AuthConfig `mapstructure:"auth"`
	AllowCIDRs []string   `mapstructure:"allow_cidrs"`
	AuditLog   bool       `mapstructure:"audit_log"`
}

type AuthConfig struct {
	Type      string `mapstructure:"type"` // token | basic | none
	TokenFile string `mapstructure:"token_file"`
	Token     string `mapstructure:"token"`    // inline alternative to TokenFile
	Username  string `mapstructure:"username"` // for basic
	Password  string `mapstructure:"password"` // for basic
}

type LoggingConfig struct {
	Level     string `mapstructure:"level"`  // debug | info | warn | error
	Format    string `mapstructure:"format"` // json | console
	LogAccess bool   `mapstructure:"log_access"`
	LogDenied bool   `mapstructure:"log_denied"`
	HashIP    bool   `mapstructure:"hash_ip"`
	LogSalt   string `mapstructure:"log_salt"`
}

// Expired usage records are purged by a background loop.
type CleanupConfig struct {
	// Enabled is a pointer so that an omitted key is distinguishable from
	// an explicit "false". Omitting it defaults to on: interval and
	// expired_grace_period already default to sane values, and a config
	// that silently never reclaims usage records grows without bound.
	Enabled            *bool         `mapstructure:"enabled"`
	Interval           time.Duration `mapstructure:"interval"`
	ExpiredGracePeriod time.Duration `mapstructure:"expired_grace_period"`
}
