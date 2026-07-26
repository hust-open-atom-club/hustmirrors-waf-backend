package pow

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// JSON tags use short field names to match the wire format exactly.
type TokenPayload struct {
	Version    int    `json:"v"`
	Mode       string `json:"mode"`
	Algorithm  string `json:"alg"`
	IP         string `json:"ip,omitempty"`
	Path       string `json:"path"`
	Timestamp  int64  `json:"ts"`
	ExpiresAt  int64  `json:"exp"`
	Difficulty int    `json:"d"`
	Counter    string `json:"cnt"`
	Salt       string `json:"salt,omitempty"`
}

func DecodeToken(raw string) (*TokenPayload, error) {
	if raw == "" {
		return nil, ErrEmpty
	}
	bytes, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		// Fall back to padded base64url for backwards compat.
		bytes, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: base64: %v", ErrMalformed, err)
		}
	}
	var p TokenPayload
	if err := json.Unmarshal(bytes, &p); err != nil {
		return nil, fmt.Errorf("%w: json: %v", ErrMalformed, err)
	}
	return &p, nil
}

func EncodeToken(p *TokenPayload) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var (
	ErrEmpty                = errors.New("token empty")
	ErrMalformed            = errors.New("token malformed")
	ErrUnsupportedVersion   = errors.New("token version unsupported")
	ErrUnsupportedMode      = errors.New("token mode unsupported")
	ErrUnsupportedAlgorithm = errors.New("token algorithm unsupported")
	ErrPathInvalid          = errors.New("token path invalid")
	ErrPathTooLong          = errors.New("token path too long")
	ErrIPMissing            = errors.New("token ip missing")
	ErrIPInvalid            = errors.New("token ip invalid")
	ErrIPForbidden          = errors.New("token ip must be empty in generic mode")
	ErrCounterInvalid       = errors.New("token cnt invalid")
	ErrDifficultyInvalid    = errors.New("token difficulty invalid")
	ErrTimestampInvalid     = errors.New("token ts invalid")
	ErrExpiryInvalid        = errors.New("token exp invalid")
	ErrSaltInvalid          = errors.New("token salt invalid")
)

const (
	MaxPathLength    = 4096
	MaxCounterLength = 64
	MaxDifficulty    = 64
	Version1         = 1
)

type ValidatorOptions struct {
	AllowedSalts   []string
	AllowEmptySalt bool
	AllowedModes   []string // typically ["ip_bound","generic"]; first enabled mode wins
	RequireIP      bool     // when ip_bound is enabled, require IP
	MinDifficulty  int
	MaxDifficulty  int
}

// ValidatePayload runs field-level validation but does not check time/expiry;
// those depend on the current time and per-mode max TTL, enforced separately
// by the auth service.
func ValidatePayload(p *TokenPayload, opts *ValidatorOptions) error {
	if p == nil {
		return ErrMalformed
	}
	if p.Version != Version1 {
		return ErrUnsupportedVersion
	}

	modeOK := p.Mode == "ip_bound" || p.Mode == "generic"
	if opts != nil && len(opts.AllowedModes) > 0 {
		modeOK = false
		for _, m := range opts.AllowedModes {
			if p.Mode == m {
				modeOK = true
				break
			}
		}
	}
	if !modeOK {
		return ErrUnsupportedMode
	}

	if p.Algorithm == "" {
		return ErrUnsupportedAlgorithm
	}
	if !strings.EqualFold(p.Algorithm, "sha256") {
		return ErrUnsupportedAlgorithm
	}

	if p.Path == "" || !strings.HasPrefix(p.Path, "/") {
		return ErrPathInvalid
	}
	if len(p.Path) > MaxPathLength {
		return ErrPathTooLong
	}
	// path is interpolated into the canonical signing input, so a newline
	// here would let the token declare extra fields. See isCanonicalSafe.
	if !isCanonicalSafe(p.Path) {
		return ErrPathInvalid
	}

	switch p.Mode {
	case "ip_bound":
		if p.IP == "" {
			if opts != nil && opts.RequireIP {
				return ErrIPMissing
			}
		} else if !isValidIPString(p.IP) {
			return ErrIPInvalid
		}
	case "generic":
		if p.IP != "" {
			return ErrIPForbidden
		}
	}

	if p.Counter == "" || len(p.Counter) > MaxCounterLength {
		return ErrCounterInvalid
	}
	if !isCounterSafe(p.Counter) {
		return ErrCounterInvalid
	}

	minD, maxD := 0, MaxDifficulty
	if opts != nil {
		if opts.MinDifficulty > 0 {
			minD = opts.MinDifficulty
		}
		if opts.MaxDifficulty > 0 {
			maxD = opts.MaxDifficulty
		}
	}
	if p.Difficulty < minD || p.Difficulty > maxD {
		return ErrDifficultyInvalid
	}

	if opts != nil {
		if p.Salt == "" {
			if !opts.AllowEmptySalt {
				return ErrSaltInvalid
			}
		} else {
			// Same canonical-injection concern as path. Salts come from
			// config so this should never fire, but the check costs
			// nothing and keeps the invariant local to the validator.
			if !isCanonicalSafe(p.Salt) {
				return ErrSaltInvalid
			}
			ok := false
			for _, s := range opts.AllowedSalts {
				if s == p.Salt {
					ok = true
					break
				}
			}
			if !ok {
				return ErrSaltInvalid
			}
		}
	}

	if p.Timestamp <= 0 {
		return ErrTimestampInvalid
	}
	if p.ExpiresAt <= 0 {
		return ErrExpiryInvalid
	}
	if p.ExpiresAt <= p.Timestamp {
		return ErrExpiryInvalid
	}

	return nil
}
