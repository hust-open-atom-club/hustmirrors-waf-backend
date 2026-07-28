package auth

// decideForAllow maps a risk-engine ACCEPT/RATE_LIMIT result into a
// decision string. Valid PoW → verified; otherwise the rate limit
// determines whether it's unverified_slow or unverified_very_slow.
// "0" / empty rate means full speed (metadata etc.) → verified.
func (s *Service) decideForAllow(res AuthResult) string {
	if res.Mode != "" && isVerifiedReason(res.Reason) {
		return DecisionVerified
	}
	if res.LimitRate != "" && res.LimitRate != "0" {
		if isVerySlowRate(res.LimitRate) {
			return DecisionUnverifiedVerySlow
		}
		return DecisionUnverifiedSlow
	}
	return DecisionVerified
}

func isVerifiedReason(reason string) bool {
	switch reason {
	case ReasonGenericValid, ReasonIPBoundValid, ReasonRequirePowPass, ReasonValidPowFullSpeed:
		return true
	}
	return false
}

// isVerySlowRate reports whether the rate limit is "very slow" (<=128k).
func isVerySlowRate(rate string) bool {
	n, unit, ok := parseRate(rate)
	if !ok {
		return false
	}
	bytesPerSec := n
	switch unit {
	case 'k', 'K':
		bytesPerSec = n * 1024
	case 'm', 'M':
		bytesPerSec = n * 1024 * 1024
	case 'g', 'G':
		bytesPerSec = n * 1024 * 1024 * 1024
	}
	return bytesPerSec <= 128*1024
}

// parseRate splits a rate string like "512k" into (512, 'k', true).
func parseRate(s string) (int, byte, bool) {
	if s == "" {
		return 0, 0, false
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, 0, false
	}
	n := 0
	for j := 0; j < i; j++ {
		n = n*10 + int(s[j]-'0')
	}
	var unit byte
	if i < len(s) {
		unit = s[i]
	}
	return n, unit, true
}

func powStatusToReason(status string) string {
	switch status {
	case "invalid":
		return ReasonSignMismatch
	case "expired":
		return ReasonExpired
	case "used_up":
		return ReasonUsedUp
	case "unverifiable":
		return ReasonMissingRealIP
	case "mode_disabled":
		return ReasonModeDisabled
	}
	return ReasonSignMismatch
}

func reasonForAccept(in string) string {
	if in == "" {
		return ReasonRiskAccept
	}
	return in
}

func statusBucket(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}
