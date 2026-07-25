package auth

// Decision constants emitted in the X-Pow-Decision response header.
const (
	DecisionVerified         = "verified"
	DecisionUnverifiedSlow   = "unverified_slow"
	DecisionUnverifiedVerySlow = "unverified_very_slow"
	DecisionNotProtected     = "not_protected"
	DecisionDenied          = "denied"
	DecisionBypass          = "bypass"
	// DecisionDryRun: dry-run mode rewrote a deny to an allow.
	DecisionDryRun          = "dry_run"
)

// Reason constants. These appear in the X-Pow-Reason / X-Pow-Error headers
// and in the structured log line.
const (
	ReasonNotProtected     = "not_protected"
	ReasonIPBoundValid     = "ip_bound_valid"
	ReasonGenericValid     = "generic_valid"
	ReasonDryRunAllow      = "dry_run_allow"
	ReasonBypassAll        = "bypass_all"
	ReasonRiskAccept       = "risk_accept"
	ReasonRiskRateLimit    = "risk_rate_limit"
	ReasonRequirePowPass   = "require_pow_pass"
	ReasonValidPowFullSpeed = "valid_pow_full_speed"

	ReasonMissingHeaders       = "missing_headers"
	ReasonInvalidOriginalURI   = "invalid_original_uri"
	ReasonMissingTokenOrSign   = "missing_token_or_sign"
	ReasonTokenTooLong         = "token_too_long"
	ReasonSignTooLong          = "sign_too_long"
	ReasonMalformedToken       = "malformed_token"
	ReasonUnsupportedVersion   = "unsupported_version"
	ReasonUnsupportedMode      = "unsupported_mode"
	ReasonModeDisabled         = "mode_disabled"
	ReasonUnsupportedAlgorithm = "unsupported_algorithm"
	ReasonPathMismatch         = "path_mismatch"
	ReasonExpired              = "expired"
	ReasonTTLTooLong           = "ttl_too_long"
	ReasonTimestampFromFuture  = "timestamp_from_future"
	ReasonDifficultyTooLow     = "difficulty_too_low"
	ReasonDifficultyTooHigh    = "difficulty_too_high"
	ReasonInvalidCounter       = "invalid_counter"
	ReasonInvalidSalt          = "invalid_salt"
	ReasonInvalidIP            = "invalid_ip"
	ReasonIPForbidden          = "ip_forbidden"
	ReasonIPMissing            = "ip_missing"
	ReasonInvalidSignFormat    = "invalid_sign_format"
	ReasonSignMismatch         = "sign_mismatch"
	ReasonDifficultyNotMet     = "difficulty_not_met"
	ReasonIPMismatch           = "ip_mismatch"
	ReasonUsedUp               = "used_up"
	ReasonRateLimited          = "rate_limited"
	ReasonRiskReject           = "risk_reject"
	ReasonRiskTooMany          = "risk_too_many"
	ReasonStorageError         = "storage_error"
	ReasonInternalError        = "internal_error"
)

// statusForReason returns the canonical HTTP status for a deny reason.
// Allow reasons return 200; transient/system errors return 500.
func statusForReason(reason string) int {
	switch reason {
	case ReasonNotProtected, ReasonIPBoundValid, ReasonGenericValid,
		ReasonDryRunAllow, ReasonBypassAll,
		ReasonRiskAccept, ReasonRiskRateLimit, ReasonRequirePowPass:
		return 200
	case ReasonRateLimited, ReasonRiskTooMany:
		return 429
	case ReasonStorageError, ReasonInternalError, ReasonMissingHeaders:
		return 500
	}
	return 403
}
