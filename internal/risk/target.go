package risk

// Target constants. The string forms appear in the YAML config and in
// diagnostics.
const (
	TargetACCEPT     = "ACCEPT"
	TargetREJECT     = "REJECT"
	TargetRATELIMIT  = "RATE_LIMIT"
	TargetTOOMANY    = "TOO_MANY"
	TargetREQUIREPOW = "REQUIRE_POW"
	TargetJUMP       = "JUMP"
	TargetRETURN     = "RETURN"
	TargetLOG        = "LOG"
	TargetMARK       = "MARK"
)

// isTerminal reports whether target ends rule-chain evaluation.
func isTerminal(target string) bool {
	switch target {
	case TargetACCEPT, TargetREJECT, TargetRATELIMIT, TargetTOOMANY, TargetREQUIREPOW:
		return true
	}
	return false
}

// IsValidRuleTarget reports whether a rule may use this target. Exported
// because config validation needs the same answer.
func IsValidRuleTarget(t string) bool {
	switch t {
	case TargetACCEPT, TargetREJECT, TargetRATELIMIT, TargetTOOMANY,
		TargetREQUIREPOW, TargetJUMP, TargetRETURN, TargetLOG, TargetMARK:
		return true
	}
	return false
}

// IsValidPolicyTarget reports whether a chain policy may use this target.
// A policy is the fallthrough verdict, so it must be terminal.
func IsValidPolicyTarget(t string) bool {
	switch t {
	case TargetACCEPT, TargetREJECT, TargetRATELIMIT, TargetTOOMANY, TargetREQUIREPOW:
		return true
	}
	return false
}

func defaultStatusCodeFor(target string) int {
	switch target {
	case TargetACCEPT, TargetRATELIMIT:
		return 200
	case TargetREJECT, TargetREQUIREPOW:
		return 403
	case TargetTOOMANY:
		return 429
	}
	return 0
}
