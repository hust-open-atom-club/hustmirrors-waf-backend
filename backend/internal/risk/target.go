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

func isValidRuleTarget(t string) bool {
	switch t {
	case TargetACCEPT, TargetREJECT, TargetRATELIMIT, TargetTOOMANY,
		TargetREQUIREPOW, TargetJUMP, TargetRETURN, TargetLOG, TargetMARK:
		return true
	}
	return false
}

// isValidPolicyTarget reports whether a string is a valid chain policy
// target. Policy may not be JUMP/RETURN/LOG/MARK.
func isValidPolicyTarget(t string) bool {
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
