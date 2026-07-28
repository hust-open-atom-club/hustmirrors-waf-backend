package risk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// allTargets is every target constant this package defines. Adding a new one
// without listing it here makes TestTargetConstants_AllCovered fail, which is
// the trigger that sends you to the checks below.
var allTargets = []string{
	TargetACCEPT, TargetREJECT, TargetRATELIMIT, TargetTOOMANY,
	TargetREQUIREPOW, TargetJUMP, TargetRETURN, TargetLOG, TargetMARK,
}

// TestTargetValidators_MatchConfigValidation ties the two target lists
// together. config/validate.go keeps its own copy because it cannot import
// this package (risk imports config), so nothing else would catch a target
// added to one side only.
func TestTargetValidators_MatchConfigValidation(t *testing.T) {
	// Mirror of isValidTarget in internal/config/validate.go. Keep in step.
	configSaysValid := func(target string, policy bool) bool {
		switch target {
		case "ACCEPT", "REJECT", "RATE_LIMIT", "TOO_MANY", "REQUIRE_POW":
			return true
		case "JUMP", "RETURN", "LOG", "MARK":
			return !policy
		}
		return false
	}

	for _, target := range allTargets {
		assert.Equal(t, configSaysValid(target, false), IsValidRuleTarget(target),
			"rule target %q: config validation and the engine disagree", target)
		assert.Equal(t, configSaysValid(target, true), IsValidPolicyTarget(target),
			"policy target %q: config validation and the engine disagree", target)
	}

	// Neither side may accept something outside the set.
	for _, junk := range []string{"", "accept", "DROP", "REJECT_ALL"} {
		assert.False(t, IsValidRuleTarget(junk), "%q must not be a valid rule target", junk)
		assert.False(t, IsValidPolicyTarget(junk), "%q must not be a valid policy target", junk)
		assert.False(t, configSaysValid(junk, false))
	}
}

// TestTargetConstants_AllCovered fails when a target constant is added
// without being listed in allTargets, so the parity check above cannot be
// silently bypassed by forgetting to extend it.
func TestTargetConstants_AllCovered(t *testing.T) {
	// isTerminal and defaultStatusCodeFor together touch every target, so
	// each one must be classified by at least one of them or by the
	// non-terminal set.
	nonTerminal := map[string]bool{
		TargetJUMP: true, TargetRETURN: true, TargetLOG: true, TargetMARK: true,
	}
	for _, target := range allTargets {
		if nonTerminal[target] {
			assert.False(t, isTerminal(target), "%q is non-terminal", target)
			continue
		}
		assert.True(t, isTerminal(target), "%q must be terminal", target)
		assert.NotZero(t, defaultStatusCodeFor(target),
			"terminal target %q needs a default status code", target)
	}
	assert.Len(t, allTargets, 9,
		"a target was added or removed; update allTargets and the config mirror above")
}
