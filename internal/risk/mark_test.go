package risk

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEngine_MARK_Accumulates verifies that MARK targets accumulate marks
// across rules and JUMPs, and the final Decision carries them.
func TestEngine_MARK_Accumulates(t *testing.T) {
	chains := ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: Policy{Target: TargetACCEPT, Reason: "default"},
			Rules: []Rule{
				{Name: "mark suspect", Match: matchAll{}, Target: TargetMARK, Mark: "suspect"},
				{Name: "mark abusive", Match: matchAll{}, Target: TargetMARK, Mark: "abusive"},
				{Name: "allow", Match: matchAll{}, Target: TargetACCEPT, Reason: "ok"},
			},
		},
	}
	e, err := NewEngine(chains)
	require.NoError(t, err)

	r, err := e.Evaluate(context.Background(), &RequestContext{Path: "/x.iso"})
	require.NoError(t, err)
	assert.Equal(t, TargetACCEPT, r.Decision.Target)
	assert.Equal(t, []string{"suspect", "abusive"}, r.Decision.Marks)
}

// TestEngine_MARK_SurvivesJump verifies marks survive a JUMP into a
// child chain and back.
func TestEngine_MARK_SurvivesJump(t *testing.T) {
	chains := ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: Policy{Target: TargetACCEPT, Reason: "default"},
			Rules: []Rule{
				{Name: "mark before jump", Match: matchAll{}, Target: TargetMARK, Mark: "before"},
				{Name: "jump", Match: matchAll{}, Target: TargetJUMP, Chain: "CHILD"},
			},
		},
		"CHILD": {
			Name:   "CHILD",
			Policy: Policy{Target: TargetACCEPT, Reason: "child_default"},
			Rules: []Rule{
				{Name: "mark in child", Match: matchAll{}, Target: TargetMARK, Mark: "in_child"},
				{Name: "accept in child", Match: matchAll{}, Target: TargetACCEPT, Reason: "child_ok"},
			},
		},
	}
	e, err := NewEngine(chains)
	require.NoError(t, err)

	r, err := e.Evaluate(context.Background(), &RequestContext{Path: "/x.iso"})
	require.NoError(t, err)
	assert.Equal(t, TargetACCEPT, r.Decision.Target)
	assert.Equal(t, "child_ok", r.Decision.Reason)
	assert.Equal(t, []string{"before", "in_child"}, r.Decision.Marks)
}

// TestEngine_MARK_NoMarkField verifies marks is empty when no MARK rule
// fires.
func TestEngine_MARK_NoMarkField(t *testing.T) {
	chains := ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: Policy{Target: TargetACCEPT, Reason: "default"},
			Rules: []Rule{
				{Name: "allow", Match: matchAll{}, Target: TargetACCEPT, Reason: "ok"},
			},
		},
	}
	e, err := NewEngine(chains)
	require.NoError(t, err)
	r, err := e.Evaluate(context.Background(), &RequestContext{Path: "/x.iso"})
	require.NoError(t, err)
	assert.Empty(t, r.Decision.Marks)
}
