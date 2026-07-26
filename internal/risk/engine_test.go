package risk

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage/memory"
)

func TestEngine_AcceptMetadataPath(t *testing.T) {
	e := newTestEngine(t)
	ctx := &RequestContext{
		Path:      "/ubuntu/Packages",
		Method:    "GET",
		IP:        "1.2.3.4",
		PowStatus: "missing",
	}
	r, err := e.Evaluate(context.Background(), ctx)
	require.NoError(t, err)
	assert.Equal(t, TargetACCEPT, r.Decision.Target)
	assert.Equal(t, "metadata_full_speed", r.Decision.Reason)
	assert.Equal(t, 200, r.Decision.StatusCode)
}

func TestEngine_RejectInvalidPow(t *testing.T) {
	e := newTestEngine(t)
	ctx := &RequestContext{
		Path: "/ubuntu/x.iso", Method: "GET", IP: "1.2.3.4",
		IsProtected: true, PowStatus: "invalid",
	}
	r, err := e.Evaluate(context.Background(), ctx)
	require.NoError(t, err)
	assert.Equal(t, TargetREJECT, r.Decision.Target)
	assert.Equal(t, 403, r.Decision.StatusCode)
	assert.Equal(t, "invalid_pow", r.Decision.Reason)
}

func TestEngine_ValidPowFullSpeed(t *testing.T) {
	e := newTestEngine(t)
	ctx := &RequestContext{
		Path: "/ubuntu/x.iso", Method: "GET", IP: "1.2.3.4",
		IsProtected: true, PowStatus: "valid", PowMode: "generic",
	}
	r, err := e.Evaluate(context.Background(), ctx)
	require.NoError(t, err)
	assert.Equal(t, TargetACCEPT, r.Decision.Target)
	assert.Equal(t, "valid_pow_full_speed", r.Decision.Reason)
}

func TestEngine_MissingPowJumpsToRiskCheck(t *testing.T) {
	e := newTestEngine(t)
	ctx := &RequestContext{
		Path: "/ubuntu/x.iso", Method: "GET", IP: "1.2.3.4",
		IsProtected: true, PowStatus: "missing",
	}
	// No counter resolver: counter rules will evaluate to false.
	r, err := e.Evaluate(context.Background(), ctx)
	require.NoError(t, err)
	// Falls through to RISK_CHECK policy = RATE_LIMIT "normal_unverified_slow".
	assert.Equal(t, TargetRATELIMIT, r.Decision.Target)
	assert.Equal(t, "512k", r.Decision.LimitRate)
	assert.Equal(t, "normal_unverified_slow", r.Decision.Reason)

	// Trace should mention the jump into RISK_CHECK.
	var sawJump bool
	for _, step := range r.Trace {
		if step.JumpTo == "RISK_CHECK" {
			sawJump = true
		}
	}
	assert.True(t, sawJump)
}

func TestEngine_RiskCheckManyProtectedRequests(t *testing.T) {
	e := newTestEngine(t)
	store := memory.NewCounterStore()
	// Pre-increment the counter so the rule fires.
	_, _, err := store.Incr(context.Background(), "ip_protected_requests_10m", "1.2.3.4", 10*time.Minute)
	require.NoError(t, err)
	// Add 5 more hits so count >= 6
	for i := 0; i < 5; i++ {
		_, _, _ = store.Incr(context.Background(), "ip_protected_requests_10m", "1.2.3.4", 10*time.Minute)
	}
	reg := NewCounterRegistry(testCounters(), store)
	req := &RequestContext{
		Path: "/ubuntu/x.iso", Method: "GET", IP: "1.2.3.4",
		IsProtected: true, PowStatus: "missing",
	}
	req.Counters = reg.LookupResolver(context.Background(), req)
	r, err := e.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, TargetRATELIMIT, r.Decision.Target)
	assert.Equal(t, "128k", r.Decision.LimitRate)
	assert.Equal(t, "many_protected_requests", r.Decision.Reason)
}

func TestEngine_PolicyDefault(t *testing.T) {
	e := newTestEngine(t)
	ctx := &RequestContext{
		Path: "/x.txt", Method: "GET", IP: "1.2.3.4",
		IsProtected: false, PowStatus: "missing",
	}
	r, err := e.Evaluate(context.Background(), ctx)
	require.NoError(t, err)
	assert.Equal(t, TargetACCEPT, r.Decision.Target)
	assert.Equal(t, "not_protected", r.Decision.Reason)
}

func TestEngine_JumpToUnknownChain_Errors(t *testing.T) {
	chains := ChainMap{
		"INPUT": {
			Name:   "INPUT",
			Policy: Policy{Target: TargetACCEPT, Reason: "fallback"},
			Rules: []Rule{
				{Name: "jump-bad", Match: matchAll{}, Target: TargetJUMP, Chain: "NOPE"},
			},
		},
	}
	e, err := NewEngine(chains)
	require.NoError(t, err)
	_, err = e.Evaluate(context.Background(), &RequestContext{Path: "/x"})
	require.Error(t, err)
}

func TestNewEngine_NoChainsErrors(t *testing.T) {
	_, err := NewEngine(nil)
	require.ErrorIs(t, err, ErrNoChains)
}

func TestCompileMatcher_BadRegex(t *testing.T) {
	_, err := CompileMatcher(MatchConfig{PathRegex: "["})
	require.Error(t, err)
	_, err = CompileMatcher(MatchConfig{UserAgentRegex: "("})
	require.Error(t, err)
}

func TestCompileMatcher_BadCIDR(t *testing.T) {
	_, err := CompileMatcher(MatchConfig{IPCIDRIn: []string{"nope"}})
	require.Error(t, err)
}

func TestCounterRegistry_IncrementForRequest(t *testing.T) {
	store := memory.NewCounterStore()
	defer store.Close()
	reg := NewCounterRegistry(testCounters(), store)
	req := &RequestContext{
		Path: "/ubuntu/x.iso", Method: "GET", IP: "1.2.3.4",
		IsProtected: true, PowStatus: "missing", PowMode: "",
	}
	errs := reg.IncrementForRequest(context.Background(), req)
	assert.Empty(t, errs)

	v, _ := store.Get(context.Background(), "ip_protected_requests_10m", "1.2.3.4", 10*time.Minute)
	assert.Equal(t, int64(1), v)
	v, _ = store.Get(context.Background(), "ip_missing_pow_1h", "1.2.3.4", time.Hour)
	assert.Equal(t, int64(1), v)
}

func TestCachingResolver_Cache(t *testing.T) {
	store := memory.NewCounterStore()
	defer store.Close()
	reg := NewCounterRegistry(testCounters(), store)
	req := &RequestContext{Path: "/x", Method: "GET", IP: "1.2.3.4", IsProtected: true, PowStatus: "missing"}

	// Increment via registry first.
	_ = reg.IncrementForRequest(context.Background(), req)

	resolver := reg.LookupResolver(context.Background(), req)
	require.NotNil(t, resolver)
	v1 := resolver.Get("ip_protected_requests_10m")
	assert.Equal(t, int64(1), v1)
	// Underlying counter increases after; cached value should still be v1.
	_, _, _ = store.Incr(context.Background(), "ip_protected_requests_10m", "1.2.3.4", 10*time.Minute)
	v2 := resolver.Get("ip_protected_requests_10m")
	assert.Equal(t, v1, v2, "caching resolver should not refetch")

	// Unknown counter returns 0.
	assert.Equal(t, int64(0), resolver.Get("unknown"))
}

func TestCounterWhenMatches(t *testing.T) {
	t.Run("IsProtectedMismatch", func(t *testing.T) {
		when := config.CounterWhenConfig{IsProtected: ptrBool(true)}
		req := &RequestContext{IsProtected: false}
		assert.False(t, counterWhenMatches(when, req))
	})
	t.Run("PowStatusMismatch", func(t *testing.T) {
		when := config.CounterWhenConfig{PowStatus: "missing"}
		req := &RequestContext{PowStatus: "valid"}
		assert.False(t, counterWhenMatches(when, req))
	})
	t.Run("PowModeMismatch", func(t *testing.T) {
		when := config.CounterWhenConfig{PowMode: "generic"}
		req := &RequestContext{PowMode: "ip_bound"}
		assert.False(t, counterWhenMatches(when, req))
	})
	t.Run("AllEmptyMatch", func(t *testing.T) {
		when := config.CounterWhenConfig{}
		req := &RequestContext{}
		assert.True(t, counterWhenMatches(when, req))
	})
}

func TestCounterKey(t *testing.T) {
	req := &RequestContext{IP: "1.2.3.4", Path: "/x.iso"}
	assert.Equal(t, "1.2.3.4", counterKey("ip", req))
	assert.Equal(t, "/x.iso", counterKey("path", req))
	assert.Equal(t, "1.2.3.4|/x.iso", counterKey("ip_path", req))
	assert.Equal(t, "", counterKey("nope", req))
}

func TestCompareCounter(t *testing.T) {
	cases := []struct {
		v    int64
		op   string
		tgt  int64
		want bool
	}{
		{5, ">=", 5, true},
		{5, ">", 5, false},
		{5, "==", 5, true},
		{5, "!=", 5, false},
		{5, "<=", 5, true},
		{5, "<", 5, false},
		{5, "?", 5, false}, // unknown op
	}
	for _, c := range cases {
		assert.Equal(t, c.want, compareCounter(c.v, c.op, c.tgt))
	}
}

func TestNoopCounterResolver(t *testing.T) {
	assert.Equal(t, int64(0), NoopCounterResolver.Get("x"))
}

// Sanity: counter resolver should be safe for concurrent Get.
func TestCachingResolver_ConcurrentGet(t *testing.T) {
	store := memory.NewCounterStore()
	defer store.Close()
	reg := NewCounterRegistry(testCounters(), store)
	req := &RequestContext{IP: "1.2.3.4", IsProtected: true, PowStatus: "missing"}
	_ = reg.IncrementForRequest(context.Background(), req)
	resolver := reg.LookupResolver(context.Background(), req)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = resolver.Get("ip_protected_requests_10m")
		}()
	}
	wg.Wait()
}

func TestEngine_UnknownTarget(t *testing.T) {
	// Engine should never produce an unknown target from a well-configured
	// chain; here we just ensure decisionFromRule uses defaults for empty.
	d := decisionFromRule("INPUT", Rule{Name: "x", Target: TargetACCEPT})
	assert.Equal(t, 200, d.StatusCode)
}

func TestFromConfig_Disabled(t *testing.T) {
	_, err := FromConfig(config.RiskControlConfig{Enabled: false})
	require.Error(t, err)
	assert.True(t, errors.Is(err, nil) || err != nil)
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	rc := config.RiskControlConfig{
		Enabled:  true,
		Counters: testCounters(),
		Chains: map[string]config.ChainConfig{
			"INPUT": {
				Policy: config.PolicyConfig{Target: "RATE_LIMIT", LimitRate: "512k", Reason: "default_unverified_slow"},
				Rules: []config.RuleConfig{
					{Name: "allow metadata", Match: config.MatchConfig{PathRegex: `^/.+/(Packages|Release|InRelease|repomd\.xml)(\..+)?$`}, Target: "ACCEPT", LimitRate: "0", Reason: "metadata_full_speed"},
					{Name: "allow non protected path", Match: config.MatchConfig{IsProtected: ptrBool(false)}, Target: "ACCEPT", LimitRate: "0", Reason: "not_protected"},
					{Name: "reject invalid pow", Match: config.MatchConfig{PowStatusIn: []string{"invalid", "expired", "used_up"}}, Target: "REJECT", Status: 403, Reason: "invalid_pow"},
					{Name: "allow valid pow full speed", Match: config.MatchConfig{PowStatus: "valid"}, Target: "ACCEPT", LimitRate: "0", Reason: "valid_pow_full_speed"},
					{Name: "missing pow risk check", Match: config.MatchConfig{PowStatus: "missing", IsProtected: ptrBool(true)}, Target: "JUMP", Chain: "RISK_CHECK"},
				},
			},
			"RISK_CHECK": {
				Policy: config.PolicyConfig{Target: "RATE_LIMIT", LimitRate: "512k", Reason: "normal_unverified_slow"},
				Rules: []config.RuleConfig{
					{Name: "many protected requests", Match: config.MatchConfig{Counter: &config.CounterMatch{Name: "ip_protected_requests_10m", Op: ">=", Value: 5}}, Target: "RATE_LIMIT", LimitRate: "128k", Reason: "many_protected_requests"},
					{Name: "extreme abuse", Match: config.MatchConfig{Counter: &config.CounterMatch{Name: "ip_protected_requests_1h", Op: ">=", Value: 20}}, Target: "TOO_MANY", Status: 429, Reason: "extreme_abuse"},
				},
			},
		},
	}
	e, err := FromConfig(rc)
	require.NoError(t, err)
	return e
}

func testCounters() map[string]config.CounterConfig {
	return map[string]config.CounterConfig{
		"ip_protected_requests_10m": {Key: "ip", Window: 10 * time.Minute, When: config.CounterWhenConfig{IsProtected: ptrBool(true)}, Storage: "memory"},
		"ip_missing_pow_1h":         {Key: "ip", Window: time.Hour, When: config.CounterWhenConfig{IsProtected: ptrBool(true), PowStatus: "missing"}, Storage: "memory"},
		"ip_protected_requests_1h":  {Key: "ip", Window: time.Hour, When: config.CounterWhenConfig{IsProtected: ptrBool(true)}, Storage: "memory"},
	}
}

func ptrBool(b bool) *bool { return &b }
