package risk

import (
	"context"
	"sync"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/config"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/logging"
	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/storage"
)

// CounterRegistry bundles the runtime state needed to drive risk-engine
// counters: the definition (window, key, when) and the storage backend.
type CounterRegistry struct {
	defs   map[string]config.CounterConfig
	store  storage.CounterStore
	logger logging.Logger
}

// NewCounterRegistry binds a CounterStore to a set of counter definitions.
// store may be nil; in that case IncrementForRequest is a no-op.
func NewCounterRegistry(defs map[string]config.CounterConfig, store storage.CounterStore) *CounterRegistry {
	return &CounterRegistry{defs: defs, store: store, logger: logging.NewNop()}
}

// WithLogger attaches a logger so counter read failures become visible.
// Without one they are silent, and a rule like "counter >= N -> REJECT"
// stops rejecting the moment the backend is unreachable.
func (r *CounterRegistry) WithLogger(l logging.Logger) *CounterRegistry {
	if r == nil || l == nil {
		return r
	}
	r.logger = l
	return r
}

// IncrementForRequest increments every counter whose When predicate
// matches the given RequestContext. Failures are returned as a slice so
// the caller can decide whether to log-and-continue.
func (r *CounterRegistry) IncrementForRequest(ctx context.Context, req *RequestContext) []error {
	if r == nil || r.store == nil || req == nil {
		return nil
	}
	var errs []error
	for name, def := range r.defs {
		if !counterWhenMatches(def.When, req) {
			continue
		}
		key := counterKey(def.Key, req)
		if key == "" {
			continue
		}
		if _, _, err := r.store.Incr(ctx, name, key, def.Window); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// counterWhenMatches reports whether the counter's WhenConfig matches the
// request. Empty fields in when mean "any".
func counterWhenMatches(when config.CounterWhenConfig, req *RequestContext) bool {
	if when.IsProtected != nil && *when.IsProtected != req.IsProtected {
		return false
	}
	if when.IsRangeRequest != nil && *when.IsRangeRequest != req.IsRangeRequest {
		return false
	}
	if when.PowStatus != "" && when.PowStatus != req.PowStatus {
		return false
	}
	if when.PowMode != "" && when.PowMode != req.PowMode {
		return false
	}
	return true
}

// counterKey derives the per-counter key for a request based on the
// configured "key" field. Currently only "ip", "path", and "ip_path" are
// supported; unknown values are skipped.
func counterKey(keyField string, req *RequestContext) string {
	switch keyField {
	case "ip":
		return req.IP
	case "path":
		return req.Path
	case "ip_path":
		return req.IP + "|" + req.Path
	}
	return ""
}

// LookupResolver returns a CounterResolver that fetches the current value
// of any configured counter for the given request, caching the result for
// the lifetime of the resolver so multiple rules referencing the same
// counter do not multiply storage calls.
func (r *CounterRegistry) LookupResolver(ctx context.Context, req *RequestContext) CounterResolver {
	if r == nil || r.store == nil {
		return NoopCounterResolver
	}
	cache := make(map[string]int64, len(r.defs))
	return &cachingResolver{
		ctx:    ctx,
		req:    req,
		defs:   r.defs,
		store:  r.store,
		cache:  cache,
		logger: r.logger,
	}
}

type cachingResolver struct {
	ctx    context.Context
	req    *RequestContext
	defs   map[string]config.CounterConfig
	store  storage.CounterStore
	logger logging.Logger
	mu     sync.Mutex
	cache  map[string]int64
}

func (c *cachingResolver) Get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.cache[name]; ok {
		return v
	}
	def, ok := c.defs[name]
	if !ok {
		return 0
	}
	key := counterKey(def.Key, c.req)
	if key == "" {
		return 0
	}
	v, err := c.store.Get(c.ctx, name, key, def.Window)
	if err != nil {
		// Returning 0 keeps the request flowing, which is the right
		// trade-off: failing closed would reject all traffic whenever the
		// counter backend hiccups. But it means a rule such as
		// "counter >= N -> REJECT" silently stops rejecting, so the failure
		// must not be invisible. The storage decorator also counts this
		// under storage_operations_total{outcome="err"}.
		if c.logger != nil {
			c.logger.Warn(c.ctx, "counter read failed; treating as 0, rules keyed on it will not fire",
				logging.String("counter", name),
				logging.Err(err))
		}
		return 0
	}
	c.cache[name] = v
	return v
}

var _ CounterResolver = (*cachingResolver)(nil)
