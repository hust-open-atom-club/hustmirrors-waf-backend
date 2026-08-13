package risk

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// PendingBlocker limits the number of concurrent protected requests from one
// IP. When an IP exceeds its pending limit, it is temporarily blocked.
//
// Enter returns a release function for an accepted request. The release
// function is safe to call more than once. A nil/empty IP is intentionally not
// tracked because the caller cannot attribute it to a client reliably.
type PendingBlocker interface {
	Enter(ip string) (release func(), blocked bool)
	Close() error
}

type pendingEntry struct {
	pending      int
	blockedUntil time.Time
}

// PendingSnapshot is a read-only view of one pending bucket. It is scoped to
// the current backend instance; it is not a cluster-wide block list.
type PendingSnapshot struct {
	IP           string    `json:"ip"`
	Pending      int       `json:"pending"`
	Blocked      bool      `json:"blocked"`
	BlockedUntil time.Time `json:"blocked_until,omitempty"`
}

// IPPendingBlocker is an in-process pending-request limiter. It is intended
// to protect one backend instance; use a shared store if the block must span
// multiple replicas.
type IPPendingBlocker struct {
	mu        sync.Mutex
	maxPerIP  int
	blockTTL  time.Duration
	entries   map[string]pendingEntry
	closed    bool
	now       func() time.Time
	lastSweep time.Time
}

const pendingSweepInterval = 30 * time.Second

func NewIPPendingBlocker(maxPerIP int, blockTTL time.Duration) *IPPendingBlocker {
	if maxPerIP < 1 {
		maxPerIP = 1
	}
	if blockTTL <= 0 {
		blockTTL = time.Hour
	}
	return &IPPendingBlocker{
		maxPerIP: maxPerIP,
		blockTTL: blockTTL,
		entries:  make(map[string]pendingEntry),
		now:      time.Now,
	}
}

// Enter reserves one pending slot. When the IP is already blocked or has
// reached maxPerIP, the request is rejected and the block TTL starts (or is
// refreshed). A blocked request receives a nil release function.
func (b *IPPendingBlocker) Enter(ip string) (func(), bool) {
	if b == nil || ip == "" {
		return func() {}, false
	}
	if addr, err := netip.ParseAddr(ip); err == nil {
		ip = addr.Unmap().String()
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return func() {}, true
	}

	now := b.now()
	b.sweepLocked(now)
	entry := b.entries[ip]
	if !entry.blockedUntil.IsZero() {
		if now.Before(entry.blockedUntil) {
			return func() {}, true
		}
		entry.blockedUntil = time.Time{}
	}
	if entry.pending >= b.maxPerIP {
		entry.blockedUntil = now.Add(b.blockTTL)
		b.entries[ip] = entry
		return func() {}, true
	}

	entry.pending++
	b.entries[ip] = entry
	var once sync.Once
	return func() {
		once.Do(func() { b.release(ip) })
	}, false
}

func (b *IPPendingBlocker) release(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	entry, ok := b.entries[ip]
	if !ok {
		return
	}
	if entry.pending > 0 {
		entry.pending--
	}
	if entry.pending == 0 && !b.blockedAt(b.now(), entry) {
		delete(b.entries, ip)
		return
	}
	b.entries[ip] = entry
}

func (b *IPPendingBlocker) blockedAt(now time.Time, entry pendingEntry) bool {
	return !entry.blockedUntil.IsZero() && now.Before(entry.blockedUntil)
}

// sweepLocked bounds memory held by expired block records. Active requests are
// retained even when they have no block deadline.
func (b *IPPendingBlocker) sweepLocked(now time.Time) {
	if !b.lastSweep.IsZero() && now.Sub(b.lastSweep) < pendingSweepInterval {
		return
	}
	b.lastSweep = now
	for ip, entry := range b.entries {
		if entry.pending == 0 && !b.blockedAt(now, entry) {
			delete(b.entries, ip)
		}
	}
}

func (b *IPPendingBlocker) Snapshot() []PendingSnapshot {
	if b == nil {
		return []PendingSnapshot{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return []PendingSnapshot{}
	}
	now := b.now()
	b.sweepLocked(now)
	out := make([]PendingSnapshot, 0, len(b.entries))
	for ip, entry := range b.entries {
		blocked := b.blockedAt(now, entry)
		if entry.pending == 0 && !blocked {
			continue
		}
		item := PendingSnapshot{IP: ip, Pending: entry.pending, Blocked: blocked}
		if blocked {
			item.BlockedUntil = entry.blockedUntil
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func (b *IPPendingBlocker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	b.entries = nil
	return nil
}

var _ PendingBlocker = (*IPPendingBlocker)(nil)
