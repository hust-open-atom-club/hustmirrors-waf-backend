package risk

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidBlockIP = errors.New("risk: invalid block IP")
)

// PendingBlocker limits the number of concurrent protected requests from one
// IP. When an IP exceeds its pending limit, it is temporarily blocked.
type PendingBlocker interface {
	Enter(ip string) (release func(), blocked bool)
	Close() error
}

type pendingEntry struct {
	pending          int
	autoBlockedUntil time.Time
}

// IPPendingBlocker is an in-process pending-request limiter that protects one
// backend instance; state is lost on restart and is not shared across replicas.
type IPPendingBlocker struct {
	mu          sync.Mutex
	maxPerIP    int
	blockTTL    time.Duration
	entries     map[string]pendingEntry
	closed      bool
	now         func() time.Time
	lastSweep   time.Time
	onAutoBlock func()
}

const pendingSweepInterval = 30 * time.Second

// NewIPPendingBlocker creates the limiter. onAutoBlock, when provided, is
// invoked every time an overflow starts a new automatic block; callers pass a
// counter increment so this package stays free of metrics dependencies.
func NewIPPendingBlocker(maxPerIP int, blockTTL time.Duration, onAutoBlock ...func()) *IPPendingBlocker {
	if maxPerIP < 1 {
		maxPerIP = 1
	}
	if blockTTL <= 0 {
		blockTTL = time.Hour
	}
	b := &IPPendingBlocker{
		maxPerIP: maxPerIP,
		blockTTL: blockTTL,
		entries:  make(map[string]pendingEntry),
		now:      time.Now,
	}
	if len(onAutoBlock) > 0 {
		b.onAutoBlock = onAutoBlock[0]
	}
	return b
}

// CanonicalIP validates one IP address and normalises IPv4-mapped IPv6.
// CIDRs are rejected because the pending limit is applied per address.
func CanonicalIP(ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" || strings.Contains(ip, "/") {
		return "", ErrInvalidBlockIP
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", ErrInvalidBlockIP
	}
	return addr.Unmap().String(), nil
}

// Enter reserves one pending slot. An existing block rejects the request
// without extending its TTL. Overflow starts a fixed block; repeated rejected
// requests do not keep it alive indefinitely.
func (b *IPPendingBlocker) Enter(ip string) (func(), bool) {
	if b == nil {
		return func() {}, false
	}
	canonical, err := CanonicalIP(ip)
	if err != nil {
		return func() {}, false
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return func() {}, true
	}

	now := b.now()
	b.sweepLocked(now)
	entry := b.entries[canonical]
	b.expireEntryLocked(now, &entry)
	if b.blockedAt(now, entry) {
		b.entries[canonical] = entry
		return func() {}, true
	}
	if entry.pending >= b.maxPerIP {
		entry.autoBlockedUntil = now.Add(b.blockTTL)
		b.entries[canonical] = entry
		// The hook is a counter increment (atomic, non-blocking), so calling
		// it under the lock keeps the trigger and the count consistent.
		if b.onAutoBlock != nil {
			b.onAutoBlock()
		}
		return func() {}, true
	}

	entry.pending++
	b.entries[canonical] = entry
	var once sync.Once
	return func() {
		once.Do(func() { b.release(canonical) })
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
	now := b.now()
	b.expireEntryLocked(now, &entry)
	if entry.pending == 0 && !b.blockedAt(now, entry) {
		delete(b.entries, ip)
		return
	}
	b.entries[ip] = entry
}

func (b *IPPendingBlocker) blockedAt(now time.Time, entry pendingEntry) bool {
	return now.Before(entry.autoBlockedUntil)
}

func (b *IPPendingBlocker) expireEntryLocked(now time.Time, entry *pendingEntry) {
	if !entry.autoBlockedUntil.IsZero() && !now.Before(entry.autoBlockedUntil) {
		entry.autoBlockedUntil = time.Time{}
	}
}

func (b *IPPendingBlocker) sweepLocked(now time.Time) {
	if !b.lastSweep.IsZero() && now.Sub(b.lastSweep) < pendingSweepInterval {
		return
	}
	b.lastSweep = now
	for ip, entry := range b.entries {
		b.expireEntryLocked(now, &entry)
		if entry.pending == 0 && !b.blockedAt(now, entry) {
			delete(b.entries, ip)
			continue
		}
		b.entries[ip] = entry
	}
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
