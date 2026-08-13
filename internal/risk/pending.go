package risk

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidBlockIP = errors.New("risk: invalid block IP")
	ErrInvalidBlock   = errors.New("risk: invalid block request")
	ErrBlockerClosed  = errors.New("risk: pending blocker is closed")
)

// PendingBlocker limits the number of concurrent protected requests from one
// IP. When an IP exceeds its pending limit, it is temporarily blocked.
type PendingBlocker interface {
	Enter(ip string) (release func(), blocked bool)
	Close() error
}

// ManualBlockChecker is the minimal capability used by the auth path. Manual
// operator blocks are checked before bypass_all and protection matching.
type ManualBlockChecker interface {
	ManuallyBlocked(ip string) bool
}

// IPBlockAdmin is the mutation capability exposed to the admin service.
type IPBlockAdmin interface {
	Block(ip string, input BlockInput) (BlockResult, error)
	Unblock(ip string) (BlockResult, error)
}

type BlockInput struct {
	TTL    time.Duration
	Reason string
	Actor  string
}

type BlockResult struct {
	Changed bool
	State   PendingSnapshot
}

type pendingEntry struct {
	pending int

	autoBlockedUntil time.Time
	autoCreatedAt    time.Time
	autoUpdatedAt    time.Time

	manualBlockedUntil time.Time
	manualReason       string
	manualActor        string
	manualCreatedAt    time.Time
	manualUpdatedAt    time.Time
}

// PendingSnapshot is a read-only view of one pending bucket. It is scoped to
// the current backend instance; it is not a cluster-wide block list.
type PendingSnapshot struct {
	IP           string    `json:"ip"`
	Pending      int       `json:"pending"`
	Blocked      bool      `json:"blocked"`
	BlockedUntil time.Time `json:"blocked_until,omitempty"`
	Source       string    `json:"source,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Actor        string    `json:"actor,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// IPPendingBlocker is an in-process pending-request limiter and manual IP
// denylist. It protects one backend instance; state is lost on restart and is
// not shared across replicas.
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

// CanonicalIP validates one IP address and normalises IPv4-mapped IPv6.
// CIDRs are intentionally rejected because the Phase 2 denylist is per-IP.
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

// Enter reserves one pending slot. Existing automatic or manual blocks reject
// the request without extending their TTL. Overflow starts a fixed automatic
// block; repeated rejected requests do not keep it alive indefinitely.
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
		if entry.autoCreatedAt.IsZero() {
			entry.autoCreatedAt = now
		}
		entry.autoUpdatedAt = now
		b.entries[canonical] = entry
		return func() {}, true
	}

	entry.pending++
	b.entries[canonical] = entry
	var once sync.Once
	return func() {
		once.Do(func() { b.release(canonical) })
	}, false
}

// ManuallyBlocked reports only the operator-managed denylist state. It is
// intentionally separate from automatic pending blocks so auth can enforce it
// before bypass_all without changing the existing automatic pending scope.
func (b *IPPendingBlocker) ManuallyBlocked(ip string) bool {
	if b == nil {
		return false
	}
	canonical, err := CanonicalIP(ip)
	if err != nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	now := b.now()
	b.sweepLocked(now)
	entry, ok := b.entries[canonical]
	if !ok {
		return false
	}
	b.expireEntryLocked(now, &entry)
	if entry.pending == 0 && !b.blockedAt(now, entry) {
		delete(b.entries, canonical)
		return false
	}
	b.entries[canonical] = entry
	return now.Before(entry.manualBlockedUntil)
}

func (b *IPPendingBlocker) Block(ip string, input BlockInput) (BlockResult, error) {
	canonical, err := CanonicalIP(ip)
	if err != nil {
		return BlockResult{}, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	input.Actor = strings.TrimSpace(input.Actor)
	if input.TTL <= 0 || input.Reason == "" || input.Actor == "" {
		return BlockResult{}, ErrInvalidBlock
	}
	if b == nil {
		return BlockResult{}, ErrBlockerClosed
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return BlockResult{}, ErrBlockerClosed
	}
	now := b.now()
	b.sweepLocked(now)
	entry := b.entries[canonical]
	b.expireEntryLocked(now, &entry)

	requestedUntil := now.Add(input.TTL)
	changed := entry.manualBlockedUntil.IsZero() || requestedUntil.After(entry.manualBlockedUntil) ||
		entry.manualReason != input.Reason || entry.manualActor != input.Actor
	if entry.manualCreatedAt.IsZero() {
		entry.manualCreatedAt = now
	}
	if requestedUntil.After(entry.manualBlockedUntil) {
		entry.manualBlockedUntil = requestedUntil
	}
	entry.manualReason = input.Reason
	entry.manualActor = input.Actor
	if changed {
		entry.manualUpdatedAt = now
	}
	b.entries[canonical] = entry
	return BlockResult{Changed: changed, State: b.snapshotLocked(canonical, entry, now)}, nil
}

// Unblock clears only the manual block. An unexpired automatic pending block
// remains effective and is reflected in the returned state.
func (b *IPPendingBlocker) Unblock(ip string) (BlockResult, error) {
	canonical, err := CanonicalIP(ip)
	if err != nil {
		return BlockResult{}, err
	}
	if b == nil {
		return BlockResult{}, ErrBlockerClosed
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return BlockResult{}, ErrBlockerClosed
	}
	now := b.now()
	b.sweepLocked(now)
	entry, ok := b.entries[canonical]
	if !ok {
		return BlockResult{State: PendingSnapshot{IP: canonical}}, nil
	}
	b.expireEntryLocked(now, &entry)
	changed := !entry.manualBlockedUntil.IsZero()
	entry.manualBlockedUntil = time.Time{}
	entry.manualReason = ""
	entry.manualActor = ""
	entry.manualCreatedAt = time.Time{}
	entry.manualUpdatedAt = time.Time{}
	state := b.snapshotLocked(canonical, entry, now)
	if entry.pending == 0 && !b.blockedAt(now, entry) {
		delete(b.entries, canonical)
	} else {
		b.entries[canonical] = entry
	}
	return BlockResult{Changed: changed, State: state}, nil
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
	return now.Before(entry.autoBlockedUntil) || now.Before(entry.manualBlockedUntil)
}

func (b *IPPendingBlocker) expireEntryLocked(now time.Time, entry *pendingEntry) {
	if !entry.autoBlockedUntil.IsZero() && !now.Before(entry.autoBlockedUntil) {
		entry.autoBlockedUntil = time.Time{}
		entry.autoCreatedAt = time.Time{}
		entry.autoUpdatedAt = time.Time{}
	}
	if !entry.manualBlockedUntil.IsZero() && !now.Before(entry.manualBlockedUntil) {
		entry.manualBlockedUntil = time.Time{}
		entry.manualReason = ""
		entry.manualActor = ""
		entry.manualCreatedAt = time.Time{}
		entry.manualUpdatedAt = time.Time{}
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
		b.expireEntryLocked(now, &entry)
		if entry.pending == 0 && !b.blockedAt(now, entry) {
			continue
		}
		b.entries[ip] = entry
		out = append(out, b.snapshotLocked(ip, entry, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func (b *IPPendingBlocker) snapshotLocked(ip string, entry pendingEntry, now time.Time) PendingSnapshot {
	auto := now.Before(entry.autoBlockedUntil)
	manual := now.Before(entry.manualBlockedUntil)
	item := PendingSnapshot{IP: ip, Pending: entry.pending, Blocked: auto || manual}

	switch {
	case auto && manual:
		item.Source = "automatic+manual"
		item.Reason = "pending_limit; " + entry.manualReason
		item.Actor = entry.manualActor
		item.BlockedUntil = maxTime(entry.autoBlockedUntil, entry.manualBlockedUntil)
		item.CreatedAt = minNonZeroTime(entry.autoCreatedAt, entry.manualCreatedAt)
		item.UpdatedAt = maxTime(entry.autoUpdatedAt, entry.manualUpdatedAt)
	case manual:
		item.Source = "manual"
		item.Reason = entry.manualReason
		item.Actor = entry.manualActor
		item.BlockedUntil = entry.manualBlockedUntil
		item.CreatedAt = entry.manualCreatedAt
		item.UpdatedAt = entry.manualUpdatedAt
	case auto:
		item.Source = "automatic"
		item.Reason = "pending_limit"
		item.Actor = "system"
		item.BlockedUntil = entry.autoBlockedUntil
		item.CreatedAt = entry.autoCreatedAt
		item.UpdatedAt = entry.autoUpdatedAt
	}
	return item
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minNonZeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
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

var (
	_ PendingBlocker     = (*IPPendingBlocker)(nil)
	_ ManualBlockChecker = (*IPPendingBlocker)(nil)
	_ IPBlockAdmin       = (*IPPendingBlocker)(nil)
)
