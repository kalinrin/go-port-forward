package forward

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"go-port-forward/internal/models"
)

const (
	// hashVnodesPerWeight is the number of consistent-hash virtual nodes per
	// unit of backend weight (nginx-compatible: 160).
	hashVnodesPerWeight = 160

	// maxRingPoints caps the total number of virtual nodes so extreme
	// weights cannot blow up memory; relative proportions are preserved.
	maxRingPoints = 1 << 16
)

// fnv1a64 constants (64-bit FNV-1a).
const (
	fnvOffset64 uint64 = 14695981039346656037
	fnvPrime64  uint64 = 1099511628211
)

// backendStats holds per-backend runtime counters. The stats object is
// stable for the lifetime of the group, so connections captured before a
// configuration hot-reload keep counting after it.
type backendStats struct {
	activeConns atomic.Int64
	totalConns  atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
}

// backend is one schedulable upstream server.
type backend struct {
	key    string // "host:port"
	addr   string
	port   int
	weight int
	stats  *backendStats
}

// ringPoint is one virtual node on the consistent-hash ring.
type ringPoint struct {
	hash uint64
	b    *backend
}

// groupBalancer schedules connections across the backends of one upstream
// group. All rules referencing the same group share a single instance, so
// the round-robin position, connection counts and traffic stats are
// group-global (a backend is one pool, not one pool per rule).
//
// Scheduling policies:
//   - wrr        smooth weighted round robin (nginx-style)
//   - least_conn weighted least connections (conns/weight, round-robin on ties)
//   - ip_hash    consistent hash of the client source IP (ketama-style ring)
type groupBalancer struct {
	mu       sync.Mutex
	policy   models.LBPolicy
	backends []*backend

	// statsByKey preserves per-backend counters across hot reloads.
	statsByKey map[string]*backendStats

	// smooth WRR state (wrr)
	wrrCurrent  []int64
	totalWeight int64

	// least_conn tie rotation
	lcRR int

	// consistent hash ring (ip_hash), sorted by hash
	ring []ringPoint
}

// newGroupBalancer builds a balancer for an upstream group.
func newGroupBalancer(u *models.Upstream) *groupBalancer {
	b := &groupBalancer{statsByKey: make(map[string]*backendStats)}
	b.rebuild(u)
	return b
}

// rebuild replaces the backend list and policy, preserving per-backend
// stats for backends whose addr:port is unchanged. Rules referencing the
// group are not restarted and live connections are not dropped; they keep
// counting through their captured *backendStats pointers.
func (b *groupBalancer) rebuild(u *models.Upstream) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.policy = models.NormalizeLBPolicy(u.Policy)
	backends := make([]*backend, 0, len(u.Servers))
	for _, s := range u.Servers {
		key := fmt.Sprintf("%s:%d", s.Addr, s.Port)
		stats, ok := b.statsByKey[key]
		if !ok {
			stats = &backendStats{}
			b.statsByKey[key] = stats
		}
		backends = append(backends, &backend{key: key, addr: s.Addr, port: s.Port, weight: s.Weight, stats: stats})
	}
	b.backends = backends
	b.resetSchedulerLocked()
}

// resetSchedulerLocked resets all policy-specific scheduling state after the
// backend list changed.
func (b *groupBalancer) resetSchedulerLocked() {
	b.wrrCurrent = make([]int64, len(b.backends))
	b.totalWeight = 0
	for _, be := range b.backends {
		if be.weight > 0 {
			b.totalWeight += int64(be.weight)
		}
	}
	b.lcRR = 0
	b.ring = b.buildRingLocked()
}

// pick selects a backend for a new connection/session originating from
// clientIP. It returns nil when no backend is eligible (all weights are 0);
// callers drop the connection in that case.
func (b *groupBalancer) pick(clientIP net.IP) *backend {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.policy {
	case models.LBLeastConn:
		return b.pickLeastConnLocked()
	case models.LBIPHash:
		return b.pickHashLocked(clientIP)
	default:
		return b.pickWRRLocked()
	}
}

// pickWRRLocked is nginx-style smooth weighted round robin: every pick adds
// each backend's weight to its current score, selects the highest score and
// subtracts the total weight from it. This spreads high-weight backends
// evenly instead of bursting them consecutively.
func (b *groupBalancer) pickWRRLocked() *backend {
	if b.totalWeight == 0 {
		return nil
	}
	var best *backend
	bestIdx := -1
	for i, be := range b.backends {
		if be.weight <= 0 {
			continue
		}
		b.wrrCurrent[i] += int64(be.weight)
		if best == nil || b.wrrCurrent[i] > b.wrrCurrent[bestIdx] {
			best = be
			bestIdx = i
		}
	}
	if best == nil {
		return nil
	}
	b.wrrCurrent[bestIdx] -= b.totalWeight
	return best
}

// pickLeastConnLocked is weighted least connections: the backend with the
// lowest active-connections-to-weight ratio wins; equally-scored backends
// are rotated round-robin. Equal mathematical ratios compare equal in
// IEEE-754 (correctly rounded division of exact operands), so the tie set
// is exact.
func (b *groupBalancer) pickLeastConnLocked() *backend {
	var tied []*backend
	var bestScore float64
	for _, be := range b.backends {
		if be.weight <= 0 {
			continue
		}
		score := float64(be.stats.activeConns.Load()) / float64(be.weight)
		if len(tied) == 0 || score < bestScore {
			tied = append(tied[:0], be)
			bestScore = score
			continue
		}
		if score == bestScore {
			tied = append(tied, be)
		}
	}
	switch len(tied) {
	case 0:
		return nil
	case 1:
		return tied[0]
	default:
		idx := b.lcRR % len(tied)
		b.lcRR++
		return tied[idx]
	}
}

// pickHashLocked maps a client source IP onto the consistent-hash ring.
// Only the IP is hashed (never the port), so every connection from one
// client lands on the same backend.
func (b *groupBalancer) pickHashLocked(clientIP net.IP) *backend {
	if len(b.ring) == 0 {
		return nil
	}
	h := sourceIPHash(clientIP)
	i := sort.Search(len(b.ring), func(i int) bool { return b.ring[i].hash >= h })
	if i == len(b.ring) {
		i = 0 // wrap around to the first vnode
	}
	return b.ring[i].b
}

// buildRingLocked builds the sorted virtual-node ring for ip_hash. Each
// backend gets weight*160 vnodes (nginx-compatible), scaled down
// proportionally when the total would exceed maxRingPoints.
func (b *groupBalancer) buildRingLocked() []ringPoint {
	if b.policy != models.LBIPHash {
		return nil
	}
	var totalWeight int64
	for _, be := range b.backends {
		if be.weight > 0 {
			totalWeight += int64(be.weight)
		}
	}
	if totalWeight == 0 {
		return nil
	}
	scale := 1.0
	if total := totalWeight * hashVnodesPerWeight; total > maxRingPoints {
		scale = float64(maxRingPoints) / float64(total)
	}
	ring := make([]ringPoint, 0, int(float64(totalWeight)*float64(hashVnodesPerWeight)*scale)+1)
	for _, be := range b.backends {
		if be.weight <= 0 {
			continue
		}
		points := int(float64(be.weight) * hashVnodesPerWeight * scale)
		if points < 1 {
			points = 1
		}
		for i := 0; i < points; i++ {
			ring = append(ring, ringPoint{
				hash: vnodeHash(be.key, i),
				b:    be,
			})
		}
	}
	sort.Slice(ring, func(i, j int) bool { return ring[i].hash < ring[j].hash })
	return ring
}

// stats snapshots per-backend runtime counters in server-list order.
func (b *groupBalancer) stats() []models.UpstreamServerStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]models.UpstreamServerStats, 0, len(b.backends))
	for _, be := range b.backends {
		out = append(out, models.UpstreamServerStats{
			Addr:        be.addr,
			Port:        be.port,
			Weight:      be.weight,
			ActiveConns: be.stats.activeConns.Load(),
			TotalConns:  be.stats.totalConns.Load(),
			BytesIn:     be.stats.bytesIn.Load(),
			BytesOut:    be.stats.bytesOut.Load(),
		})
	}
	return out
}

// --- connection accounting (lock-free: stats objects are stable) ---

// connOpened records a new connection/session on a backend.
func (b *groupBalancer) connOpened(be *backend) {
	be.stats.activeConns.Add(1)
	be.stats.totalConns.Add(1)
}

// connClosed records a closed connection/session on a backend.
func (b *groupBalancer) connClosed(be *backend) {
	be.stats.activeConns.Add(-1)
}

// addBytesIn accumulates client→backend traffic on a backend.
func (b *groupBalancer) addBytesIn(be *backend, n int64) {
	if n > 0 {
		be.stats.bytesIn.Add(n)
	}
}

// addBytesOut accumulates backend→client traffic on a backend.
func (b *groupBalancer) addBytesOut(be *backend, n int64) {
	if n > 0 {
		be.stats.bytesOut.Add(n)
	}
}

// --- hashing helpers ---

// sourceIPHash hashes a client source IP into the ring key space. IPv4 and
// IPv6 forms hash consistently (To4/To16 normalization).
//
// The FNV-1a output must pass through fmix64: raw FNV-1a has poor avalanche,
// so inputs that share a prefix and differ only in low bits (e.g. every
// client of one /24) hash to nearly identical values, cluster onto a tiny
// arc of the ring and all land on the same backend.
func sourceIPHash(ip net.IP) uint64 {
	if ip == nil {
		return fmix64(fnvOffset64)
	}
	if v4 := ip.To4(); v4 != nil {
		return fmix64(fnv1a64(v4))
	}
	if v16 := ip.To16(); v16 != nil {
		return fmix64(fnv1a64(v16))
	}
	return fmix64(fnv1a64String(ip.String()))
}

// vnodeHash hashes one virtual-node key. fmix64 is applied for the same
// avalanche reason: adjacent vnode indices differ only in trailing digits,
// which raw FNV-1a leaves clustered on the ring.
func vnodeHash(key string, idx int) uint64 {
	return fmix64(fnv1a64String(key + "#" + strconv.Itoa(idx)))
}

// fmix64 is the murmur3 64-bit finalizer: three xor-shift/multiply rounds
// that avalanche all input bits so nearby inputs map far apart.
func fmix64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// fnv1a64String computes the 64-bit FNV-1a hash of s.
func fnv1a64String(s string) uint64 {
	h := fnvOffset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= fnvPrime64
	}
	return h
}

// fnv1a64 computes the 64-bit FNV-1a hash of b.
func fnv1a64(b []byte) uint64 {
	h := fnvOffset64
	for _, x := range b {
		h ^= uint64(x)
		h *= fnvPrime64
	}
	return h
}
