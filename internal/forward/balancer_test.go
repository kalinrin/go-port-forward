package forward

import (
	"fmt"
	"net"
	"testing"

	"go-port-forward/internal/models"
)

func testUpstream(policy models.LBPolicy, servers ...models.UpstreamServer) *models.Upstream {
	return &models.Upstream{
		ID:      "group-1",
		Name:    "test-group",
		Policy:  policy,
		Servers: servers,
	}
}

func server(addr string, port, weight int) models.UpstreamServer {
	return models.UpstreamServer{Addr: addr, Port: port, Weight: weight}
}

// TestSmoothWRRMatchesWeights verifies that smooth weighted round robin
// distributes picks proportionally to weights and stays smooth: after any
// prefix of n picks, every backend's count stays within one expected share
// (integer form: |count*W - n*w| < W). That is the defining property of
// nginx-style smooth WRR — it rejects the naive burst schedule
// (a a a a a b c) while allowing the wrap-around runs the algorithm
// legitimately produces: for 5/1/1 the cycle is "a a b a c a a", so cycle
// boundaries yield ... c a a | a a b ... = four consecutive a's, exactly
// like nginx. A "max 2 in a row" assertion would be wrong.
func TestSmoothWRRMatchesWeights(t *testing.T) {
	const (
		totalWeight = 7
		picks       = 70 // 10 full cycles
	)
	weights := map[string]int{
		"10.0.0.1:80": 5,
		"10.0.0.2:80": 1,
		"10.0.0.3:80": 1,
	}
	bal := newGroupBalancer(testUpstream(models.LBWRR,
		server("10.0.0.1", 80, 5),
		server("10.0.0.2", 80, 1),
		server("10.0.0.3", 80, 1),
	))

	counts := map[string]int{}
	order := make([]string, 0, picks)
	for i := 0; i < picks; i++ {
		be := bal.pick(nil)
		if be == nil {
			t.Fatalf("pick %d returned nil", i)
		}
		counts[be.key]++
		order = append(order, be.key)
	}

	// Exact proportional distribution over full cycles.
	for key, w := range weights {
		if want := picks * w / totalWeight; counts[key] != want {
			t.Fatalf("backend %s got %d picks, want %d", key, counts[key], want)
		}
	}

	// Smoothness: the running count never deviates from the expected share
	// by a full pick. (Naive WRR violates this: at n=4 it already reaches
	// |4*7 - 4*5| = 8 >= 7.)
	prefix := make(map[string]int, len(weights))
	for n, key := range order {
		prefix[key]++
		for bk, w := range weights {
			if diff := prefix[bk]*totalWeight - (n+1)*w; diff >= totalWeight || diff <= -totalWeight {
				t.Fatalf("prefix n=%d: backend %s count*W-n*w=%d, must stay within (-%d, %d)",
					n+1, bk, diff, totalWeight, totalWeight)
			}
		}
	}
}

// TestWRRWeightZeroExcluded verifies weight-0 backends never receive picks
// and that an all-zero group yields no backend at all.
func TestWRRWeightZeroExcluded(t *testing.T) {
	bal := newGroupBalancer(testUpstream(models.LBWRR,
		server("10.0.0.1", 80, 0),
		server("10.0.0.2", 80, 3),
	))
	for i := 0; i < 100; i++ {
		be := bal.pick(nil)
		if be == nil {
			t.Fatalf("pick %d returned nil", i)
		}
		if be.key == "10.0.0.1:80" {
			t.Fatalf("weight-0 backend was scheduled")
		}
	}

	allZero := newGroupBalancer(testUpstream(models.LBWRR,
		server("10.0.0.1", 80, 0),
		server("10.0.0.2", 80, 0),
	))
	if be := allZero.pick(nil); be != nil {
		t.Fatalf("all-zero group should yield nil, got %s", be.key)
	}
}

// TestLeastConnPrefersWeightedMinimum verifies the conns/weight scoring and
// round-robin tie-breaking.
func TestLeastConnPrefersWeightedMinimum(t *testing.T) {
	bal := newGroupBalancer(testUpstream(models.LBLeastConn,
		server("10.0.0.1", 80, 1),
		server("10.0.0.2", 80, 2),
	))
	a := bal.backends[0]
	b := bal.backends[1]

	// A: 4 conns / weight 1 = 4; B: 2 conns / weight 2 = 1 → B wins.
	a.stats.activeConns.Store(4)
	b.stats.activeConns.Store(2)
	if be := bal.pick(nil); be != b {
		t.Fatalf("expected weighted-minimum backend B, got %s", be.key)
	}

	// A: 2/1 = 2; B: 4/2 = 2 → tie → round-robin rotation.
	a.stats.activeConns.Store(2)
	b.stats.activeConns.Store(4)
	first := bal.pick(nil)
	second := bal.pick(nil)
	if first == second {
		t.Fatalf("tied backends should rotate, got %s twice", first.key)
	}

	// A: 3/1 = 3; B: 4/2 = 2 → B wins despite more raw connections.
	a.stats.activeConns.Store(3)
	b.stats.activeConns.Store(4)
	if be := bal.pick(nil); be != b {
		t.Fatalf("expected B (score 2 < 3), got %s", be.key)
	}
}

// TestIPHashStablePerSourceIP verifies the same source IP always maps to the
// same backend.
func TestIPHashStablePerSourceIP(t *testing.T) {
	bal := newGroupBalancer(testUpstream(models.LBIPHash,
		server("10.0.0.1", 80, 1),
		server("10.0.0.2", 80, 1),
		server("10.0.0.3", 80, 1),
	))
	ip := net.ParseIP("192.168.7.42")
	first := bal.pick(ip)
	for i := 0; i < 50; i++ {
		if be := bal.pick(ip); be != first {
			t.Fatalf("source IP remapped between picks: %s → %s", first.key, be.key)
		}
	}
}

// TestIPHashMinimalRemapOnRemoval verifies the consistent-hash property:
// removing one backend only remaps the clients that were mapped to it.
func TestIPHashMinimalRemapOnRemoval(t *testing.T) {
	servers := []models.UpstreamServer{
		server("10.0.0.1", 80, 1),
		server("10.0.0.2", 80, 1),
		server("10.0.0.3", 80, 1),
	}
	bal := newGroupBalancer(testUpstream(models.LBIPHash, servers...))

	clients := make([]net.IP, 0, 600)
	mapping := map[string]string{} // client → backend key
	for i := 0; i < 600; i++ {
		ip := net.ParseIP(fmt.Sprintf("172.16.%d.%d", i/250, i%250+1))
		clients = append(clients, ip)
		be := bal.pick(ip)
		if be == nil {
			t.Fatalf("pick returned nil for %s", ip)
		}
		mapping[ip.String()] = be.key
	}

	// Sanity: with a well-mixed hash, equal-weight backends own roughly
	// equal shares of the clients. This is the assertion that catches hash
	// clustering (raw FNV-1a maps all 172.16.x.y onto one or two backends
	// because they share a prefix).
	perBackend := map[string]int{}
	for _, key := range mapping {
		perBackend[key]++
	}
	for _, key := range []string{"10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"} {
		if perBackend[key] < len(clients)/6 {
			t.Fatalf("backend %s received only %d/%d clients — hash distribution is skewed",
				key, perBackend[key], len(clients))
		}
	}

	// Remove the middle backend and rebuild.
	removed := "10.0.0.2:80"
	bal.rebuild(testUpstream(models.LBIPHash, servers[0], servers[2]))

	remapped, kept := 0, 0
	for _, ip := range clients {
		be := bal.pick(ip)
		if be == nil {
			t.Fatalf("pick returned nil after rebuild for %s", ip)
		}
		if mapping[ip.String()] == removed {
			// Clients of the removed backend may move anywhere.
			if be.key == removed {
				t.Fatalf("removed backend still scheduled for %s", ip)
			}
			remapped++
			continue
		}
		if be.key != mapping[ip.String()] {
			t.Fatalf("client %s remapped from %s to %s although its backend was kept",
				ip, mapping[ip.String()], be.key)
		}
		kept++
	}
	if remapped == 0 || kept == 0 {
		t.Fatalf("unexpected distribution: remapped=%d kept=%d", remapped, kept)
	}
	if remapped > len(clients)/2 {
		t.Fatalf("consistent hash remapped %d/%d clients, want at most ~1/3", remapped, len(clients))
	}
}

// TestIPHashWeightZeroExcluded verifies weight-0 backends are absent from
// the hash ring.
func TestIPHashWeightZeroExcluded(t *testing.T) {
	bal := newGroupBalancer(testUpstream(models.LBIPHash,
		server("10.0.0.1", 80, 0),
		server("10.0.0.2", 80, 1),
	))
	for i := 0; i < 200; i++ {
		ip := net.ParseIP(fmt.Sprintf("192.168.%d.%d", i/250, i%250+1))
		be := bal.pick(ip)
		if be == nil {
			t.Fatalf("pick returned nil for %s", ip)
		}
		if be.key == "10.0.0.1:80" {
			t.Fatalf("weight-0 backend present on hash ring")
		}
	}
}

// TestIPHashHugeWeightsDoNotExplode verifies the vnode cap keeps the ring
// bounded while remaining schedulable.
func TestIPHashHugeWeightsDoNotExplode(t *testing.T) {
	bal := newGroupBalancer(testUpstream(models.LBIPHash,
		server("10.0.0.1", 80, 1<<30),
		server("10.0.0.2", 80, 1<<30),
	))
	if len(bal.ring) > maxRingPoints {
		t.Fatalf("ring size = %d, want <= %d", len(bal.ring), maxRingPoints)
	}
	if be := bal.pick(net.ParseIP("192.168.1.1")); be == nil {
		t.Fatal("pick returned nil with huge weights")
	}
}

// TestRebuildPreservesStatsAndPolicy verifies hot-reload semantics: counters
// survive for unchanged addr:port, the policy switch takes effect, and
// removed backends disappear from stats.
func TestRebuildPreservesStatsAndPolicy(t *testing.T) {
	bal := newGroupBalancer(testUpstream(models.LBWRR,
		server("10.0.0.1", 80, 1),
		server("10.0.0.2", 80, 1),
	))
	a := bal.pick(nil)
	bal.connOpened(a)
	bal.addBytesIn(a, 100)
	bal.addBytesOut(a, 40)

	// Rebuild: keep both backends, add a third, switch policy.
	bal.rebuild(testUpstream(models.LBLeastConn,
		server("10.0.0.1", 80, 1),
		server("10.0.0.2", 80, 1),
		server("10.0.0.3", 80, 1),
	))

	stats := bal.stats()
	if len(stats) != 3 {
		t.Fatalf("stats length = %d, want 3", len(stats))
	}
	var aStat *models.UpstreamServerStats
	for i := range stats {
		if stats[i].Addr == a.addr && stats[i].Port == a.port {
			aStat = &stats[i]
		}
	}
	if aStat == nil {
		t.Fatalf("backend %s missing after rebuild", a.key)
	}
	if aStat.ActiveConns != 1 || aStat.TotalConns != 1 || aStat.BytesIn != 100 || aStat.BytesOut != 40 {
		t.Fatalf("stats not preserved across rebuild: %+v", aStat)
	}

	// least_conn now active: the busy backend must not be picked.
	if be := bal.pick(nil); be == a {
		t.Fatalf("least_conn picked the only backend with active connections")
	}

	// Removing a backend drops it from stats; its counter goes orphaned.
	bal.rebuild(testUpstream(models.LBLeastConn,
		server("10.0.0.2", 80, 1),
		server("10.0.0.3", 80, 1),
	))
	stats = bal.stats()
	if len(stats) != 2 {
		t.Fatalf("stats length after removal = %d, want 2", len(stats))
	}
	for _, s := range stats {
		if s.Addr == a.addr {
			t.Fatalf("removed backend still present in stats")
		}
	}
}

// TestConnAccounting verifies the connection/traffic accounting helpers.
func TestConnAccounting(t *testing.T) {
	bal := newGroupBalancer(testUpstream(models.LBWRR,
		server("10.0.0.1", 80, 1),
	))
	be := bal.pick(nil)
	bal.connOpened(be)
	bal.connOpened(be)
	bal.connClosed(be)
	bal.addBytesIn(be, 10)
	bal.addBytesIn(be, -5) // ignored
	bal.addBytesOut(be, 7)

	s := bal.stats()[0]
	if s.ActiveConns != 1 || s.TotalConns != 2 {
		t.Fatalf("conn counters = %d/%d, want 1/2", s.ActiveConns, s.TotalConns)
	}
	if s.BytesIn != 10 || s.BytesOut != 7 {
		t.Fatalf("byte counters = %d/%d, want 10/7", s.BytesIn, s.BytesOut)
	}
}
