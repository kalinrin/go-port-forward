package forward

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go-port-forward/internal/config"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go.uber.org/zap"
)

func TestUpdateRuleConflictDoesNotStopExistingForwarder(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 32})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Shutdown()

	listenPort := freeTCPPort(t)
	conflictPort := freeTCPPort(t)
	targetPort := freeTCPPort(t)

	rule, err := mgr.AddRule(&models.CreateRuleRequest{
		Name:       "active-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: listenPort,
		Protocol:   models.ProtocolTCP,
		TargetAddr: "127.0.0.1",
		TargetPort: targetPort,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("add active rule: %v", err)
	}

	_, err = mgr.AddRule(&models.CreateRuleRequest{
		Name:       "conflict-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: conflictPort,
		Protocol:   models.ProtocolTCP,
		TargetAddr: "127.0.0.1",
		TargetPort: targetPort,
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("add conflict rule: %v", err)
	}

	assertTCPDialSucceeds(t, listenPort)

	_, err = mgr.UpdateRule(rule.ID, &models.UpdateRuleRequest{ListenPort: &conflictPort})
	if !errors.Is(err, ErrPortConflict) {
		t.Fatalf("expected ErrPortConflict, got %v", err)
	}

	assertTCPDialSucceeds(t, listenPort)

	stored, err := mgr.GetRule(rule.ID)
	if err != nil {
		t.Fatalf("get rule: %v", err)
	}
	if stored.ListenPort != listenPort {
		t.Fatalf("listen port changed after failed update: got %d want %d", stored.ListenPort, listenPort)
	}
}

func TestManagerCachesReadPathsInMemory(t *testing.T) {
	store := newCountingStore(&models.ForwardRule{
		ID:         "rule-1",
		Name:       "cached",
		ListenAddr: "127.0.0.1",
		ListenPort: 18080,
		Protocol:   models.ProtocolTCP,
		TargetAddr: "127.0.0.1",
		TargetPort: 8080,
		Enabled:    false,
	})
	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 8})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Shutdown()

	if got := store.listCalls(); got != 1 {
		t.Fatalf("startup list calls = %d, want 1", got)
	}

	if _, err := mgr.ListRules(); err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if _, err := mgr.GetRule("rule-1"); err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if _, _, err := mgr.Snapshot(); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	if got := store.listCalls(); got != 1 {
		t.Fatalf("list calls after cached reads = %d, want 1", got)
	}
	if got := store.getCalls(); got != 0 {
		t.Fatalf("get calls after cached reads = %d, want 0", got)
	}
}

func TestManagerClearsOnlyTransientRuntimeFieldsForInactiveRule(t *testing.T) {
	store := newCountingStore(&models.ForwardRule{
		ID:          "rule-1",
		Name:        "stale-runtime",
		ListenAddr:  "127.0.0.1",
		ListenPort:  18080,
		Protocol:    models.ProtocolTCP,
		TargetAddr:  "127.0.0.1",
		TargetPort:  8080,
		Enabled:     false,
		Status:      models.StatusActive,
		ErrorMsg:    "stale",
		BytesIn:     100,
		BytesOut:    200,
		ActiveConns: 3,
		TotalConns:  4,
	})
	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 8})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Shutdown()

	rule, err := mgr.GetRule("rule-1")
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}

	if rule.Status != models.StatusInactive {
		t.Fatalf("status = %q, want %q", rule.Status, models.StatusInactive)
	}
	if rule.ErrorMsg != "" {
		t.Fatalf("error message should be cleared: %+v", rule)
	}
	if rule.BytesIn != 100 || rule.BytesOut != 200 || rule.ActiveConns != 3 || rule.TotalConns != 4 {
		t.Fatalf("historical traffic fields should be preserved: %+v", rule)
	}
}

func TestAddRuleSerializesConflictingConcurrentCreates(t *testing.T) {
	store := newCountingStore()
	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 8})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Shutdown()

	listenPort := freeTCPPort(t)
	targetPorts := []int{freeTCPPort(t), freeTCPPort(t), freeTCPPort(t), freeTCPPort(t)}

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, len(targetPorts))

	for i, targetPort := range targetPorts {
		wg.Add(1)
		go func(i, targetPort int) {
			defer wg.Done()
			<-start
			_, err := mgr.AddRule(&models.CreateRuleRequest{
				Name:       "race-" + strconv.Itoa(i),
				ListenAddr: "127.0.0.1",
				ListenPort: listenPort,
				Protocol:   models.ProtocolTCP,
				TargetAddr: "127.0.0.1",
				TargetPort: targetPort,
				Enabled:    false,
			})
			results <- err
		}(i, targetPort)
	}

	close(start)
	wg.Wait()
	close(results)

	var success, conflicts int
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrPortConflict):
			conflicts++
		default:
			t.Fatalf("unexpected add error: %v", err)
		}
	}

	if success != 1 {
		t.Fatalf("success count = %d, want 1", success)
	}
	if conflicts != len(targetPorts)-1 {
		t.Fatalf("conflict count = %d, want %d", conflicts, len(targetPorts)-1)
	}
	rules, err := mgr.ListRules()
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
}

func TestDiagnosticsIncludesProtocolBreakdownAndErrors(t *testing.T) {
	base := time.Now().Add(-30 * time.Minute)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy listen port: %v", err)
	}
	defer occupied.Close()

	store := newCountingStore(
		&models.ForwardRule{
			ID:         "tcp-active",
			Name:       "tcp-active",
			ListenAddr: "127.0.0.1",
			ListenPort: freeTCPPort(t),
			Protocol:   models.ProtocolTCP,
			TargetAddr: "127.0.0.1",
			TargetPort: freeTCPPort(t),
			Enabled:    true,
			UpdatedAt:  base,
		},
		&models.ForwardRule{
			ID:         "udp-idle",
			Name:       "udp-idle",
			ListenAddr: "127.0.0.1",
			ListenPort: freeTCPPort(t),
			Protocol:   models.ProtocolUDP,
			TargetAddr: "127.0.0.1",
			TargetPort: freeTCPPort(t),
			Enabled:    false,
			UpdatedAt:  base.Add(5 * time.Minute),
		},
		&models.ForwardRule{
			ID:         "both-error",
			Name:       "both-error",
			ListenAddr: "127.0.0.1",
			ListenPort: occupied.Addr().(*net.TCPAddr).Port,
			Protocol:   models.ProtocolBoth,
			TargetAddr: "127.0.0.1",
			TargetPort: freeTCPPort(t),
			Enabled:    true,
			UpdatedAt:  base.Add(10 * time.Minute),
		},
	)
	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 1, BufferSize: 4096, PoolSize: 8})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Shutdown()

	diag, err := mgr.Diagnostics()
	if err != nil {
		t.Fatalf("Diagnostics: %v", err)
	}
	if diag.CachedRules != 3 || diag.Stats == nil || diag.Stats.TotalRules != 3 {
		t.Fatalf("unexpected cached/stats snapshot: %+v", diag)
	}
	if diag.ActiveForwarders != 1 {
		t.Fatalf("active forwarders = %d, want 1", diag.ActiveForwarders)
	}
	if diag.ErrorRules != 1 || diag.RuleHealth.Error != 1 || diag.RuleHealth.Active != 1 || diag.RuleHealth.Inactive != 1 {
		t.Fatalf("unexpected rule health: %+v", diag.RuleHealth)
	}
	if diag.Protocols.TCP.ConfiguredRules != 2 || diag.Protocols.UDP.ConfiguredRules != 2 {
		t.Fatalf("unexpected configured protocol counts: %+v", diag.Protocols)
	}
	if diag.Protocols.TCP.ActiveForwarders != 1 || diag.Protocols.UDP.ActiveForwarders != 0 {
		t.Fatalf("unexpected active protocol counts: %+v", diag.Protocols)
	}
	if len(diag.Errors) != 1 || diag.Errors[0].Name != "both-error" || diag.Errors[0].Error == "" {
		t.Fatalf("unexpected error summaries: %+v", diag.Errors)
	}
	if diag.Errors[0].ErrorCount != 1 || diag.Errors[0].LastErrorAt.IsZero() || diag.Errors[0].LastStatusChangeAt.IsZero() {
		t.Fatalf("unexpected error timeline summary: %+v", diag.Errors[0])
	}
	if len(diag.TopActiveRules) != 1 || diag.TopActiveRules[0].Name != "tcp-active" {
		t.Fatalf("unexpected top active rules: %+v", diag.TopActiveRules)
	}
	if len(diag.TopErrorRules) != 1 || diag.TopErrorRules[0].Name != "both-error" {
		t.Fatalf("unexpected top error rules: %+v", diag.TopErrorRules)
	}
}

func TestDiagnosticsHotRulesAreRankedAndLimited(t *testing.T) {
	base := time.Now().Add(-2 * time.Hour)
	store := newCountingStore(
		&models.ForwardRule{ID: "r1", Name: "alpha", ListenAddr: "127.0.0.1", ListenPort: 10001, Protocol: models.ProtocolTCP, TargetAddr: "127.0.0.1", TargetPort: 20001, Enabled: false, BytesIn: 100, BytesOut: 100, ActiveConns: 1, TotalConns: 4, UpdatedAt: base},
		&models.ForwardRule{ID: "r2", Name: "beta", ListenAddr: "127.0.0.1", ListenPort: 10002, Protocol: models.ProtocolUDP, TargetAddr: "127.0.0.1", TargetPort: 20002, Enabled: false, BytesIn: 200, BytesOut: 300, ActiveConns: 3, TotalConns: 5, UpdatedAt: base.Add(1 * time.Minute)},
		&models.ForwardRule{ID: "r3", Name: "gamma", ListenAddr: "127.0.0.1", ListenPort: 10003, Protocol: models.ProtocolTCP, TargetAddr: "127.0.0.1", TargetPort: 20003, Enabled: false, BytesIn: 600, BytesOut: 600, ActiveConns: 1, TotalConns: 9, UpdatedAt: base.Add(2 * time.Minute)},
		&models.ForwardRule{ID: "r4", Name: "delta", ListenAddr: "127.0.0.1", ListenPort: 10004, Protocol: models.ProtocolUDP, TargetAddr: "127.0.0.1", TargetPort: 20004, Enabled: false, BytesIn: 50, BytesOut: 50, ActiveConns: 0, TotalConns: 2, UpdatedAt: base.Add(3 * time.Minute)},
		&models.ForwardRule{ID: "r5", Name: "epsilon", ListenAddr: "127.0.0.1", ListenPort: 10005, Protocol: models.ProtocolTCP, TargetAddr: "127.0.0.1", TargetPort: 20005, Enabled: false, BytesIn: 10, BytesOut: 10, ActiveConns: 2, TotalConns: 2, UpdatedAt: base.Add(4 * time.Minute)},
		&models.ForwardRule{ID: "r6", Name: "zeta", ListenAddr: "127.0.0.1", ListenPort: 10006, Protocol: models.ProtocolUDP, TargetAddr: "127.0.0.1", TargetPort: 20006, Enabled: false, BytesIn: 1, BytesOut: 1, ActiveConns: 0, TotalConns: 1, UpdatedAt: base.Add(5 * time.Minute)},
	)
	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 1, BufferSize: 4096, PoolSize: 8})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer mgr.Shutdown()

	diag, err := mgr.Diagnostics()
	if err != nil {
		t.Fatalf("Diagnostics: %v", err)
	}
	if len(diag.HotRules) != 5 {
		t.Fatalf("hot rule count = %d, want 5", len(diag.HotRules))
	}
	got := []string{diag.HotRules[0].Name, diag.HotRules[1].Name, diag.HotRules[2].Name, diag.HotRules[3].Name, diag.HotRules[4].Name}
	want := []string{"beta", "epsilon", "gamma", "alpha", "delta"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hot rule order = %v, want %v", got, want)
		}
	}
	if diag.HotRules[0].TotalBytes != 500 {
		t.Fatalf("top hot rule total bytes = %d, want 500", diag.HotRules[0].TotalBytes)
	}
	if diag.HotRules[0].LastStatusChangeAt.IsZero() || diag.HotRules[0].UpdatedAt.IsZero() {
		t.Fatalf("hot rule timeline fields were empty: %+v", diag.HotRules[0])
	}
	activeWant := []string{"beta", "epsilon", "gamma", "alpha", "delta"}
	activeGot := []string{diag.TopActiveRules[0].Name, diag.TopActiveRules[1].Name, diag.TopActiveRules[2].Name, diag.TopActiveRules[3].Name, diag.TopActiveRules[4].Name}
	for i := range activeWant {
		if activeGot[i] != activeWant[i] {
			t.Fatalf("top active order = %v, want %v", activeGot, activeWant)
		}
	}
	trafficWant := []string{"gamma", "beta", "alpha", "delta", "epsilon"}
	trafficGot := []string{diag.TopTrafficRules[0].Name, diag.TopTrafficRules[1].Name, diag.TopTrafficRules[2].Name, diag.TopTrafficRules[3].Name, diag.TopTrafficRules[4].Name}
	for i := range trafficWant {
		if trafficGot[i] != trafficWant[i] {
			t.Fatalf("top traffic order = %v, want %v", trafficGot, trafficWant)
		}
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func assertTCPDialSucceeds(t *testing.T, port int) {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial listener on %d: %v", port, err)
	}
	_ = conn.Close()
}

type countingStore struct {
	mu        sync.Mutex
	rules     map[string]*models.ForwardRule
	upstreams map[string]*models.Upstream
	listN     int
	getN      int
	saveN     int
	delN      int
}

func newCountingStore(seed ...*models.ForwardRule) *countingStore {
	s := &countingStore{
		rules:     make(map[string]*models.ForwardRule, len(seed)),
		upstreams: make(map[string]*models.Upstream),
	}
	for _, rule := range seed {
		s.rules[rule.ID] = cloneRule(rule)
	}
	return s
}

func (s *countingStore) ListRules() ([]*models.ForwardRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listN++
	rules := make([]*models.ForwardRule, 0, len(s.rules))
	for _, rule := range s.rules {
		rules = append(rules, cloneRule(rule))
	}
	return rules, nil
}

func (s *countingStore) GetRule(id string) (*models.ForwardRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getN++
	rule, ok := s.rules[id]
	if !ok {
		return nil, storage.ErrRuleNotFound
	}
	return cloneRule(rule), nil
}

func (s *countingStore) SaveRule(rule *models.ForwardRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveN++
	s.rules[rule.ID] = cloneRule(rule)
	return nil
}

func (s *countingStore) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delN++
	if _, ok := s.rules[id]; !ok {
		return storage.ErrRuleNotFound
	}
	delete(s.rules, id)
	return nil
}

func (s *countingStore) ListUpstreams() ([]*models.Upstream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	upstreams := make([]*models.Upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		upstreams = append(upstreams, cloneUpstream(u))
	}
	return upstreams, nil
}

func (s *countingStore) GetUpstream(id string) (*models.Upstream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.upstreams[id]
	if !ok {
		return nil, storage.ErrUpstreamNotFound
	}
	return cloneUpstream(u), nil
}

func (s *countingStore) SaveUpstream(u *models.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreams[u.ID] = cloneUpstream(u)
	return nil
}

func (s *countingStore) DeleteUpstream(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[id]; !ok {
		return storage.ErrUpstreamNotFound
	}
	delete(s.upstreams, id)
	return nil
}

func (s *countingStore) Close() error { return nil }

func (s *countingStore) listCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listN
}

func (s *countingStore) getCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getN
}

func ptrOf[T any](v T) *T { return &v }

func newTestManager(t *testing.T) (*Manager, func()) {
	t.Helper()
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()
	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mgr, err := NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 32})
	if err != nil {
		_ = store.Close()
		t.Fatalf("new manager: %v", err)
	}
	return mgr, func() {
		mgr.Shutdown()
		_ = store.Close()
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestUpstreamCRUDValidationAndNameUniqueness(t *testing.T) {
	mgr, cleanup := newTestManager(t)
	defer cleanup()

	u, err := mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:   "web",
		Policy: models.LBIPHash,
		Servers: []models.UpstreamServer{
			{Addr: "10.0.0.1", Port: 8080, Weight: 3},
			{Addr: "10.0.0.2", Port: 8080, Weight: 1},
		},
	})
	if err != nil {
		t.Fatalf("AddUpstream: %v", err)
	}
	if u.Policy != models.LBIPHash || len(u.Servers) != 2 {
		t.Fatalf("unexpected upstream: %+v", u)
	}

	// Empty policy defaults to wrr.
	u2, err := mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:    "db",
		Servers: []models.UpstreamServer{{Addr: "10.0.1.1", Port: 5432, Weight: 1}},
	})
	if err != nil {
		t.Fatalf("AddUpstream default policy: %v", err)
	}
	if u2.Policy != models.LBWRR {
		t.Fatalf("default policy = %q, want wrr", u2.Policy)
	}

	// Duplicate name.
	_, err = mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:    "web",
		Servers: []models.UpstreamServer{{Addr: "10.0.0.9", Port: 80, Weight: 1}},
	})
	if !errors.Is(err, ErrUpstreamNameExists) {
		t.Fatalf("expected ErrUpstreamNameExists, got %v", err)
	}

	// No servers.
	_, err = mgr.AddUpstream(&models.CreateUpstreamRequest{Name: "empty"})
	if !errors.Is(err, ErrInvalidUpstream) {
		t.Fatalf("expected ErrInvalidUpstream, got %v", err)
	}

	// Duplicate backend entry.
	_, err = mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name: "dup",
		Servers: []models.UpstreamServer{
			{Addr: "10.0.0.1", Port: 80, Weight: 1},
			{Addr: "10.0.0.1", Port: 80, Weight: 2},
		},
	})
	if !errors.Is(err, ErrInvalidUpstream) {
		t.Fatalf("expected ErrInvalidUpstream for duplicate backend, got %v", err)
	}

	// Weight out of range.
	_, err = mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:    "neg",
		Servers: []models.UpstreamServer{{Addr: "10.0.0.1", Port: 80, Weight: -1}},
	})
	if !errors.Is(err, ErrInvalidUpstream) {
		t.Fatalf("expected ErrInvalidUpstream for negative weight, got %v", err)
	}

	// Update: rename, switch policy, replace servers.
	policy := models.LBLeastConn
	updated, err := mgr.UpdateUpstream(u.ID, &models.UpdateUpstreamRequest{
		Name:   ptrOf("web-v2"),
		Policy: &policy,
		Servers: []models.UpstreamServer{
			{Addr: "10.0.0.1", Port: 8080, Weight: 1},
			{Addr: "10.0.0.2", Port: 8080, Weight: 1},
			{Addr: "10.0.0.3", Port: 8080, Weight: 1},
		},
	})
	if err != nil {
		t.Fatalf("UpdateUpstream: %v", err)
	}
	if updated.Name != "web-v2" || updated.Policy != models.LBLeastConn || len(updated.Servers) != 3 {
		t.Fatalf("unexpected update result: %+v", updated)
	}

	// Renaming to an existing name fails.
	_, err = mgr.UpdateUpstream(u2.ID, &models.UpdateUpstreamRequest{Name: ptrOf("web-v2")})
	if !errors.Is(err, ErrUpstreamNameExists) {
		t.Fatalf("expected ErrUpstreamNameExists on rename, got %v", err)
	}

	list, err := mgr.ListUpstreams()
	if err != nil || len(list) != 2 {
		t.Fatalf("ListUpstreams = %v, %v", list, err)
	}
	got, err := mgr.GetUpstream(u.ID)
	if err != nil || got.Name != "web-v2" {
		t.Fatalf("GetUpstream = %+v, %v", got, err)
	}
	if len(got.ServerStats) != 3 {
		t.Fatalf("ServerStats length = %d, want 3 (zero-filled without balancer)", len(got.ServerStats))
	}

	if err := mgr.DeleteUpstream(u2.ID); err != nil {
		t.Fatalf("DeleteUpstream: %v", err)
	}
	if _, err := mgr.GetUpstream(u2.ID); !errors.Is(err, storage.ErrUpstreamNotFound) {
		t.Fatalf("expected ErrUpstreamNotFound after delete, got %v", err)
	}
}

func TestDeleteUpstreamBlockedWhileReferenced(t *testing.T) {
	mgr, cleanup := newTestManager(t)
	defer cleanup()

	u, err := mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:    "shared",
		Servers: []models.UpstreamServer{{Addr: "127.0.0.1", Port: 9090, Weight: 1}},
	})
	if err != nil {
		t.Fatalf("AddUpstream: %v", err)
	}

	// A disabled rule still blocks deletion.
	rule, err := mgr.AddRule(&models.CreateRuleRequest{
		Name:       "ref-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: freeTCPPort(t),
		Protocol:   models.ProtocolTCP,
		GroupID:    u.ID,
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	err = mgr.DeleteUpstream(u.ID)
	if !errors.Is(err, ErrUpstreamInUse) {
		t.Fatalf("expected ErrUpstreamInUse, got %v", err)
	}
	if !strings.Contains(err.Error(), "ref-rule") {
		t.Fatalf("error should list referencing rule names: %v", err)
	}

	if err := mgr.DeleteRule(rule.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if err := mgr.DeleteUpstream(u.ID); err != nil {
		t.Fatalf("DeleteUpstream after rule removal: %v", err)
	}
}

func TestGroupRuleTargetValidation(t *testing.T) {
	mgr, cleanup := newTestManager(t)
	defer cleanup()

	u, err := mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:    "grp",
		Servers: []models.UpstreamServer{{Addr: "127.0.0.1", Port: 9090, Weight: 1}},
	})
	if err != nil {
		t.Fatalf("AddUpstream: %v", err)
	}

	// Group and inline target are mutually exclusive.
	_, err = mgr.AddRule(&models.CreateRuleRequest{
		Name: "both", ListenAddr: "127.0.0.1", ListenPort: freeTCPPort(t),
		Protocol: models.ProtocolTCP, GroupID: u.ID,
		TargetAddr: "127.0.0.1", TargetPort: 80, Enabled: false,
	})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("expected ErrInvalidRule for group+target, got %v", err)
	}

	// Neither is provided.
	_, err = mgr.AddRule(&models.CreateRuleRequest{
		Name: "neither", ListenAddr: "127.0.0.1", ListenPort: freeTCPPort(t),
		Protocol: models.ProtocolTCP, Enabled: false,
	})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("expected ErrInvalidRule for neither, got %v", err)
	}

	// Unknown group.
	_, err = mgr.AddRule(&models.CreateRuleRequest{
		Name: "ghost", ListenAddr: "127.0.0.1", ListenPort: freeTCPPort(t),
		Protocol: models.ProtocolTCP, GroupID: "no-such-group", Enabled: false,
	})
	if !errors.Is(err, storage.ErrUpstreamNotFound) {
		t.Fatalf("expected ErrUpstreamNotFound, got %v", err)
	}

	// Valid group rule: inline target cleared, decorated with group metadata.
	rule, err := mgr.AddRule(&models.CreateRuleRequest{
		Name: "ok", ListenAddr: "127.0.0.1", ListenPort: freeTCPPort(t),
		Protocol: models.ProtocolTCP, GroupID: u.ID, Enabled: false,
	})
	if err != nil {
		t.Fatalf("AddRule group mode: %v", err)
	}
	if rule.TargetAddr != "" || rule.TargetPort != 0 {
		t.Fatalf("group rule should clear inline target fields: %+v", rule)
	}
	if rule.GroupName != "grp" || rule.GroupServerCount != 1 {
		t.Fatalf("group decoration missing: %+v", rule)
	}

	// Switching an existing rule from group to single target requires the address.
	empty := ""
	_, err = mgr.UpdateRule(rule.ID, &models.UpdateRuleRequest{GroupID: &empty})
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("expected ErrInvalidRule when dropping group without target, got %v", err)
	}
}

func TestGroupRuleDistributesTCPConnections(t *testing.T) {
	mgr, cleanup := newTestManager(t)
	defer cleanup()

	// Two backend listeners counting accepted connections.
	backends := make([]net.Listener, 2)
	accepts := make([]int64, 2)
	var mu sync.Mutex
	for i := range backends {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("backend listen: %v", err)
		}
		backends[i] = ln
		go func(i int, ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				accepts[i]++
				mu.Unlock()
				_ = conn.Close()
			}
		}(i, ln)
	}
	defer func() {
		for _, ln := range backends {
			ln.Close()
		}
	}()

	u, err := mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:   "tcp-pool",
		Policy: models.LBWRR,
		Servers: []models.UpstreamServer{
			{Addr: "127.0.0.1", Port: backends[0].Addr().(*net.TCPAddr).Port, Weight: 1},
			{Addr: "127.0.0.1", Port: backends[1].Addr().(*net.TCPAddr).Port, Weight: 1},
		},
	})
	if err != nil {
		t.Fatalf("AddUpstream: %v", err)
	}

	listenPort := freeTCPPort(t)
	rule, err := mgr.AddRule(&models.CreateRuleRequest{
		Name:       "lb-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: listenPort,
		Protocol:   models.ProtocolTCP,
		GroupID:    u.ID,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if rule.Status != models.StatusActive {
		t.Fatalf("rule status = %q, want active (err=%q)", rule.Status, rule.ErrorMsg)
	}

	// Four connections, WRR alternates → two per backend.
	for i := 0; i < 4; i++ {
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		_ = conn.Close()
	}

	waitFor(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return accepts[0]+accepts[1] == 4
	})
	mu.Lock()
	a, b := accepts[0], accepts[1]
	mu.Unlock()
	if a != 2 || b != 2 {
		t.Fatalf("backend accepts = %d/%d, want 2/2", a, b)
	}

	// Per-backend stats are visible through the group.
	got, err := mgr.GetUpstream(u.ID)
	if err != nil {
		t.Fatalf("GetUpstream: %v", err)
	}
	var total int64
	for _, s := range got.ServerStats {
		total += s.TotalConns
	}
	if total != 4 {
		t.Fatalf("backend total conns = %d, want 4", total)
	}
}

func TestGroupRuleSchedulesUDPPerSession(t *testing.T) {
	mgr, cleanup := newTestManager(t)
	defer cleanup()

	u, err := mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:   "udp-pool",
		Policy: models.LBWRR,
		Servers: []models.UpstreamServer{
			{Addr: "127.0.0.1", Port: freeUDPPort(t), Weight: 1},
			{Addr: "127.0.0.1", Port: freeUDPPort(t), Weight: 1},
		},
	})
	if err != nil {
		t.Fatalf("AddUpstream: %v", err)
	}

	listenPort := freeUDPPort(t)
	rule, err := mgr.AddRule(&models.CreateRuleRequest{
		Name:       "udp-lb",
		ListenAddr: "127.0.0.1",
		ListenPort: listenPort,
		Protocol:   models.ProtocolUDP,
		GroupID:    u.ID,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if rule.Status != models.StatusActive {
		t.Fatalf("rule status = %q, want active (err=%q)", rule.Status, rule.ErrorMsg)
	}

	// Two clients (distinct source ports) → two sessions → one per backend.
	for i := 0; i < 2; i++ {
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listenPort})
		if err != nil {
			t.Fatalf("dial udp: %v", err)
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatalf("write udp: %v", err)
		}
		_ = c.Close()
	}

	waitFor(t, 3*time.Second, func() bool {
		got, err := mgr.GetUpstream(u.ID)
		if err != nil || len(got.ServerStats) != 2 {
			return false
		}
		return got.ServerStats[0].TotalConns == 1 && got.ServerStats[1].TotalConns == 1
	})
}

func TestUpdateUpstreamHotReloadKeepsStatsAndConnections(t *testing.T) {
	mgr, cleanup := newTestManager(t)
	defer cleanup()

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()
	held := make(chan net.Conn, 1)
	go func() {
		conn, err := backendLn.Accept()
		if err == nil {
			held <- conn
		}
	}()

	backendPort := backendLn.Addr().(*net.TCPAddr).Port
	u, err := mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:    "hot",
		Policy:  models.LBWRR,
		Servers: []models.UpstreamServer{{Addr: "127.0.0.1", Port: backendPort, Weight: 1}},
	})
	if err != nil {
		t.Fatalf("AddUpstream: %v", err)
	}

	listenPort := freeTCPPort(t)
	rule, err := mgr.AddRule(&models.CreateRuleRequest{
		Name:       "hot-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: listenPort,
		Protocol:   models.ProtocolTCP,
		GroupID:    u.ID,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	select {
	case conn := <-held:
		defer conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for backend accept")
	}

	waitFor(t, 2*time.Second, func() bool {
		got, err := mgr.GetUpstream(u.ID)
		if err != nil || len(got.ServerStats) != 1 {
			return false
		}
		return got.ServerStats[0].ActiveConns == 1 && got.ServerStats[0].TotalConns == 1
	})

	// Hot reload: switch policy and add a second backend.
	policy := models.LBLeastConn
	_, err = mgr.UpdateUpstream(u.ID, &models.UpdateUpstreamRequest{
		Policy: &policy,
		Servers: []models.UpstreamServer{
			{Addr: "127.0.0.1", Port: backendPort, Weight: 1},
			{Addr: "127.0.0.1", Port: freeTCPPort(t), Weight: 1},
		},
	})
	if err != nil {
		t.Fatalf("UpdateUpstream: %v", err)
	}

	// The rule keeps running and the in-flight connection keeps counting.
	after, err := mgr.GetRule(rule.ID)
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if after.Status != models.StatusActive {
		t.Fatalf("rule status after hot reload = %q, want active", after.Status)
	}
	got, err := mgr.GetUpstream(u.ID)
	if err != nil {
		t.Fatalf("GetUpstream: %v", err)
	}
	if len(got.ServerStats) != 2 {
		t.Fatalf("server stats = %d, want 2", len(got.ServerStats))
	}
	if got.ServerStats[0].ActiveConns != 1 || got.ServerStats[0].TotalConns != 1 {
		t.Fatalf("stats not preserved across hot reload: %+v", got.ServerStats[0])
	}
}
