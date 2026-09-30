package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go-port-forward/internal/config"
	"go-port-forward/internal/firewall"
	"go-port-forward/internal/forward"
	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/internal/storage"
	"go-port-forward/pkg/os/wsl"
	"go.uber.org/zap"
)

func TestCreateRuleRejectsUnknownJSONFields(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(`{"name":"demo","listen_port":18080,"protocol":"tcp","target_addr":"127.0.0.1","target_port":80,"extra":true}`))
	rec := httptest.NewRecorder()

	h.createRule(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateRuleMapsConflictTo409(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	port := freePort(t)
	_, err := h.mgr.AddRule(&models.CreateRuleRequest{
		Name:       "existing",
		ListenAddr: "127.0.0.1",
		ListenPort: port,
		Protocol:   models.ProtocolTCP,
		TargetAddr: "127.0.0.1",
		TargetPort: freePort(t),
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(`{"name":"dup","listen_addr":"127.0.0.1","listen_port":`+strconv.Itoa(port)+`,"protocol":"tcp","target_addr":"127.0.0.1","target_port":8080}`))
	rec := httptest.NewRecorder()

	h.createRule(rec, req)

	if rec.Code != 409 {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
}

func TestToggleRuleRequiresEnabledField(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	rule, err := h.mgr.AddRule(&models.CreateRuleRequest{
		Name:       "toggle-me",
		ListenAddr: "127.0.0.1",
		ListenPort: freePort(t),
		Protocol:   models.ProtocolTCP,
		TargetAddr: "127.0.0.1",
		TargetPort: freePort(t),
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	req := httptest.NewRequest("PUT", "/api/rules/"+rule.ID+"/toggle", strings.NewReader(`{}`))
	req.SetPathValue("id", rule.ID)
	rec := httptest.NewRecorder()

	h.toggleRule(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateRuleRejectsProxyProtocolOnUDPOnlyRule(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(`{"name":"udp-proxy","listen_port":18181,"protocol":"udp","target_addr":"127.0.0.1","target_port":53,"proxy_protocol":true}`))
	rec := httptest.NewRecorder()

	h.createRule(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "PROXY protocol") {
		t.Fatalf("error should mention PROXY protocol: %s", rec.Body.String())
	}
}

func TestCreateRuleAcceptsProxyProtocolOnTCPRule(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/rules", strings.NewReader(`{"name":"tcp-proxy","listen_addr":"127.0.0.1","listen_port":`+strconv.Itoa(freePort(t))+`,"protocol":"tcp","target_addr":"127.0.0.1","target_port":80,"proxy_protocol":true,"enabled":false}`))
	rec := httptest.NewRecorder()

	h.createRule(rec, req)

	if rec.Code != 201 {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"proxy_protocol":true`) {
		t.Fatalf("created rule should echo proxy_protocol=true: %s", rec.Body.String())
	}
}

func TestServerStartReturnsErrorWhenPortIsOccupied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	srv := New(config.WebConfig{Host: "127.0.0.1", Port: port}, nil, nil)
	if err := srv.Start(); err == nil {
		t.Fatal("expected Start to fail when port is occupied")
	}
}

func TestToggleRuleSyncsFirewallOnEnableAndDisable(t *testing.T) {
	fw := &fakeFirewall{}
	h, cleanup := newTestHandlerWithFirewall(t, fw)
	defer cleanup()

	rule, err := h.mgr.AddRule(&models.CreateRuleRequest{
		Name:        "toggle-fw",
		ListenAddr:  "127.0.0.1",
		ListenPort:  freePort(t),
		Protocol:    models.ProtocolTCP,
		TargetAddr:  "127.0.0.1",
		TargetPort:  freePort(t),
		Enabled:     false,
		AddFirewall: true,
	})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	enableReq := httptest.NewRequest(http.MethodPut, "/api/rules/"+rule.ID+"/toggle", strings.NewReader(`{"enabled":true}`))
	enableReq.SetPathValue("id", rule.ID)
	enableRec := httptest.NewRecorder()
	h.toggleRule(enableRec, enableReq)
	if enableRec.Code != http.StatusOK {
		t.Fatalf("enable status = %d, want 200, body=%s", enableRec.Code, enableRec.Body.String())
	}
	if len(fw.added) != 1 {
		t.Fatalf("firewall add calls = %d, want 1", len(fw.added))
	}

	disableReq := httptest.NewRequest(http.MethodPut, "/api/rules/"+rule.ID+"/toggle", strings.NewReader(`{"enabled":false}`))
	disableReq.SetPathValue("id", rule.ID)
	disableRec := httptest.NewRecorder()
	h.toggleRule(disableRec, disableReq)
	if disableRec.Code != http.StatusOK {
		t.Fatalf("disable status = %d, want 200, body=%s", disableRec.Code, disableRec.Body.String())
	}
	if len(fw.deleted) != 1 {
		t.Fatalf("firewall delete calls = %d, want 1", len(fw.deleted))
	}
}

func TestUpdateRuleSyncsFirewallWhenEndpointChanges(t *testing.T) {
	fw := &fakeFirewall{}
	h, cleanup := newTestHandlerWithFirewall(t, fw)
	defer cleanup()

	rule, err := h.mgr.AddRule(&models.CreateRuleRequest{
		Name:        "fw-update",
		ListenAddr:  "127.0.0.1",
		ListenPort:  freePort(t),
		Protocol:    models.ProtocolTCP,
		TargetAddr:  "127.0.0.1",
		TargetPort:  freePort(t),
		Enabled:     true,
		AddFirewall: true,
	})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	newPort := freePort(t)
	req := httptest.NewRequest(http.MethodPut, "/api/rules/"+rule.ID, strings.NewReader(`{"listen_port":`+strconv.Itoa(newPort)+`}`))
	req.SetPathValue("id", rule.ID)
	rec := httptest.NewRecorder()

	h.updateRule(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if len(fw.deleted) != 1 || fw.deleted[0].Port != rule.ListenPort {
		t.Fatalf("unexpected firewall delete calls: %#v", fw.deleted)
	}
	if len(fw.added) != 1 || fw.added[0].Port != newPort {
		t.Fatalf("unexpected firewall add calls: %#v", fw.added)
	}
}

func TestWSLCapabilityEndpointReturnsCapabilityPayload(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	oldDetect := wslDetectCapability
	wslDetectCapability = func() wsl.Capability {
		return wsl.Capability{
			Supported:  true,
			Installed:  true,
			Enabled:    true,
			HasDistros: true,
			ShowImport: true,
			Distros:    []wsl.Distro{{Name: "Ubuntu-24.04", State: "Running", Version: "2", Default: true}},
		}
	}
	defer func() { wslDetectCapability = oldDetect }()

	req := httptest.NewRequest(http.MethodGet, "/api/wsl/capability", nil)
	rec := httptest.NewRecorder()

	h.wslCapability(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"show_import":true`) || !strings.Contains(body, `Ubuntu-24.04`) {
		t.Fatalf("unexpected capability payload: %s", body)
	}
}

func TestDashboardReturnsRulesAndStatsInSinglePayload(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	_, err := h.mgr.AddRule(&models.CreateRuleRequest{
		Name:       "dashboard-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: freePort(t),
		Protocol:   models.ProtocolTCP,
		TargetAddr: "127.0.0.1",
		TargetPort: freePort(t),
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	rec := httptest.NewRecorder()

	h.dashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"rules"`) || !strings.Contains(body, `"stats"`) || !strings.Contains(body, `dashboard-rule`) {
		t.Fatalf("unexpected dashboard payload: %s", body)
	}
}

func TestDiagnosticsReturnsRuntimePoolAndManagerSnapshot(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	_, err := h.mgr.AddRule(&models.CreateRuleRequest{
		Name:       "diag-rule",
		ListenAddr: "127.0.0.1",
		ListenPort: freePort(t),
		Protocol:   models.ProtocolTCP,
		TargetAddr: "127.0.0.1",
		TargetPort: freePort(t),
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy listen port: %v", err)
	}
	defer occupied.Close()
	_, err = h.mgr.AddRule(&models.CreateRuleRequest{
		Name:       "diag-error",
		ListenAddr: "127.0.0.1",
		ListenPort: occupied.Addr().(*net.TCPAddr).Port,
		Protocol:   models.ProtocolBoth,
		TargetAddr: "127.0.0.1",
		TargetPort: freePort(t),
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("seed error rule: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics", nil)
	rec := httptest.NewRecorder()

	h.diagnostics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, needle := range []string{`"runtime"`, `"pool"`, `"manager"`, `"protocols"`, `"hot_rules"`, `"top_active_rules"`, `"top_traffic_rules"`, `"top_error_rules"`, `"last_error_at"`, `"last_status_change_at"`, `"error_count"`, `"errors"`, `"cached_rules":2`, `"inactive":1`, `"error":1`, `diag-error`} {
		if !strings.Contains(body, needle) {
			t.Fatalf("diagnostics payload missing %s: %s", needle, body)
		}
	}
}

func TestUpstreamEndpointsCRUDAndReferenceBlocking(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	// Create.
	body := `{"name":"web","policy":"wrr","servers":[{"addr":"10.0.0.1","port":80,"weight":2},{"addr":"10.0.0.2","port":80,"weight":1}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/upstreams", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.createUpstream(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		Success bool `json:"success"`
		Data    struct {
			ID         string                       `json:"id"`
			Policy     string                       `json:"policy"`
			Servers    []models.UpstreamServer      `json:"servers"`
			ServerStat []models.UpstreamServerStats `json:"server_stats"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !created.Success || created.Data.ID == "" || len(created.Data.Servers) != 2 || len(created.Data.ServerStat) != 2 {
		t.Fatalf("unexpected create payload: %s", rec.Body.String())
	}

	// Duplicate name → 409.
	req = httptest.NewRequest(http.MethodPost, "/api/upstreams", strings.NewReader(body))
	rec = httptest.NewRecorder()
	h.createUpstream(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate name status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}

	// Invalid (no servers) → 400.
	req = httptest.NewRequest(http.MethodPost, "/api/upstreams", strings.NewReader(`{"name":"bad"}`))
	rec = httptest.NewRecorder()
	h.createUpstream(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid upstream status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}

	// Rule referencing the group.
	ruleBody := `{"name":"grp-rule","listen_addr":"127.0.0.1","listen_port":` + strconv.Itoa(freePort(t)) + `,"protocol":"tcp","group_id":"` + created.Data.ID + `","enabled":false}`
	req = httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(ruleBody))
	rec = httptest.NewRecorder()
	h.createRule(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("group rule status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"group_id":"`+created.Data.ID+`"`) {
		t.Fatalf("created rule should echo group_id: %s", rec.Body.String())
	}

	// Rule with unknown group → 404.
	req = httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(`{"name":"ghost","listen_port":`+strconv.Itoa(freePort(t))+`,"protocol":"tcp","group_id":"missing","enabled":false}`))
	rec = httptest.NewRecorder()
	h.createRule(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown group status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}

	// Delete blocked while referenced → 409 with rule name.
	req = httptest.NewRequest(http.MethodDelete, "/api/upstreams/"+created.Data.ID, nil)
	req.SetPathValue("id", created.Data.ID)
	rec = httptest.NewRecorder()
	h.deleteUpstream(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("blocked delete status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "grp-rule") {
		t.Fatalf("conflict should mention referencing rule: %s", rec.Body.String())
	}

	// List includes the group.
	req = httptest.NewRequest(http.MethodGet, "/api/upstreams", nil)
	rec = httptest.NewRecorder()
	h.listUpstreams(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"web"`) {
		t.Fatalf("list upstreams: %d %s", rec.Code, rec.Body.String())
	}

	// Update (rename) → 200.
	req = httptest.NewRequest(http.MethodPut, "/api/upstreams/"+created.Data.ID, strings.NewReader(`{"name":"web-v2"}`))
	req.SetPathValue("id", created.Data.ID)
	rec = httptest.NewRecorder()
	h.updateUpstream(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "web-v2") {
		t.Fatalf("update upstream: %d %s", rec.Code, rec.Body.String())
	}

	// Get one.
	req = httptest.NewRequest(http.MethodGet, "/api/upstreams/"+created.Data.ID, nil)
	req.SetPathValue("id", created.Data.ID)
	rec = httptest.NewRecorder()
	h.getUpstream(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "web-v2") {
		t.Fatalf("get upstream: %d %s", rec.Code, rec.Body.String())
	}

	// Unknown id → 404.
	req = httptest.NewRequest(http.MethodGet, "/api/upstreams/missing", nil)
	req.SetPathValue("id", "missing")
	rec = httptest.NewRecorder()
	h.getUpstream(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing upstream status = %d, want 404", rec.Code)
	}
}

func TestCreateRuleRejectsGroupAndTargetTogether(t *testing.T) {
	h, cleanup := newTestHandler(t)
	defer cleanup()

	upstream, err := h.mgr.AddUpstream(&models.CreateUpstreamRequest{
		Name:    "grp",
		Servers: []models.UpstreamServer{{Addr: "127.0.0.1", Port: 9090, Weight: 1}},
	})
	if err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	body := `{"name":"both","listen_port":` + strconv.Itoa(freePort(t)) + `,"protocol":"tcp","group_id":"` + upstream.ID + `","target_addr":"127.0.0.1","target_port":80,"enabled":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(body))
	rec := httptest.NewRecorder()

	h.createRule(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mutually exclusive") {
		t.Fatalf("error should mention mutual exclusion: %s", rec.Body.String())
	}
}

func newTestHandler(t *testing.T) (*handler, func()) {
	return newTestHandlerWithFirewall(t, nil)
}

func newTestHandlerWithFirewall(t *testing.T, fw firewall.Manager) (*handler, func()) {
	t.Helper()
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	store, err := storage.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mgr, err := forward.NewManager(store, config.ForwardConfig{DialTimeout: 1, UDPTimeout: 30, BufferSize: 4096, PoolSize: 32})
	if err != nil {
		_ = store.Close()
		t.Fatalf("new manager: %v", err)
	}
	return &handler{mgr: mgr, fw: fw}, func() {
		mgr.Shutdown()
		_ = store.Close()
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type fakeFirewall struct {
	added   []firewall.Rule
	deleted []firewall.Rule
}

func (f *fakeFirewall) AddRule(r firewall.Rule) error {
	f.added = append(f.added, r)
	return nil
}

func (f *fakeFirewall) DeleteRule(r firewall.Rule) error {
	f.deleted = append(f.deleted, r)
	return nil
}

func (f *fakeFirewall) RuleExists(firewall.Rule) (bool, error) {
	return false, nil
}
