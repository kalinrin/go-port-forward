package forward

import (
	"net/netip"
	"sync"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/pkg/ipfilter"
)

// ManagerOption 自定义 Manager 的可选行为。
// ManagerOption customizes optional Manager behavior.
type ManagerOption func(*Manager)

// WithIPFilter 安装全局 IP 过滤器，对该 Manager 启动的所有转发器生效；
// logBlocked 控制是否（限流地）记录被拦截的连接。过滤器在启动时加载，
// 修改名单需重启进程生效。
// WithIPFilter installs a global IP filter applied to every forwarder
// started by this Manager; logBlocked controls whether blocked connections
// are (rate-limited) logged. The filter is loaded at startup; reloading
// the list requires a process restart.
func WithIPFilter(f *ipfilter.Filter, logBlocked bool) ManagerOption {
	return func(m *Manager) {
		m.filter = f
		m.logBlocked = logBlocked && f != nil
	}
}

// blockLogInterval 是同一转发器两次拦截日志之间的最小间隔。
// blockLogInterval is the minimum interval between two block logs per forwarder.
const blockLogInterval = time.Minute

// blockLogThrottle 聚合限流拦截日志，避免扫描流量刷爆日志文件。
// blockLogThrottle aggregates and rate-limits block logs so that scan
// traffic cannot flood the log file.
type blockLogThrottle struct {
	mu      sync.Mutex
	last    time.Time
	pending int64
}

// note 记录一次拦截；距上次输出超过 blockLogInterval 时输出一条聚合日志。
// note records one block; it emits one aggregated log line when more than
// blockLogInterval has elapsed since the last emission.
func (t *blockLogThrottle) note(rule, proto string, ip netip.Addr, total int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending++
	now := time.Now()
	if now.Sub(t.last) < blockLogInterval {
		return
	}
	t.last = now
	logger.S.Infow("connections blocked by ipfilter | ipfilter 拦截了连接",
		"rule", rule, "proto", proto,
		"count", t.pending, "total", total,
		"last_ip", ip.String())
	t.pending = 0
}

// noteBlocked 记录一次被 IP 过滤器拦截的 TCP 连接。
// noteBlocked records a TCP connection blocked by the IP filter.
func (f *TCPForwarder) noteBlocked(ip netip.Addr) {
	total := f.blockedConns.Add(1)
	if f.logBlocked {
		f.blockLog.note(f.rule.Name, "tcp", ip, total)
	}
}

// noteBlocked 记录一个被 IP 过滤器拦截的 UDP 源地址。
// noteBlocked records a UDP source address blocked by the IP filter.
func (f *UDPForwarder) noteBlocked(ip netip.Addr) {
	total := f.blockedConns.Add(1)
	if f.logBlocked {
		f.blockLog.note(f.rule.Name, "udp", ip, total)
	}
}

// Blocked 返回被拦截的 TCP 连接数（仅统计，不计入转发指标）。
// Blocked returns the number of blocked TCP connections (informational
// only, excluded from forwarding metrics).
func (f *TCPForwarder) Blocked() int64 { return f.blockedConns.Load() }

// Blocked 返回被拦截的 UDP 源地址数（仅统计，不计入转发指标）。
// Blocked returns the number of blocked UDP sources (informational only,
// excluded from forwarding metrics).
func (f *UDPForwarder) Blocked() int64 { return f.blockedConns.Load() }
