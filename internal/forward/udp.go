package forward

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"
	"go-port-forward/pkg/ipfilter"
	"go-port-forward/pkg/pool"

	"go.uber.org/zap"
)

// udpAddrKey 是 UDP 地址的固定大小可比较 key，避免每包调用 String() 产生字符串分配。
// udpAddrKey is a fixed-size comparable key for UDP addresses, avoiding per-packet
// string allocation from String().
type udpAddrKey struct {
	ip   [net.IPv6len]byte // 16 bytes，同时容纳 IPv4 和 IPv6 | fits both IPv4 and IPv6
	port uint16
	len  uint8 // IP 原始长度（4 或 16），确保不同表示不会碰撞 | raw IP length (4 or 16)
	zone string
}

// makeUDPAddrKey 从 *net.UDPAddr 构造零分配的 map key。
// makeUDPAddrKey constructs a zero-allocation map key from *net.UDPAddr.
func makeUDPAddrKey(addr *net.UDPAddr) udpAddrKey {
	var k udpAddrKey
	k.port = uint16(addr.Port)
	k.len = uint8(len(addr.IP))
	k.zone = addr.Zone
	copy(k.ip[:], addr.IP)
	return k
}

// udpSession tracks an upstream UDP connection for a specific client address.
// backend is the scheduled upstream-group backend (nil in single-target
// mode); it is picked once at session creation and pinned for the session
// lifetime so datagrams never reorder across backends.
type udpSession struct {
	upstream *net.UDPConn
	lastSeen time.Time
	backend  *backend
}

// UDPForwarder listens on a local UDP port and forwards datagrams to a target.
type UDPForwarder struct {
	rule       *models.ForwardRule
	conn       *net.UDPConn
	readConn   net.PacketConn // read side (maybe wrapped by the IP filter)
	targetAddr *net.UDPAddr
	sessions   map[udpAddrKey]*udpSession
	perIP      map[[net.IPv6len]byte]int // live sessions per source IP (cap enforcement)
	stopCh     chan struct{}
	wg         sync.WaitGroup
	timeout    time.Duration

	// session caps: bound fd/goroutine usage, protecting against session
	// flooding (each session owns one upstream socket + relay goroutine).
	maxSessions int
	maxPerIP    int
	capDrops    atomic.Int64 // datagrams dropped due to caps (informational)
	capLog      blockLogThrottle

	// stats (atomic)
	bytesIn      atomic.Int64
	bytesOut     atomic.Int64
	active       atomic.Int64
	totalConns   atomic.Int64
	blockedConns atomic.Int64 // blocked counter (informational only)

	stopOnce sync.Once
	mu       sync.Mutex

	// IP filter (global, optional)
	filter     *ipfilter.Filter
	logBlocked bool
	blockLog   blockLogThrottle

	// bal schedules backends when the rule references an upstream group;
	// nil in single-target mode.
	bal *groupBalancer
}

// Default UDP session caps applied when the config value is <= 0.
const (
	defaultUDPMaxSessions      = 65536
	defaultUDPMaxSessionsPerIP = 1024
)

func newUDPForwarder(rule *models.ForwardRule, timeoutSec, maxSessions, maxSessionsPerIP int) *UDPForwarder {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	if maxSessions <= 0 {
		maxSessions = defaultUDPMaxSessions
	}
	if maxSessionsPerIP <= 0 {
		maxSessionsPerIP = defaultUDPMaxSessionsPerIP
	}
	return &UDPForwarder{
		rule:        rule,
		timeout:     time.Duration(timeoutSec) * time.Second,
		maxSessions: maxSessions,
		maxPerIP:    maxSessionsPerIP,
		sessions:    make(map[udpAddrKey]*udpSession),
		perIP:       make(map[[net.IPv6len]byte]int),
		stopCh:      make(chan struct{}),
	}
}

func (f *UDPForwarder) Start() error {
	listenAddr := fmt.Sprintf("%s:%d", f.rule.ListenAddr, f.rule.ListenPort)
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("UDP 监听失败 | UDP listen failed %s: %w", listenAddr, err)
	}
	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", f.rule.TargetAddr, f.rule.TargetPort))
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("UDP 目标地址无效 | invalid UDP target address: %w", err)
	}
	f.conn = conn
	f.targetAddr = targetAddr
	// Install the global IP filter (a no-op when disabled): datagrams from
	// blocked sources are dropped at read time and never create sessions.
	f.readConn = ipfilter.WrapPacketConn(conn, f.filter, f.noteBlocked)

	f.wg.Add(2)
	go f.readLoop()
	go f.cleanupLoop()

	logger.S.Infow("UDP forwarder started", "rule", f.rule.Name, "listen", listenAddr,
		"target", fmt.Sprintf("%s:%d", f.rule.TargetAddr, f.rule.TargetPort))
	return nil
}

func (f *UDPForwarder) Stop() {
	f.stopOnce.Do(func() {
		close(f.stopCh)
		if f.conn != nil {
			_ = f.conn.Close()
		}
		f.mu.Lock()
		for key, s := range f.sessions {
			_ = s.upstream.Close()
			delete(f.sessions, key)
			if s.backend != nil {
				f.bal.connClosed(s.backend)
			}
		}
		f.active.Store(0)
		f.perIP = make(map[[net.IPv6len]byte]int)
		f.mu.Unlock()
	})
	f.wg.Wait()
}

func (f *UDPForwarder) readLoop() {
	defer f.wg.Done()
	// Use pooled buffer for reading
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	for {
		n, addr, err := f.readConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-f.stopCh:
				return
			default:
				if ne, ok := errors.AsType[net.Error](err); ok && ne.Temporary() {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				logger.L.Warn("UDP read error", zap.Error(err))
				return
			}
		}
		srcAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			// Non-UDP source address (the underlying conn is *net.UDPConn; should not happen).
			continue
		}
		// Fast path: the session already exists — forward inline. This
		// avoids a per-packet goroutine handoff, buffer copy and pool
		// submit; the write completes before the next ReadFrom reuses buf.
		if sess := f.touchSession(srcAddr); sess != nil {
			f.writeUpstream(sess, buf[:n])
			continue
		}
		// Slow path: first datagram from this client — create the session
		// asynchronously so readLoop is never blocked by dialing or
		// upstream-group scheduling.
		// Copy packet data for async processing
		pkt := pool.GetBuffer(n)[:n]
		copy(pkt, buf[:n])
		// Use goroutine pool via pkg/pool
		if err := pool.Submit(func() { f.forward(srcAddr, pkt) }); err != nil {
			go f.forward(srcAddr, pkt)
		}
	}
}

// touchSession 返回 srcAddr 的活跃会话并刷新其空闲计时；不存在时返回 nil。
// touchSession returns the live session for srcAddr, refreshing its idle
// timer, or nil when no session exists yet.
func (f *UDPForwarder) touchSession(srcAddr *net.UDPAddr) *udpSession {
	key := makeUDPAddrKey(srcAddr)
	f.mu.Lock()
	sess, ok := f.sessions[key]
	if ok {
		sess.lastSeen = time.Now()
	}
	f.mu.Unlock()
	return sess
}

// writeUpstream 向会话的上游 socket 发送一个数据报并更新流量计数。
// writeUpstream sends one datagram to the session's upstream socket and
// updates traffic counters.
func (f *UDPForwarder) writeUpstream(sess *udpSession, data []byte) {
	n, _ := sess.upstream.Write(data)
	f.bytesIn.Add(int64(n))
	if sess.backend != nil {
		f.bal.addBytesIn(sess.backend, int64(n))
	}
}

func (f *UDPForwarder) forward(srcAddr *net.UDPAddr, data []byte) {
	defer pool.PutBuffer(data)
	if f.isStopping() {
		return
	}
	sess := f.getOrCreateSession(srcAddr)
	if sess == nil {
		return
	}
	f.writeUpstream(sess, data)
}

func (f *UDPForwarder) relayBack(clientAddr *net.UDPAddr, sess *udpSession) {
	defer f.wg.Done()
	// Use pooled buffer for relay
	buf := pool.GetBuffer(65535)
	defer pool.PutBuffer(buf)
	for {
		n, err := sess.upstream.Read(buf)
		if err != nil {
			return
		}
		out, _ := f.conn.WriteToUDP(buf[:n], clientAddr)
		f.bytesOut.Add(int64(out))
		if sess.backend != nil {
			f.bal.addBytesOut(sess.backend, int64(out))
		}
	}
}

func (f *UDPForwarder) cleanupLoop() {
	defer f.wg.Done()
	ticker := time.NewTicker(f.timeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			f.mu.Lock()
			now := time.Now()
			for k, s := range f.sessions {
				if now.Sub(s.lastSeen) > f.timeout {
					_ = s.upstream.Close()
					delete(f.sessions, k)
					f.decPerIPLocked(k)
					f.active.Add(-1)
					if s.backend != nil {
						f.bal.connClosed(s.backend)
					}
				}
			}
			f.mu.Unlock()
		}
	}
}

func (f *UDPForwarder) Stats() (bytesIn, bytesOut, active, total int64) {
	return f.bytesIn.Load(), f.bytesOut.Load(), f.active.Load(), f.totalConns.Load()
}

func (f *UDPForwarder) getOrCreateSession(srcAddr *net.UDPAddr) *udpSession {
	key := makeUDPAddrKey(srcAddr) // 零分配 | zero allocation
	now := time.Now()

	f.mu.Lock()
	if sess, ok := f.sessions[key]; ok {
		sess.lastSeen = now
		f.mu.Unlock()
		return sess
	}
	// Best-effort early cap check: skip dialing when clearly over the limit.
	// The authoritative check happens at insert below (races are tolerated).
	capped := !f.allowSessionLocked(key)
	f.mu.Unlock()
	if capped {
		f.noteCapDrop(srcAddr)
		return nil
	}
	if f.isStopping() {
		return nil
	}

	// Resolve the upstream target: the rule's fixed target, or a backend
	// scheduled once per session (the session then pins that backend).
	target := f.targetAddr
	var be *backend
	if f.rule.GroupID != "" {
		if f.bal == nil {
			logger.L.Warn("upstream group balancer missing", zap.String("rule", f.rule.Name), zap.String("group", f.rule.GroupID))
			return nil
		}
		be = f.bal.pick(srcAddr.IP)
		if be == nil {
			logger.L.Warn("no eligible backend in upstream group", zap.String("rule", f.rule.Name), zap.String("group", f.rule.GroupID), zap.String("client", srcAddr.String()))
			return nil
		}
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", be.addr, be.port))
		if err != nil {
			logger.L.Warn("UDP backend address invalid", zap.String("backend", be.key), zap.Error(err))
			return nil
		}
		target = addr
	}

	up, err := net.DialUDP("udp", nil, target)
	if err != nil {
		logger.L.Warn("UDP dial failed", zap.String("target", target.String()), zap.Error(err))
		return nil
	}

	f.mu.Lock()
	if sess, ok := f.sessions[key]; ok {
		sess.lastSeen = now
		f.mu.Unlock()
		_ = up.Close()
		return sess
	}
	if f.isStopping() {
		f.mu.Unlock()
		_ = up.Close()
		return nil
	}
	// Authoritative cap check: a concurrent creator may have filled the
	// quota between the early check and this insert.
	if !f.allowSessionLocked(key) {
		f.mu.Unlock()
		_ = up.Close()
		f.noteCapDrop(srcAddr)
		return nil
	}
	sess := &udpSession{upstream: up, lastSeen: now, backend: be}
	f.sessions[key] = sess
	f.perIP[key.ip]++
	f.active.Add(1)
	f.totalConns.Add(1)
	if be != nil {
		f.bal.connOpened(be)
	}
	f.wg.Add(1)
	go f.relayBack(cloneUDPAddr(srcAddr), sess)
	f.mu.Unlock()
	return sess
}

// allowSessionLocked 判断是否还能为 key 创建一个新会话（全局与每源 IP 上限）。
// 调用方需持有 f.mu。
// allowSessionLocked reports whether one more session for key fits within
// the global and per-source-IP caps. Caller must hold f.mu.
func (f *UDPForwarder) allowSessionLocked(key udpAddrKey) bool {
	if len(f.sessions) >= f.maxSessions {
		return false
	}
	if f.perIP[key.ip] >= f.maxPerIP {
		return false
	}
	return true
}

// decPerIPLocked 将该源 IP 的会话计数减一。调用方需持有 f.mu。
// decPerIPLocked drops one from the source-IP session count. Caller holds f.mu.
func (f *UDPForwarder) decPerIPLocked(k udpAddrKey) {
	if c, ok := f.perIP[k.ip]; ok {
		if c <= 1 {
			delete(f.perIP, k.ip)
		} else {
			f.perIP[k.ip] = c - 1
		}
	}
}

// noteCapDrop 记录一个因会话达到上限而被丢弃的数据报（限流聚合日志）。
// noteCapDrop records a datagram dropped because a session cap was reached
// (rate-limited aggregated log; the drop counter is informational).
func (f *UDPForwarder) noteCapDrop(srcAddr *net.UDPAddr) {
	total := f.capDrops.Add(1)
	f.capLog.note("udp sessions at cap, dropping datagrams | UDP 会话数达到上限，丢弃数据包",
		f.rule.Name, "udp", ipfilter.AddrFromNetAddr(srcAddr), total)
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := *addr
	if addr.IP != nil {
		clone.IP = append(net.IP(nil), addr.IP...)
	}
	return &clone
}

func (f *UDPForwarder) isStopping() bool {
	select {
	case <-f.stopCh:
		return true
	default:
		return false
	}
}
