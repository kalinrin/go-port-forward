package ipfilter

import (
	"net"
	"net/netip"
)

// listener 包装 net.Listener，在 Accept 阶段丢弃被过滤的连接：
// 被拒绝的连接立即关闭（对端收到 RST/FIN，快速失败），对上层透明。
// listener wraps a net.Listener and drops filtered connections at Accept
// time: rejected connections are closed immediately (the peer sees
// RST/FIN and fails fast), transparently to upper layers.
type listener struct {
	net.Listener
	filter  *Filter
	onBlock func(netip.Addr)
}

// WrapListener 用过滤器包装 l；f 为 nil 时原样返回 l。
// onBlock 在每次拦截后回调（可为 nil），用于计数与限流日志。
// WrapListener wraps l with the filter; a nil f returns l unchanged.
// onBlock (maybe nil) is invoked after each block, for counting and
// rate-limited logging.
func WrapListener(l net.Listener, f *Filter, onBlock func(netip.Addr)) net.Listener {
	if f == nil {
		return l
	}
	return &listener{Listener: l, filter: f, onBlock: onBlock}
}

// Accept 循环取连接，直到拿到一条被放行的连接或底层 Accept 出错。
// Accept loops until an allowed connection arrives or the underlying
// Accept fails.
func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := AddrFromNetAddr(c.RemoteAddr())
		if l.filter.Allow(ip) {
			return c, nil
		}
		_ = c.Close()
		if l.onBlock != nil {
			l.onBlock(ip)
		}
	}
}

// packetConn 包装 net.PacketConn，在 ReadFrom 阶段按源地址丢包。
// packetConn wraps a net.PacketConn and drops datagrams from filtered
// sources at ReadFrom time.
type packetConn struct {
	net.PacketConn
	filter  *Filter
	onBlock func(netip.Addr)
}

// WrapPacketConn 用过滤器包装 pc；f 为 nil 时原样返回 pc。
// WrapPacketConn wraps pc with the filter; a nil f returns pc unchanged.
func WrapPacketConn(pc net.PacketConn, f *Filter, onBlock func(netip.Addr)) net.PacketConn {
	if f == nil {
		return pc
	}
	return &packetConn{PacketConn: pc, filter: f, onBlock: onBlock}
}

// ReadFrom 循环读取，直到拿到一个被放行的报文或底层 ReadFrom 出错；
// 被拦截的报文直接丢弃，对上层不可见。
// ReadFrom loops until an allowed datagram arrives or the underlying
// ReadFrom fails; blocked datagrams are dropped invisibly to upper layers.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		ip := AddrFromNetAddr(addr)
		if p.filter.Allow(ip) {
			return n, addr, nil
		}
		if p.onBlock != nil {
			p.onBlock(ip)
		}
	}
}
