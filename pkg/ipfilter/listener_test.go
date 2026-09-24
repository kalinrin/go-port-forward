package ipfilter

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWrapListenerNilFilter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	require.Equal(t, ln, WrapListener(ln, nil, nil))
}

func TestWrapListenerBlocked(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	f, err := New(Config{Mode: ModeAllowlist, CIDRs: []string{"203.0.113.0/24"}})
	require.NoError(t, err)

	blockedCh := make(chan netip.Addr, 1)
	wrapped := WrapListener(ln, f, func(ip netip.Addr) { blockedCh <- ip })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := wrapped.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close()

	// 被拦截的连接立即关闭，客户端读取很快失败。
	// Blocked connections are closed immediately; the client read fails fast.
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = client.Read(make([]byte, 1))
	require.Error(t, err)

	select {
	case ip := <-blockedCh:
		require.True(t, ip.IsLoopback(), ip.String())
	case <-time.After(2 * time.Second):
		t.Fatal("onBlock not invoked")
	}

	// Accept 不会把被拦截的连接交给上层。
	// Accept must not hand blocked connections to upper layers.
	select {
	case c := <-accepted:
		_ = c.Close()
		t.Fatal("blocked connection was returned by Accept")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestWrapListenerAllowed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	f, err := New(Config{Mode: ModeAllowlist, CIDRs: []string{"127.0.0.0/8"}})
	require.NoError(t, err)

	wrapped := WrapListener(ln, f, func(netip.Addr) { t.Error("onBlock must not be invoked") })
	defer wrapped.Close()

	go func() {
		c, err := wrapped.Accept()
		if err == nil {
			_, _ = c.Write([]byte("ok"))
			_ = c.Close()
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2)
	_, err = io.ReadFull(client, buf)
	require.NoError(t, err)
	require.Equal(t, "ok", string(buf))
}

func TestWrapPacketConnBlocked(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()

	f, err := New(Config{Mode: ModeBlocklist, CIDRs: []string{"127.0.0.0/8"}})
	require.NoError(t, err)

	blockedCh := make(chan netip.Addr, 1)
	wrapped := WrapPacketConn(pc, f, func(ip netip.Addr) { blockedCh <- ip })

	sender, err := net.Dial("udp", pc.LocalAddr().String())
	require.NoError(t, err)
	defer sender.Close()
	_, err = sender.Write([]byte("x"))
	require.NoError(t, err)

	// 被拦截的报文被丢弃：ReadFrom 一直阻塞到超时。
	// Blocked datagrams are dropped: ReadFrom blocks until the deadline.
	require.NoError(t, wrapped.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	_, _, err = wrapped.ReadFrom(make([]byte, 16))
	require.Error(t, err)
	var ne net.Error
	require.ErrorAs(t, err, &ne)
	require.True(t, ne.Timeout())

	select {
	case ip := <-blockedCh:
		require.True(t, ip.IsLoopback(), ip.String())
	case <-time.After(time.Second):
		t.Fatal("onBlock not invoked")
	}
}

func TestWrapPacketConnAllowed(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()

	f, err := New(Config{Mode: ModeBlocklist, CIDRs: []string{"203.0.113.0/24"}})
	require.NoError(t, err)

	wrapped := WrapPacketConn(pc, f, func(netip.Addr) { t.Error("onBlock must not be invoked") })

	sender, err := net.Dial("udp", pc.LocalAddr().String())
	require.NoError(t, err)
	defer sender.Close()
	_, err = sender.Write([]byte("x"))
	require.NoError(t, err)

	require.NoError(t, wrapped.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 16)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "x", string(buf[:n]))
}
