package forward

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"go-port-forward/internal/logger"
	"go-port-forward/internal/models"

	"go.uber.org/zap"
)

func TestTCPForwarderStopClosesActiveConnections(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	rule := &models.ForwardRule{
		Name:       "tcp-stop",
		ListenAddr: "127.0.0.1",
		ListenPort: 0,
		TargetAddr: "127.0.0.1",
		TargetPort: targetLn.Addr().(*net.TCPAddr).Port,
	}
	fwd := newTCPForwarder(rule, 1, 4096)
	if err := fwd.Start(); err != nil {
		t.Fatalf("start tcp forwarder: %v", err)
	}

	client, err := net.Dial("tcp", fwd.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer client.Close()

	var upstream net.Conn
	select {
	case upstream = <-accepted:
		defer upstream.Close()
	case <-time.After(2 * time.Second):
		fwd.Stop()
		t.Fatal("timeout waiting for target accept")
	}

	stopped := make(chan struct{})
	go func() {
		fwd.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return promptly")
	}

	_, _, active, total := fwd.Stats()
	if active != 0 {
		t.Fatalf("active connections after stop = %d, want 0", active)
	}
	if total != 1 {
		t.Fatalf("total connections = %d, want 1", total)
	}

	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = client.Read(buf)
	if err == nil {
		t.Fatal("expected client read to fail after stop")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("client connection was not closed after stop: %v", err)
	}
	if !errors.Is(err, io.EOF) {
		_ = client.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
		if _, werr := client.Write([]byte("x")); werr == nil {
			t.Fatalf("expected client write to fail after stop, read err=%v", err)
		}
	}
}

func TestTCPForwarderSendsProxyProtocolHeader(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	// upstreamResult captures the header line and payload seen by the target.
	type upstreamResult struct {
		header  string
		payload string
	}
	got := make(chan upstreamResult, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the PROXY header line first, then the remaining payload.
		reader := bufio.NewReader(conn)
		header, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		payload, err := io.ReadAll(reader)
		if err != nil {
			return
		}
		got <- upstreamResult{header: header, payload: string(payload)}
	}()

	rule := &models.ForwardRule{
		Name:          "tcp-proxyproto",
		ListenAddr:    "127.0.0.1",
		ListenPort:    0,
		TargetAddr:    "127.0.0.1",
		TargetPort:    targetLn.Addr().(*net.TCPAddr).Port,
		ProxyProtocol: true,
	}
	fwd := newTCPForwarder(rule, 1, 4096)
	if err := fwd.Start(); err != nil {
		t.Fatalf("start tcp forwarder: %v", err)
	}
	defer fwd.Stop()

	client, err := net.Dial("tcp", fwd.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	clientLocal := client.LocalAddr().(*net.TCPAddr)
	listenPort := fwd.listener.Addr().(*net.TCPAddr).Port
	wantHeader := fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n",
		clientLocal.IP.String(), "127.0.0.1", clientLocal.Port, listenPort)

	select {
	case res := <-got:
		if res.header != wantHeader {
			t.Fatalf("header = %q, want %q", res.header, wantHeader)
		}
		if res.payload != "hello" {
			t.Fatalf("payload = %q, want %q", res.payload, "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for upstream result")
	}
}

func TestTCPForwarderOmitsProxyProtocolHeaderWhenDisabled(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	got := make(chan string, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		payload, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		got <- string(payload)
	}()

	rule := &models.ForwardRule{
		Name:       "tcp-plain",
		ListenAddr: "127.0.0.1",
		ListenPort: 0,
		TargetAddr: "127.0.0.1",
		TargetPort: targetLn.Addr().(*net.TCPAddr).Port,
	}
	fwd := newTCPForwarder(rule, 1, 4096)
	if err := fwd.Start(); err != nil {
		t.Fatalf("start tcp forwarder: %v", err)
	}
	defer fwd.Stop()

	client, err := net.Dial("tcp", fwd.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	select {
	case payload := <-got:
		if payload != "hello" {
			t.Fatalf("payload = %q, want %q (no PROXY header expected)", payload, "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for upstream payload")
	}
}

func TestUDPForwarderCleanupExpiresSessions(t *testing.T) {
	logger.L = zap.NewNop()
	logger.S = logger.L.Sugar()

	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp target: %v", err)
	}
	defer targetConn.Close()

	stopEcho := make(chan struct{})
	go udpEchoLoop(targetConn, stopEcho)
	defer close(stopEcho)

	rule := &models.ForwardRule{
		Name:       "udp-cleanup",
		ListenAddr: "127.0.0.1",
		ListenPort: 0,
		TargetAddr: "127.0.0.1",
		TargetPort: targetConn.LocalAddr().(*net.UDPAddr).Port,
	}
	fwd := newUDPForwarder(rule, 1)
	if err := fwd.Start(); err != nil {
		t.Fatalf("start udp forwarder: %v", err)
	}
	defer fwd.Stop()

	client, err := net.DialUDP("udp", nil, fwd.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp forwarder: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write udp packet: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read udp echo: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("unexpected udp echo %q", string(buf[:n]))
	}

	waitFor(t, 2*time.Second, func() bool {
		_, _, active, total := fwd.Stats()
		return active == 1 && total == 1
	})

	waitFor(t, 3*time.Second, func() bool {
		_, _, active, _ := fwd.Stats()
		return active == 0
	})
}

func TestMakeUDPAddrKeyIncludesZone(t *testing.T) {
	baseIP := net.ParseIP("fe80::1")
	if baseIP == nil {
		t.Fatal("parse ipv6 failed")
	}

	keyA := makeUDPAddrKey(&net.UDPAddr{IP: baseIP, Port: 5353, Zone: "eth0"})
	keyB := makeUDPAddrKey(&net.UDPAddr{IP: baseIP, Port: 5353, Zone: "eth1"})
	keyC := makeUDPAddrKey(&net.UDPAddr{IP: baseIP, Port: 5353, Zone: "eth0"})

	if keyA == keyB {
		t.Fatal("different zones must produce different session keys")
	}
	if keyA != keyC {
		t.Fatal("same zone must produce same session key")
	}
}

func udpEchoLoop(conn *net.UDPConn, stop <-chan struct{}) {
	buf := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				select {
				case <-stop:
					return
				default:
					continue
				}
			}
			return
		}
		_, _ = conn.WriteToUDP(buf[:n], addr)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition not satisfied before timeout")
}
