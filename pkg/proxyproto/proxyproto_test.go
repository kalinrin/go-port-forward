package proxyproto

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestHeaderLine(t *testing.T) {
	mustIP := func(s string) net.IP {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("parse ip %q failed", s)
		}
		return ip
	}

	tests := []struct {
		name string
		src  net.Addr
		dst  net.Addr
		want string
	}{
		{
			name: "tcp4",
			src:  &net.TCPAddr{IP: mustIP("192.0.2.1"), Port: 54321},
			dst:  &net.TCPAddr{IP: mustIP("198.51.100.2"), Port: 80},
			want: "PROXY TCP4 192.0.2.1 198.51.100.2 54321 80\r\n",
		},
		{
			name: "v4-mapped ipv6 renders as tcp4",
			src:  &net.TCPAddr{IP: mustIP("::ffff:192.0.2.100"), Port: 443},
			dst:  &net.TCPAddr{IP: mustIP("::ffff:198.51.100.1"), Port: 8443},
			want: "PROXY TCP4 192.0.2.100 198.51.100.1 443 8443\r\n",
		},
		{
			name: "tcp6",
			src:  &net.TCPAddr{IP: mustIP("2001:db8::1"), Port: 54321},
			dst:  &net.TCPAddr{IP: mustIP("2001:db8::2"), Port: 80},
			want: "PROXY TCP6 2001:db8::1 2001:db8::2 54321 80\r\n",
		},
		{
			name: "mixed family falls back to unknown",
			src:  &net.TCPAddr{IP: mustIP("192.0.2.1"), Port: 54321},
			dst:  &net.TCPAddr{IP: mustIP("2001:db8::2"), Port: 80},
			want: "PROXY UNKNOWN\r\n",
		},
		{
			name: "missing ip falls back to unknown",
			src:  &net.TCPAddr{Port: 54321},
			dst:  &net.TCPAddr{IP: mustIP("198.51.100.2"), Port: 80},
			want: "PROXY UNKNOWN\r\n",
		},
		{
			name: "non-tcp addr falls back to unknown",
			src:  &net.UDPAddr{IP: mustIP("192.0.2.1"), Port: 54321},
			dst:  &net.TCPAddr{IP: mustIP("198.51.100.2"), Port: 80},
			want: "PROXY UNKNOWN\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(headerLine(tt.src, tt.dst))
			if got != tt.want {
				t.Fatalf("header = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteHeaderWritesLine(t *testing.T) {
	var buf bytes.Buffer
	src := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 80}

	if err := WriteHeader(&buf, src, dst); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if got, want := buf.String(), "PROXY TCP4 192.0.2.1 198.51.100.2 54321 80\r\n"; got != want {
		t.Fatalf("written = %q, want %q", got, want)
	}
}

func TestWriteHeaderPropagatesWriteError(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 80}

	want := errors.New("boom")
	err := WriteHeader(errWriter{want}, src, dst)
	if !errors.Is(err, want) {
		t.Fatalf("WriteHeader error = %v, want %v", err, want)
	}
}

func TestWriteHeaderRejectsNilWriter(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 80}
	if err := WriteHeader(nil, src, dst); err == nil {
		t.Fatal("expected error for nil writer")
	}
}

// errWriter 总是返回固定错误的 io.Writer。
// errWriter is an io.Writer that always returns a fixed error.
type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }
