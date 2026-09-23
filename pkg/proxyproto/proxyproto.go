// Package proxyproto 实现 PROXY protocol v1 头部的生成与写入，
// 用于四层转发器向目标传递连接的真实源地址。
// Package proxyproto implements PROXY protocol v1 header generation and
// writing, used by L4 forwarders to pass the real client address to targets.
//
// 规范参考（HAProxy）：
// Specification reference (HAProxy):
// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
package proxyproto

import (
	"fmt"
	"io"
	"net"
)

// unknownLine 无法确定地址族时发送的头部行；
// 符合规范的接收端将忽略此行并使用连接的实际地址。
// unknownLine is the header line sent when the address family cannot be
// determined; compliant receivers ignore it and fall back to the
// connection's actual address.
var unknownLine = []byte("PROXY UNKNOWN\r\n")

// WriteHeader 向 w 写入一条 PROXY protocol v1 头部，描述原始连接 src → dst。
// src 为真实客户端地址（客户端侧 RemoteAddr），
// dst 为客户端连入的本地地址（客户端侧 LocalAddr）。
// WriteHeader writes a PROXY protocol v1 header to w describing the
// original connection src → dst.
// src is the real client address (client-side RemoteAddr) and dst is the
// local address the client connected to (client-side LocalAddr).
//
// 仅描述 TCP 地址；非 TCP 地址或地址族不一致时写入 "PROXY UNKNOWN" 行。
// Only TCP addresses are described; non-TCP addresses or mismatched
// families produce a "PROXY UNKNOWN" line.
func WriteHeader(w io.Writer, src, dst net.Addr) error {
	if w == nil {
		return fmt.Errorf("proxyproto: nil writer")
	}
	_, err := w.Write(headerLine(src, dst))
	return err
}

// headerLine 构造完整的头部行（含 CRLF）。
// headerLine builds the complete header line (including CRLF).
func headerLine(src, dst net.Addr) []byte {
	srcTCP, srcOK := src.(*net.TCPAddr)
	dstTCP, dstOK := dst.(*net.TCPAddr)
	if !srcOK || !dstOK {
		return unknownLine
	}
	return tcpHeader(srcTCP, dstTCP)
}

// tcpHeader 构造 TCP 连接的头部行。
// IPv4-mapped IPv6 地址按规范渲染为 IPv4 点分形式。
// tcpHeader builds the header line for a TCP connection.
// IPv4-mapped IPv6 addresses are rendered as IPv4 dotted form per spec.
func tcpHeader(src, dst *net.TCPAddr) []byte {
	srcIP4, dstIP4 := src.IP.To4(), dst.IP.To4()
	switch {
	case srcIP4 != nil && dstIP4 != nil:
		return fmt.Appendf(nil, "PROXY TCP4 %s %s %d %d\r\n",
			srcIP4, dstIP4, src.Port, dst.Port)
	case srcIP4 == nil && dstIP4 == nil && src.IP.To16() != nil && dst.IP.To16() != nil:
		return fmt.Appendf(nil, "PROXY TCP6 %s %s %d %d\r\n",
			src.IP, dst.IP, src.Port, dst.Port)
	default:
		// 地址族不一致（一端 IPv4、一端 IPv6）或地址缺失，无法如实描述。
		// Mismatched families (one IPv4, one IPv6) or missing addresses
		// cannot be described faithfully.
		return unknownLine
	}
}
