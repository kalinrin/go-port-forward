//go:build linux

package forward

import (
	"io"
	"net"
)

// spliceCopy 将两端均为裸 TCP 连接的拷贝委托给 TCPConn.ReadFrom。
// 在 Linux 上这会走 splice(2) 快速路径：数据在两个 socket 之间完全于内核态
// 移动（无用户态缓冲、无逐块 read/write 系统调用），同时 ReadFrom 仍返回
// 精确的字节数，流量统计不受影响。
// spliceCopy delegates the copy to TCPConn.ReadFrom when both ends are raw
// TCP connections. On Linux this takes the splice(2) fast path: data moves
// between the two sockets entirely in kernel space (no user-space buffer, no
// per-chunk read/write syscalls) while ReadFrom still reports the exact
// number of bytes copied, so traffic stats remain accurate.
func spliceCopy(dst io.Writer, src io.Reader) (n int64, handled bool) {
	dstTCP, ok := dst.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	if _, ok := src.(*net.TCPConn); !ok {
		return 0, false
	}
	n, err := dstTCP.ReadFrom(src)
	_ = err // 拷贝错误经由随后的半关闭/连接关闭暴露，与 io.Copy 行为一致
	// copy errors surface via the subsequent half-close/conn close, same as io.Copy
	return n, true
}
