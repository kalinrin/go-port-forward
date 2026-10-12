//go:build !linux

package forward

import "io"

// spliceCopy 在无 splice(2) 的平台上返回未处理，回退到池化缓冲的计数拷贝路径。
// spliceCopy is a no-op on platforms without splice(2); the pooled-buffer
// counting path is used instead.
func spliceCopy(dst io.Writer, src io.Reader) (n int64, handled bool) {
	return 0, false
}
