// Package ipfilter 提供基于 CIDR 名单的全局 IP 访问过滤，
// 用于在四层转发器接受连接（或读取 UDP 报文）时尽早丢弃不受信的流量。
// Package ipfilter provides global CIDR-list-based IP access filtering,
// allowing L4 forwarders to drop untrusted traffic as early as possible
// when accepting connections (or reading UDP datagrams).
//
// 支持白名单（allowlist，仅放行名单内地址）与黑名单（blocklist，仅拦截
// 名单内地址）两种模式；名单可来自配置内联条目或外部文件（每行一个
// CIDR，支持 # 注释，兼容 chnroute 等公开名单）。
// Both allowlist (only listed addresses pass) and blocklist (only listed
// addresses are dropped) modes are supported; entries may be inline in the
// configuration or loaded from an external file (one CIDR per line, '#'
// comments supported, compatible with public lists such as chnroute).
package ipfilter

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// Mode 是过滤模式。
// Mode is the filtering mode.
type Mode string

const (
	// ModeAllowlist 仅放行名单内的地址，其余全部拒绝。
	// ModeAllowlist only allows listed addresses; everything else is denied.
	ModeAllowlist Mode = "allowlist"
	// ModeBlocklist 仅拦截名单内的地址，其余全部放行。
	// ModeBlocklist only blocks listed addresses; everything else is allowed.
	ModeBlocklist Mode = "blocklist"
)

// Config 是过滤器的构建配置。
// Config is the builder configuration for a Filter.
type Config struct {
	// Mode 过滤模式，空值默认为 ModeAllowlist。
	// Mode is the filtering mode; empty defaults to ModeAllowlist.
	Mode Mode
	// CIDRs 内联 CIDR 条目。
	// CIDRs holds inline CIDR entries.
	CIDRs []string
	// File 外部名单文件路径（每行一个 CIDR，支持 # 注释）。
	// File is the path of an external list file (one CIDR per line,
	// '#' comments supported).
	File string
	// AllowPrivate 始终放行私网/环回/链路本地地址，
	// 防止内网健康检查与管理流量被误杀。
	// AllowPrivate always allows private/loopback/link-local addresses,
	// preventing internal health checks and management traffic from
	// being blocked accidentally.
	AllowPrivate bool
}

// Filter 编译后的 IP 过滤器，并发安全（构建完成后只读）。
// Filter is a compiled IP filter; it is safe for concurrent use
// (read-only after construction).
type Filter struct {
	mode         Mode
	allowPrivate bool
	root4        *node
	root6        *node
	prefixes     int
}

// node 是二进制前缀树的节点，按地址位逐位索引。
// node is a node of the binary prefix trie, indexed bit by bit.
type node struct {
	children [2]*node
	terminal bool
}

// New 按配置构建过滤器。名单为空时返回错误——空名单在两种模式下都没有
// 意义（白名单=全拒，黑名单=全放），失败快速暴露配置错误。
// New builds a Filter from cfg. An empty list is an error — it is
// meaningless in both modes (allowlist = deny all, blocklist = allow all),
// and failing fast surfaces misconfiguration.
func New(cfg Config) (*Filter, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeAllowlist
	}
	if mode != ModeAllowlist && mode != ModeBlocklist {
		return nil, fmt.Errorf("ipfilter: 未知模式 | unknown mode %q", cfg.Mode)
	}
	f := &Filter{mode: mode, allowPrivate: cfg.AllowPrivate}
	for _, c := range cfg.CIDRs {
		if err := f.add(c); err != nil {
			return nil, err
		}
	}
	if cfg.File != "" {
		if err := f.addFile(cfg.File); err != nil {
			return nil, err
		}
	}
	if f.prefixes == 0 {
		return nil, errors.New("ipfilter: CIDR 名单为空 | empty CIDR list")
	}
	return f, nil
}

// Len 返回已加载的前缀数量。
// Len returns the number of loaded prefixes.
func (f *Filter) Len() int {
	if f == nil {
		return 0
	}
	return f.prefixes
}

// Allow 判断 ip 是否被放行；nil 过滤器放行一切（等价于未启用）。
// Allow reports whether ip is allowed; a nil Filter allows everything
// (equivalent to disabled).
func (f *Filter) Allow(ip netip.Addr) bool {
	if f == nil {
		return true
	}
	ip = ip.Unmap()
	if !ip.IsValid() {
		// 无法识别的地址：白名单下拒绝，黑名单下放行。
		// Unidentifiable address: deny in allowlist mode, allow in blocklist mode.
		return f.mode != ModeAllowlist
	}
	if f.allowPrivate && isPrivateAddr(ip) {
		return true
	}
	var listed bool
	if ip.Is4() {
		listed = lookup(f.root4, ip)
	} else {
		listed = lookup(f.root6, ip)
	}
	if f.mode == ModeAllowlist {
		return listed
	}
	return !listed
}

// AllowAddr 判断 net.Addr（*net.TCPAddr / *net.UDPAddr 等）是否被放行。
// AllowAddr reports whether a net.Addr (*net.TCPAddr / *net.UDPAddr etc.)
// is allowed.
func (f *Filter) AllowAddr(addr net.Addr) bool {
	if f == nil {
		return true
	}
	return f.Allow(AddrFromNetAddr(addr))
}

// AddrFromNetAddr 从 net.Addr 提取 netip.Addr；提取失败返回零值 Addr。
// AddrFromNetAddr extracts a netip.Addr from a net.Addr; it returns the
// zero Addr when extraction fails.
func AddrFromNetAddr(addr net.Addr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip
	case *net.IPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		ip, _ := netip.ParseAddr(host)
		return ip
	}
	ip, _ := netip.ParseAddr(addr.String())
	return ip
}

// ParseCIDR 解析单条名单条目：支持 CIDR（"1.2.3.0/24"）与裸 IP
// （"1.2.3.4" 按主机前缀处理）。
// ParseCIDR parses a single list entry: either a CIDR ("1.2.3.0/24") or a
// bare IP ("1.2.3.4", treated as a host prefix).
func ParseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errors.New("ipfilter: 空条目 | empty entry")
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return normalize(p)
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("ipfilter: 无效的 CIDR 条目 | invalid CIDR entry %q", s)
}

// normalize 将 IPv4-mapped IPv6 前缀折算为 IPv4 前缀，
// 保证与 Unmap 后的查询地址走同一棵树。
// normalize converts an IPv4-mapped IPv6 prefix into an IPv4 prefix so it
// shares the same trie as Unmap'ed query addresses.
func normalize(p netip.Prefix) (netip.Prefix, error) {
	addr := p.Addr()
	bits := p.Bits()
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
		if bits < 0 {
			return netip.Prefix{}, fmt.Errorf("ipfilter: 无效的映射前缀 | invalid mapped prefix %s", p)
		}
		p = netip.PrefixFrom(addr, bits)
	}
	return p.Masked(), nil
}

// add 将单条条目插入前缀树。
// add inserts a single entry into the trie.
func (f *Filter) add(s string) error {
	p, err := ParseCIDR(s)
	if err != nil {
		return err
	}
	addr := p.Addr()
	if addr.Is4() {
		f.root4 = insert(f.root4, addr, p.Bits())
	} else {
		f.root6 = insert(f.root6, addr, p.Bits())
	}
	f.prefixes++
	return nil
}

// addFile 从文件加载名单（每行一个 CIDR，# 之后为注释）。
// 任一条目无效都会使整体加载失败，避免截断的名单悄悄生效。
// addFile loads entries from a file (one CIDR per line, '#' starts a
// comment). Any invalid entry fails the whole load so a truncated list
// never silently takes effect.
func (f *Filter) addFile(path string) error {
	fp, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("ipfilter: 打开名单文件失败 | open list file %s: %w", path, err)
	}
	defer fp.Close()
	sc := bufio.NewScanner(fp)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := stripComment(sc.Text())
		if line == "" {
			continue
		}
		if err := f.add(line); err != nil {
			return fmt.Errorf("ipfilter: %s:%d: %w", path, lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("ipfilter: 读取名单文件失败 | read list file %s: %w", path, err)
	}
	return nil
}

// stripComment 去掉 # 注释并修剪空白。
// stripComment removes the '#' comment and trims whitespace.
func stripComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// addrBytes 返回地址的原始字节（IPv4 为 4 字节、IPv6 为 16 字节），供按位遍历。
// addrBytes returns the raw address bytes (4 for IPv4, 16 for IPv6) for
// bitwise traversal.
func addrBytes(addr netip.Addr) []byte {
	if addr.Is4() {
		b4 := addr.As4()
		return b4[:]
	}
	b16 := addr.As16()
	return b16[:]
}

// bitAt 返回 b 的第 i 位（自最高位起数），取值为 0 或 1。
// bitAt returns the i-th bit of b, counted from the most significant bit;
// the result is 0 or 1.
func bitAt(b []byte, i int) uint8 {
	return b[i>>3] >> (7 - uint(i&7)) & 1
}

// insert 将 addr 的前 bits 位写入前缀树，返回（可能新建的）根。
// insert writes the first bits of addr into the trie and returns the
// (possibly newly created) root.
func insert(root *node, addr netip.Addr, bits int) *node {
	if root == nil {
		root = &node{}
	}
	cur := root
	b := addrBytes(addr)
	for i := 0; i < bits; i++ {
		bit := bitAt(b, i)
		if cur.children[bit] == nil {
			cur.children[bit] = &node{}
		}
		cur = cur.children[bit]
	}
	cur.terminal = true
	return root
}

// lookup 沿 addr 的位逐位下钻，命中任一 terminal 节点即为匹配。
// lookup walks the trie along the bits of addr; hitting any terminal node
// means a match.
func lookup(root *node, addr netip.Addr) bool {
	cur := root
	if cur == nil {
		return false
	}
	if cur.terminal {
		return true
	}
	b := addrBytes(addr)
	for i := 0; i < len(b)*8; i++ {
		cur = cur.children[bitAt(b, i)]
		if cur == nil {
			return false
		}
		if cur.terminal {
			return true
		}
	}
	return false
}

// isPrivateAddr 覆盖 RFC1918/ULA 私网、环回、链路本地与未指定地址。
// isPrivateAddr covers RFC1918/ULA private, loopback, link-local and
// unspecified addresses.
func isPrivateAddr(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}
