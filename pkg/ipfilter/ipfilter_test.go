package ipfilter

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustFilter(t *testing.T, cfg Config) *Filter {
	t.Helper()
	f, err := New(cfg)
	require.NoError(t, err)
	return f
}

func TestParseCIDR(t *testing.T) {
	p, err := ParseCIDR("203.0.113.0/24")
	require.NoError(t, err)
	require.Equal(t, "203.0.113.0/24", p.String())

	// 未按掩码对齐的输入会被归一化 | unmasked input is normalized
	p, err = ParseCIDR(" 203.0.113.7/24 ")
	require.NoError(t, err)
	require.Equal(t, "203.0.113.0/24", p.String())

	// 裸 IPv4 → 主机前缀 | bare IPv4 → host prefix
	p, err = ParseCIDR("203.0.113.9")
	require.NoError(t, err)
	require.Equal(t, "203.0.113.9/32", p.String())

	// 裸 IPv6 → 主机前缀 | bare IPv6 → host prefix
	p, err = ParseCIDR("2001:db8::1")
	require.NoError(t, err)
	require.Equal(t, "2001:db8::1/128", p.String())

	_, err = ParseCIDR("")
	require.Error(t, err)

	_, err = ParseCIDR("not-an-ip")
	require.Error(t, err)
}

func TestNewRejectsEmptyList(t *testing.T) {
	_, err := New(Config{})
	require.Error(t, err)
}

func TestNewRejectsUnknownMode(t *testing.T) {
	_, err := New(Config{Mode: "foo", CIDRs: []string{"203.0.113.0/24"}})
	require.Error(t, err)
}

func TestNewRejectsBadEntry(t *testing.T) {
	_, err := New(Config{CIDRs: []string{"203.0.113.0/24", "bad-entry"}})
	require.Error(t, err)
}

func TestAllowlist(t *testing.T) {
	f := mustFilter(t, Config{
		Mode:  ModeAllowlist,
		CIDRs: []string{"203.0.113.0/24", "2001:db8::/32"},
	})
	require.True(t, f.Allow(netip.MustParseAddr("203.0.113.5")))
	require.False(t, f.Allow(netip.MustParseAddr("198.51.100.1")))
	require.True(t, f.Allow(netip.MustParseAddr("2001:db8::1")))
	require.False(t, f.Allow(netip.MustParseAddr("2001:db9::1")))
	// 未识别地址在白名单模式下拒绝 | unidentified address denied in allowlist mode
	require.False(t, f.Allow(netip.Addr{}))
}

func TestBlocklist(t *testing.T) {
	f := mustFilter(t, Config{
		Mode:  ModeBlocklist,
		CIDRs: []string{"203.0.113.0/24"},
	})
	require.False(t, f.Allow(netip.MustParseAddr("203.0.113.5")))
	require.True(t, f.Allow(netip.MustParseAddr("198.51.100.1")))
	// 未识别地址在黑名单模式下放行 | unidentified address allowed in blocklist mode
	require.True(t, f.Allow(netip.Addr{}))
}

func TestAllowPrivate(t *testing.T) {
	priv := mustFilter(t, Config{
		Mode:         ModeAllowlist,
		CIDRs:        []string{"203.0.113.0/24"},
		AllowPrivate: true,
	})
	for _, s := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "fd00::1", "::1"} {
		require.True(t, priv.Allow(netip.MustParseAddr(s)), s)
	}
	require.False(t, priv.Allow(netip.MustParseAddr("198.51.100.1")))

	noPriv := mustFilter(t, Config{
		Mode:  ModeAllowlist,
		CIDRs: []string{"203.0.113.0/24"},
	})
	require.False(t, noPriv.Allow(netip.MustParseAddr("192.168.1.1")))
	require.True(t, noPriv.Allow(netip.MustParseAddr("203.0.113.5")))
}

func TestMappedIPv4(t *testing.T) {
	f := mustFilter(t, Config{
		Mode:  ModeAllowlist,
		CIDRs: []string{"203.0.113.0/24"},
	})
	// IPv4-mapped IPv6 与 IPv4 命中同一条规则 | IPv4-mapped IPv6 hits the same rule as IPv4
	require.True(t, f.Allow(netip.MustParseAddr("::ffff:203.0.113.9")))
	require.True(t, f.AllowAddr(&net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.9"), Port: 12345}))
	require.False(t, f.Allow(netip.MustParseAddr("::ffff:198.51.100.9")))
}

func TestMappedPrefixEntry(t *testing.T) {
	// ::ffff:203.0.113.0/120 等价于 203.0.113.0/24 | equivalent to 203.0.113.0/24
	f := mustFilter(t, Config{
		Mode:  ModeAllowlist,
		CIDRs: []string{"::ffff:203.0.113.0/120"},
	})
	require.True(t, f.Allow(netip.MustParseAddr("203.0.113.9")))
	require.False(t, f.Allow(netip.MustParseAddr("203.0.114.9")))
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	content := `# chnroute 样例 | sample list
203.0.113.0/24

198.51.100.0/25 # 行内注释 | inline comment
192.0.2.1
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	f := mustFilter(t, Config{Mode: ModeAllowlist, File: path})
	require.Equal(t, 3, f.Len())
	require.True(t, f.Allow(netip.MustParseAddr("198.51.100.100")))
	require.False(t, f.Allow(netip.MustParseAddr("198.51.100.200")))
	require.True(t, f.Allow(netip.MustParseAddr("192.0.2.1")))
}

func TestLoadFileFailsOnBadLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	require.NoError(t, os.WriteFile(path, []byte("203.0.113.0/24\noops\n"), 0o644))
	_, err := New(Config{Mode: ModeAllowlist, File: path})
	require.Error(t, err)
	require.Contains(t, err.Error(), ":2")
}

func TestLoadFileMissing(t *testing.T) {
	_, err := New(Config{Mode: ModeAllowlist, File: filepath.Join(t.TempDir(), "nope.txt")})
	require.Error(t, err)
}

func TestNilFilterAllowsEverything(t *testing.T) {
	var f *Filter
	require.True(t, f.Allow(netip.MustParseAddr("198.51.100.1")))
	require.True(t, f.AllowAddr(&net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1}))
	require.Equal(t, 0, f.Len())
}

func TestAddrFromNetAddr(t *testing.T) {
	// net.ParseIP 对 IPv4 也返回 16 字节（IPv4-mapped 形式），因此提取结果是
	// Is4In6 地址，与 Is4 地址的内部表示不同，Unmap 后必须相等。
	//（Filter.Allow 内部会先 Unmap，故功能不受表示形式影响。）
	// net.ParseIP returns a 16-byte (IPv4-mapped) slice even for IPv4, so the
	// extracted address is Is4In6; its internal representation differs from an
	// Is4 address, and they must be equal after Unmap. (Filter.Allow unmaps
	// internally, so behavior is unaffected by the representation.)
	ip := AddrFromNetAddr(&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 80})
	require.True(t, ip.Is4In6())
	require.Equal(t, netip.MustParseAddr("203.0.113.7"), ip.Unmap())

	ip = AddrFromNetAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53})
	require.Equal(t, netip.MustParseAddr("2001:db8::1"), ip)

	require.Equal(t, netip.Addr{}, AddrFromNetAddr(nil))
}
