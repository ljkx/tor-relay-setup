package system

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Real /proc/net/tcp and tcp6 excerpts: sshd on 22 (0016) and tor on 9001
// (2329) listening, plus an established connection from local port 443.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18342 1 0000000000000000 100 0 0 10 0
   1: 0500710B:2329 00000000:0000 0A 00000000:00000000 00:00000000 00000000   108        0 25711 1 0000000000000000 100 0 0 10 0
   2: 0500710B:01BB 0100A8C0:D431 01 00000000:00000000 02:0009BD2F 00000000   108        0 29873 2 0000000000000000 20 4 30 10 -1
`

const procNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18344 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000500710B:1F90 0000000000000000FFFF00000100A8C0:C350 01 00000000:00000000 00:00000000 00000000    33        0 30011 1 0000000000000000 20 4 29 10 -1
`

func TestParseProcNetTCP(t *testing.T) {
	tests := []struct {
		name string
		data string
		port int
		want bool
	}{
		{"ipv4 ssh listen", procNetTCP, 22, true},
		{"ipv4 orport listen", procNetTCP, 9001, true},
		{"ipv4 established only", procNetTCP, 443, false},
		{"ipv4 remote port is not local", procNetTCP, 54321, false},
		{"ipv4 absent", procNetTCP, 9030, false},
		{"ipv6 ssh listen", procNetTCP6, 22, true},
		{"ipv6 established only", procNetTCP6, 8080, false},
		{"ipv6 absent", procNetTCP6, 9001, false},
		{"empty", "", 22, false},
		{"garbage", "a b c 0A\nx:zz y 0A\n", 22, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseProcNetTCP([]byte(tt.data), tt.port); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestListening(t *testing.T) {
	f := host.NewFake()
	f.Files["/proc/net/tcp"] = []byte(procNetTCP)
	f.Files["/proc/net/tcp6"] = []byte(procNetTCP6)

	tests := []struct {
		port   int
		v4, v6 bool
	}{
		{22, true, true},
		{9001, true, false},
		{8080, false, false},
	}
	for _, tt := range tests {
		v4, v6, err := Listening(f, tt.port)
		if err != nil || v4 != tt.v4 || v6 != tt.v6 {
			t.Errorf("Listening(%d) = %v, %v, %v; want %v, %v", tt.port, v4, v6, err, tt.v4, tt.v6)
		}
	}

	delete(f.Files, "/proc/net/tcp6") // IPv6 disabled
	if v4, v6, err := Listening(f, 9001); err != nil || !v4 || v6 {
		t.Errorf("without tcp6: %v %v %v", v4, v6, err)
	}
	if _, _, err := Listening(host.NewFake(), 9001); err == nil {
		t.Error("want error when no table is readable")
	}
}

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

func TestCheckIPv6Outbound(t *testing.T) {
	tests := []struct {
		name string
		ok   func(addr string) bool
		want int
	}{
		{"all", func(string) bool { return true }, 5},
		{"none", func(string) bool { return false }, 0},
		{"maatuska only", func(a string) bool { return a == "[2001:67c:289c::9]:80" }, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var addrs []string
			dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network != "tcp6" {
					t.Errorf("network = %q", network)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Error("dial without deadline")
				}
				mu.Lock()
				addrs = append(addrs, addr)
				mu.Unlock()
				if tt.ok(addr) {
					return fakeConn{}, nil
				}
				return nil, errors.New("unreachable")
			}
			n, total := CheckIPv6Outbound(context.Background(), dial)
			if n != tt.want || total != 5 {
				t.Errorf("got %d/%d, want %d/5", n, total, tt.want)
			}
			slices.Sort(addrs)
			want := []string{
				"[2001:638:a000:4140::ffff:189]:443",
				"[2001:678:558:1000::244]:443",
				"[2001:67c:289c::9]:80",
				"[2620:13:4000:6000::1000:118]:443",
				"[2a02:16a8:662:2203::1]:443",
			}
			if !slices.Equal(addrs, want) {
				t.Errorf("dialled %q", addrs)
			}
		})
	}
}

func TestCheckIPv6OutboundConcurrentAndCancellable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		<-ctx.Done() // every authority hangs
		return nil, ctx.Err()
	}
	start := time.Now()
	n, _ := CheckIPv6Outbound(ctx, dial)
	if n != 0 {
		t.Errorf("reachable = %d", n)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v; dials must run concurrently and honour ctx", d)
	}
}
