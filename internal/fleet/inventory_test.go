package fleet

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/config"
)

const baseConfig = `# the operator's comments survive when nothing is overridden
[relay]
nickname = "BaseRelay"
contact = "ops@example.org"
or_port = 9001
metrics_port = true

[bandwidth]
monthly_quota = "10TB"
`

// writeBase writes relay.toml into a fresh directory and returns it.
func writeBase(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "relay.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func parse(t *testing.T, inventory string) (Inventory, error) {
	t.Helper()
	return Parse([]byte(inventory), writeBase(t, baseConfig))
}

func TestParseMergesOverridesAndTemplates(t *testing.T) {
	inv, err := parse(t, `
config = "relay.toml"
parallel = 3
nickname = "Fleet{n}{host}"

[[host]]
address = "root@relay1.example.org"

[[host]]
address = "admin@relay2.example.org"
[host.relay]
ipv6 = "2001:db8::2"
[host.bandwidth]
monthly_quota = "20TB"

[[host]]
address = "203.0.113.7"
relay = { nickname = "Special", or_port = 443 }
`)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Parallel != 3 || inv.Nickname != "Fleet{n}{host}" || len(inv.Entries) != 3 {
		t.Fatalf("inventory = %+v", inv)
	}
	tests := []struct {
		nick, ipv6, quota string
		port              int
	}{
		{"Fleet1relay1", "", "10TB", 9001},
		{"Fleet2relay2", "2001:db8::2", "20TB", 9001},
		{"Special", "", "10TB", 443},
	}
	for i, tt := range tests {
		e := inv.Entries[i]
		s := e.Setup
		if e.Index != i+1 || e.Instance != DefaultInstance {
			t.Errorf("entry %d: index %d instance %q", i, e.Index, e.Instance)
		}
		if s.Relay.Nickname != tt.nick || s.Relay.IPv6 != tt.ipv6 || s.Bandwidth.MonthlyQuota != tt.quota || s.Relay.ORPort != tt.port {
			t.Errorf("entry %d: relay %+v bandwidth %+v", i, s.Relay, s.Bandwidth)
		}
		// Settings that nobody overrode come from the base config.
		if s.Relay.Contact != "ops@example.org" || !s.Relay.MetricsPort {
			t.Errorf("entry %d lost base settings: %+v", i, s.Relay)
		}
		// The uploaded config is what was validated.
		back, err := config.Parse(e.Config)
		if err != nil || !reflect.DeepEqual(back, s) {
			t.Errorf("entry %d: Config does not parse back to Setup: %v\n%s", i, err, e.Config)
		}
		if !strings.Contains(string(e.Config), "merged from the fleet inventory") {
			t.Errorf("entry %d: merged config lacks its header:\n%s", i, e.Config)
		}
	}
}

func TestParseKeepsTheBaseConfigByteForByte(t *testing.T) {
	inv, err := parse(t, "config = \"relay.toml\"\n[[host]]\naddress = \"relay1\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if string(inv.Entries[0].Config) != baseConfig {
		t.Errorf("an entry without overrides should get the base config unchanged:\n%s", inv.Entries[0].Config)
	}
	if inv.Parallel != 1 {
		t.Errorf("default parallel = %d, want 1", inv.Parallel)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name, inventory, want string
	}{
		{"unknown top-level key", "config = \"relay.toml\"\nparallell = 2\n[[host]]\naddress = \"a\"\n", "unknown inventory keys: parallell"},
		{"unknown relay key", "config = \"relay.toml\"\n[[host]]\naddress = \"a\"\n[host.relay]\nnickame = \"X\"\n", "host 1 (a): unknown config keys: relay.nickame"},
		{"unknown table", "config = \"relay.toml\"\n[[host]]\naddress = \"a\"\n[host.relays]\nnickname = \"X\"\n", "host 1 (a): unknown config keys: relays, relays.nickname"},
		{"scalar override", "config = \"relay.toml\"\n[[host]]\naddress = \"a\"\nnickname = \"X\"\n", "unknown config keys: nickname"},
		{"invalid override", "config = \"relay.toml\"\n[[host]]\naddress = \"a\"\nrelay = { nickname = \"bad name\" }\n", "host 1 (a): relay.nickname"},
		{"invalid template result", "config = \"relay.toml\"\nnickname = \"My-Relay{n}\"\n[[host]]\naddress = \"a\"\n", "relay.nickname"},
		{"missing address", "config = \"relay.toml\"\n[[host]]\nrelay = { or_port = 1 }\n", "host 1: address is required"},
		{"bad address", "config = \"relay.toml\"\n[[host]]\naddress = \"-oProxyCommand=sh\"\n", "not an ssh destination"},
		{"no config", "[[host]]\naddress = \"a\"\n", "config: set the base relay.toml"},
		{"missing config file", "config = \"absent.toml\"\n[[host]]\naddress = \"a\"\n", "base config"},
		{"no hosts", "config = \"relay.toml\"\n", "no [[host]] entries"},
		{"parallel too high", "config = \"relay.toml\"\nparallel = 65\n[[host]]\naddress = \"a\"\n", "parallel: must be 1–64"},
		{"broken TOML", "config = \n", "parse inventory"},
		{"duplicate nickname", "config = \"relay.toml\"\n[[host]]\naddress = \"a\"\n[[host]]\naddress = \"b\"\n", `nickname "BaseRelay" is used by host 1 (a) and host 2 (b)`},
		{"duplicate nickname, other case", "config = \"relay.toml\"\n[[host]]\naddress = \"a\"\nrelay = { nickname = \"x\" }\n[[host]]\naddress = \"b\"\nrelay = { nickname = \"X\" }\n", `nickname "X" is used by host 1 (a) and host 2 (b)`},
		{"same relay twice", "config = \"relay.toml\"\nnickname = \"R{n}\"\n[[host]]\naddress = \"a\"\n[[host]]\naddress = \"a\"\nrelay = { or_port = 9002 }\n", `host 1 (a) and host 2 (a) are the same relay (instance "default")`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parse(t, tt.inventory)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// entries builds relays by hand, as an inventory with relay.instance (a
// key of the multi-instance relay.toml) would.
func entries(specs ...[4]string) Inventory {
	var inv Inventory
	for i, s := range specs {
		e := Entry{Index: i + 1, Address: s[0], Instance: s[1], Setup: config.Default()}
		e.Setup.Relay.Nickname = s[2]
		e.Setup.Relay.ORPort = len(s[3]) * 1000 // ORPort by the length of the marker
		inv.Entries = append(inv.Entries, e)
	}
	return inv
}

func TestValidateServersWithSeveralRelays(t *testing.T) {
	ok := entries(
		[4]string{"root@a", "default", "One", "x"},
		[4]string{"root@a", "second", "Two", "xx"},
		[4]string{"root@b", "default", "Three", "x"},
	)
	if err := ok.validate(); err != nil {
		t.Errorf("distinct instances and ports on one server: %v", err)
	}
	tests := []struct {
		name string
		inv  Inventory
		want string
	}{
		{"same instance", entries([4]string{"a", "second", "One", "x"}, [4]string{"A", "second", "Two", "xx"}), `same relay (instance "second")`},
		{"same ORPort", entries([4]string{"a", "default", "One", "x"}, [4]string{"a", "second", "Two", "y"}), "both use ORPort 1000 on the same server"},
		{"same nickname", entries([4]string{"a", "default", "One", "x"}, [4]string{"b", "default", "one", "x"}), `nickname "one" is used by`},
	}
	for _, tt := range tests {
		if err := tt.inv.validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
	// Two relays of one server form one group, in inventory order.
	groups := ok.Servers()
	if len(groups) != 2 || len(groups[0]) != 2 || groups[0][1].Nickname() != "Two" || groups[1][0].Nickname() != "Three" {
		t.Errorf("Servers() = %+v", groups)
	}
	if got := ok.Addresses(); !reflect.DeepEqual(got, []string{"root@a", "root@b"}) {
		t.Errorf("Addresses() = %q", got)
	}
}

func TestMergeTablesIsGeneric(t *testing.T) {
	base := map[string]any{
		"relay":  map[string]any{"nickname": "A", "or_port": int64(9001)},
		"family": map[string]any{"keep_ids": []any{"x"}},
	}
	mergeTables(base, map[string]any{
		"relay":   map[string]any{"instance": "second", "or_port": int64(443)}, // a key this version does not know
		"family":  map[string]any{"keep_ids": []any{"y", "z"}},                 // arrays replace
		"newpart": map[string]any{"enabled": true},                             // a table this version does not know
	})
	want := map[string]any{
		"relay":   map[string]any{"nickname": "A", "or_port": int64(443), "instance": "second"},
		"family":  map[string]any{"keep_ids": []any{"y", "z"}},
		"newpart": map[string]any{"enabled": true},
	}
	if !reflect.DeepEqual(base, want) {
		t.Errorf("merged = %#v", base)
	}
	if got := instanceOf(base); got != "second" {
		t.Errorf("instanceOf = %q", got)
	}
	for _, m := range []map[string]any{{}, {"relay": "x"}, {"relay": map[string]any{"instance": ""}}, {"relay": map[string]any{"instance": 3}}} {
		if got := instanceOf(m); got != DefaultInstance {
			t.Errorf("instanceOf(%v) = %q", m, got)
		}
	}
}

func TestExpandNickname(t *testing.T) {
	tests := []struct {
		template, address string
		index             int
		want              string
	}{
		{"MyRelay{n}", "root@relay1.example.org", 3, "MyRelay3"},
		{"{host}", "root@relay-1.example.org", 1, "relay1"},
		{"Tor{host}{n}", "admin@203.0.113.7", 2, "Tor203011372"},
		{"Tor{host}", "[2001:db8::7]", 1, "Tor2001db87"},
		{"X{host}{n}", "averyveryverylonghostname.example.org", 12, "Xaveryveryverylon12"},
		{"{host}{host}", "abcdefghijklmnopqrstuvwxyz", 1, "abcdefghiabcdefghi"},
		{"Plain", "relay", 9, "Plain"},
	}
	for _, tt := range tests {
		got := ExpandNickname(tt.template, tt.index, tt.address)
		if got != tt.want {
			t.Errorf("ExpandNickname(%q, %d, %q) = %q, want %q", tt.template, tt.index, tt.address, got, tt.want)
		}
		if len(got) > 19 {
			t.Errorf("%q is longer than 19", got)
		}
	}
}

func TestOnly(t *testing.T) {
	inv := entries(
		[4]string{"root@relay1.example.org", "default", "One", "x"},
		[4]string{"relay2", "default", "Two", "x"},
		[4]string{"root@relay3.example.org", "default", "Three", "x"},
	)
	got, err := inv.Only([]string{"relay1.example.org", " two ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 || got.Entries[0].Nickname() != "One" || got.Entries[1].Nickname() != "Two" {
		t.Errorf("Only = %+v", got.Entries)
	}
	if got, _ := inv.Only([]string{"root@relay3.example.org"}); len(got.Entries) != 1 {
		t.Errorf("full address: %+v", got.Entries)
	}
	if _, err := inv.Only([]string{"relay9"}); err == nil || !strings.Contains(err.Error(), "--only relay9 matches no relay") {
		t.Errorf("unknown name: %v", err)
	}
	if got, _ := inv.Only(nil); len(got.Entries) != 3 {
		t.Error("no names keeps everything")
	}
}

func TestFromHosts(t *testing.T) {
	dir := writeBase(t, baseConfig)
	cfg := filepath.Join(dir, "relay.toml")
	inv, err := FromHosts(cfg, []string{"root@a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if !inv.SharedNickname || inv.Parallel != 1 || len(inv.Entries) != 2 {
		t.Fatalf("inventory = %+v", inv)
	}
	for _, e := range inv.Entries {
		if string(e.Config) != baseConfig || e.Nickname() != "BaseRelay" {
			t.Errorf("%s: %q", e.Address, e.Config)
		}
	}
	for _, tt := range []struct {
		cfg   string
		hosts []string
		want  string
	}{
		{cfg, nil, "no hosts given"},
		{cfg, []string{"a", "a"}, "host a is listed twice"},
		{cfg, []string{"a b"}, "not an ssh destination"},
		{"", []string{"a"}, "needs --config"},
	} {
		if _, err := FromHosts(tt.cfg, tt.hosts); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("FromHosts(%q, %q) = %v, want %q", tt.cfg, tt.hosts, err, tt.want)
		}
	}
}

func TestExampleInventory(t *testing.T) {
	inv, err := Load(filepath.Join("..", "..", "docs", "examples", "fleet.toml"))
	if err != nil {
		t.Fatalf("docs/examples/fleet.toml: %v", err)
	}
	var nicks []string
	for _, e := range inv.Entries {
		nicks = append(nicks, e.Nickname())
	}
	if !reflect.DeepEqual(nicks, []string{"Example1", "Example2", "ExampleSpecial"}) || inv.Parallel != 4 {
		t.Errorf("nicknames %q, parallel %d", nicks, inv.Parallel)
	}
	if e := inv.Entries[2]; e.Setup.Relay.ORPort != 443 || e.Setup.Bandwidth.MonthlyQuota != "20TB" || e.Host() != "relay3" {
		t.Errorf("third relay = %+v", e.Setup)
	}
	if inv.Entries[1].Setup.Relay.IPv6 != "2001:db8::2" || inv.Entries[1].Host() != "relay2.example.org" {
		t.Errorf("second relay = %+v", inv.Entries[1].Setup.Relay)
	}
}

func TestValidAddress(t *testing.T) {
	for _, ok := range []string{"relay-1", "root@relay-1.example.org", "my_alias", "203.0.113.5", "admin@2001:db8::1", "[2001:db8::1]"} {
		if err := ValidAddress(ok); err != nil {
			t.Errorf("ValidAddress(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-oProxyCommand=x", "relay 1", "a;b", "ssh://root@relay:22", "relay:22"} {
		if err := ValidAddress(bad); err == nil {
			t.Errorf("ValidAddress(%q) accepted", bad)
		}
	}
	if HostOf("root@[2001:db8::1]") != "2001:db8::1" || HostOf("relay") != "relay" {
		t.Error("HostOf")
	}
}
