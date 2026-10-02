package relay

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

func TestValidInstanceName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ok   bool
	}{
		{"relay2", true},
		{"R2", true},
		{"0", true},
		{strings.Repeat("a", 27), true},
		{strings.Repeat("a", 28), false}, // _tor-NAME must fit 32 characters
		{"", false},
		{"default", false},
		{"relay-2", false}, // tor-instance-create rejects anything but [a-zA-Z0-9]
		{"relay_2", false},
		{"relay.2", false},
		{"../etc", false},
		{"relay 2", false},
		{"rélay", false},
	}
	for _, tt := range tests {
		if got := ValidInstanceName(tt.name); got != tt.ok {
			t.Errorf("ValidInstanceName(%q) = %v, want %v", tt.name, got, tt.ok)
		}
	}
}

func TestNamedInstanceLayout(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "default"} {
		inst, err := Named(name)
		if err != nil {
			t.Fatal(err)
		}
		want := Instance{
			Name: "default", TorrcPath: "/etc/tor/torrc", DataDir: "/var/lib/tor", KeyDir: "/var/lib/tor/keys",
			User: "debian-tor", Unit: "tor@default", DefaultsTorrc: "/usr/share/tor/tor-service-defaults-torrc",
		}
		if inst != want || !inst.IsDefault() {
			t.Errorf("Named(%q) = %+v, want %+v", name, inst, want)
		}
	}

	inst, err := Named("relay2")
	if err != nil {
		t.Fatal(err)
	}
	want := Instance{
		Name: "relay2", TorrcPath: "/etc/tor/instances/relay2/torrc",
		DataDir: "/var/lib/tor-instances/relay2", KeyDir: "/var/lib/tor-instances/relay2/keys",
		User: "_tor-relay2", Unit: "tor@relay2", DefaultsTorrc: "/usr/share/tor/tor-service-defaults-torrc-instances",
	}
	if inst != want || inst.IsDefault() {
		t.Errorf("Named(relay2) = %+v, want %+v", inst, want)
	}
	if _, err := Named("relay-2"); err == nil {
		t.Error("Named accepted a name tor-instance-create rejects")
	}
	if (Instance{}).OrDefault() != DefaultInstance() || !(Instance{}).IsDefault() {
		t.Error("the zero Instance should mean the default instance")
	}
}

func TestDiscover(t *testing.T) {
	t.Parallel()
	h := host.NewFake()
	h.Files["/etc/tor/torrc"] = []byte("Nickname A\nORPort 9001\n")
	h.Files["/etc/tor/instances/relay3/torrc"] = []byte("ORPort 9003\nMetricsPort 127.0.0.1:9037\n")
	h.Files["/etc/tor/instances/relay2/torrc"] = []byte("ORPort 9002\nDataDirectory /srv/tor2\n")
	h.Files["/etc/tor/instances/client/torrc"] = []byte("+SocksPort auto\n") // not a relay
	h.Files["/etc/tor/instances/bad-name/torrc"] = []byte("ORPort 9009\n")   // ignored by the tor package too
	h.Files["/etc/tor/instances/default/torrc"] = []byte("ORPort 9010\n")

	configs, err := DiscoverConfigs(h)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range configs {
		names = append(names, c.Name)
	}
	if !slices.Equal(names, []string{"default", "relay2", "relay3"}) {
		t.Fatalf("discovered %q", names)
	}
	if got := configs[1].DataDirectory(); got != "/srv/tor2" {
		t.Errorf("relay2 DataDirectory = %q", got)
	}
	if got := configs[2].DataDirectory(); got != "/var/lib/tor-instances/relay3" {
		t.Errorf("relay3 DataDirectory = %q, want the instance default", got)
	}
	if got := configs[2].Doc.MetricsPortNumber(); got != 9037 {
		t.Errorf("relay3 MetricsPort = %d", got)
	}

	list, _ := Discover(h)
	if inst, ok := Find(list, "relay2"); !ok || inst.Unit != "tor@relay2" {
		t.Errorf("Find(relay2) = %+v, %v", inst, ok)
	}
	if _, ok := Find(list, ""); !ok {
		t.Error("Find(\"\") should find the default instance")
	}
	if _, ok := Find(list, "client"); ok {
		t.Error("a non-relay instance was discovered")
	}

	// A default torrc without an ORPort is not a relay.
	h2 := host.NewFake()
	h2.Files["/etc/tor/torrc"] = []byte("SocksPort 9050\n")
	h2.Files["/etc/tor/instances/r2/torrc"] = []byte("ORPort 443\n")
	list, _ = Discover(h2)
	if len(list) != 1 || list[0].Name != "r2" {
		t.Errorf("Discover = %+v, want only r2", list)
	}
	if list, _ := Discover(host.NewFake()); len(list) != 0 {
		t.Errorf("empty host discovered %+v", list)
	}
}

func TestMetricsAddress(t *testing.T) {
	t.Parallel()
	def := DefaultInstance()
	r2, _ := Named("relay2")
	tests := []struct {
		name    string
		inst    Instance
		current string
		used    []int
		want    string
	}{
		{"default", def, "", nil, "127.0.0.1:9035"},
		{"named starts at 9036", r2, "", []int{9001, 9035}, "127.0.0.1:9036"},
		{"named skips used", r2, "", []int{9035, 9036, 9037}, "127.0.0.1:9038"},
		{"default taken by another instance", def, "", []int{9035}, "127.0.0.1:9036"},
		{"current kept", r2, "127.0.0.1:9040", []int{9035}, "127.0.0.1:9040"},
		{"current collides", r2, "127.0.0.1:9035", []int{9035}, "127.0.0.1:9036"},
		{"current not loopback", r2, "0.0.0.0:9040", nil, "127.0.0.1:9036"},
	}
	for _, tt := range tests {
		if got := MetricsAddress(tt.inst, tt.current, tt.used); got != tt.want {
			t.Errorf("%s: MetricsAddress = %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := NextFreePort(9001, []int{9001, 9002, 9004}); got != 9003 {
		t.Errorf("NextFreePort = %d", got)
	}
}

func TestORPortNumbers(t *testing.T) {
	t.Parallel()
	doc := ParseDocument([]byte("ORPort 443 NoListen\nORPort 127.0.0.1:9090 NoAdvertise\nORPort [2001:db8::1]:443\nORPort auto\n"))
	if got := doc.ORPortNumbers(); !slices.Equal(got, []int{443, 9090}) {
		t.Errorf("ORPortNumbers = %v", got)
	}
	if doc.FirstORPort() != 443 {
		t.Errorf("FirstORPort = %d", doc.FirstORPort())
	}
	if got := ParseDocument(nil).DataDirectoryOr("/x"); got != "/x" {
		t.Errorf("DataDirectoryOr = %q", got)
	}
}

func TestVerifyNamedInstanceUsesRenderedDefaults(t *testing.T) {
	t.Parallel()
	h := host.NewFake()
	h.Paths["tor"] = true
	h.Files[InstanceDefaultsTemplate] = []byte("DataDirectory /var/lib/tor-instances/@@NAME@@\nUser _tor-@@NAME@@\n")
	var defaults string
	h.Handler = func(c host.Command) (host.Result, error) {
		// The rendered defaults exist while tor runs.
		data, err := os.ReadFile(c.Args[1])
		if err != nil {
			t.Errorf("defaults file: %v", err)
		}
		defaults = string(data)
		return host.Result{}, nil
	}
	inst, _ := Named("relay2")
	if err := VerifyInstance(context.Background(), h, inst, "/tmp/candidate"); err != nil {
		t.Fatal(err)
	}
	c := h.Commands[0]
	if c.Args[0] != "--defaults-torrc" || !slices.Equal(c.Args[2:], []string{"-f", "/tmp/candidate", "--verify-config"}) || c.Mutates {
		t.Errorf("command = %s", c)
	}
	if defaults != "DataDirectory /var/lib/tor-instances/relay2\nUser _tor-relay2\n" {
		t.Errorf("rendered defaults = %q", defaults)
	}
	if _, err := os.Stat(c.Args[1]); !os.IsNotExist(err) {
		t.Errorf("temporary defaults %s were not removed", c.Args[1])
	}

	// Without the template (no tor package yet) tor gets the torrc alone.
	h2 := host.NewFake()
	h2.Paths["tor"] = true
	if err := VerifyInstance(context.Background(), h2, inst, "/tmp/c"); err != nil {
		t.Fatal(err)
	}
	if got := h2.CommandLines(); !slices.Equal(got, []string{"tor -f /tmp/c --verify-config"}) {
		t.Errorf("commands = %q", got)
	}
}
