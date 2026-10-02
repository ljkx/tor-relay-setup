package relay

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Debian's tor package runs one tor process per systemd unit. The default
// instance is tor@default (/etc/tor/torrc, user debian-tor, /var/lib/tor).
// `tor-instance-create NAME` adds a named instance: user and group
// _tor-NAME, /etc/tor/instances/NAME/torrc, DataDirectory
// /var/lib/tor-instances/NAME (mode 2700), started as tor@NAME from the
// tor@.service template. Large servers run several relays this way.
// Source: tor-instance-create(8), tor@.service, tor@default.service and
// /usr/share/tor/tor-service-defaults-torrc{,-instances} in the tor package.
const (
	// DefaultInstanceName names the instance behind /etc/tor/torrc.
	DefaultInstanceName = "default"
	// DefaultTorrc is the default instance's configuration file.
	DefaultTorrc = "/etc/tor/torrc"
	// InstancesDir holds one directory with a torrc per named instance.
	InstancesDir = "/etc/tor/instances"
	// InstancesDataDir holds the named instances' DataDirectories.
	InstancesDataDir = "/var/lib/tor-instances"
	// InstanceDefaultsTemplate is the defaults torrc of named instances;
	// tor@.service replaces @@NAME@@ in it before starting tor.
	InstanceDefaultsTemplate = "/usr/share/tor/tor-service-defaults-torrc-instances"
	// InstanceCreateCommand creates a named instance.
	InstanceCreateCommand = "tor-instance-create"
	// DefaultUser runs the default instance.
	DefaultUser = "debian-tor"
)

// MaxRelaysPerIPv4 is how many relays the directory authorities list per
// IPv4 address (AuthDirMaxServersPerAddr on a majority of them; raised from
// 2 to 4 in February 2023 and to 8 at the end of June 2023).
const MaxRelaysPerIPv4 = 8

// RelaysPerIPv4URL documents MaxRelaysPerIPv4.
const RelaysPerIPv4URL = "https://community.torproject.org/relay/relays-requirements/"

// maxInstanceName keeps _tor-NAME within adduser's 32-character user names.
const maxInstanceName = 27

// tor-instance-create and the tor-generator systemd generator reject any
// name with a character outside [a-zA-Z0-9], and "default".
var instanceNameRe = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// Instance is one tor process managed by systemd.
type Instance struct {
	Name      string // "default" or the tor-instance-create name
	TorrcPath string
	DataDir   string // DataDirectory unless torrc overrides it
	KeyDir    string // DataDir/keys
	User      string // the user tor drops privileges to
	Unit      string // systemd unit, e.g. tor@default
	// DefaultsTorrc is the --defaults-torrc file the unit passes to tor. For
	// a named instance it is a template with @@NAME@@ placeholders.
	DefaultsTorrc string
}

// DefaultInstance returns the instance behind /etc/tor/torrc.
func DefaultInstance() Instance {
	return Instance{
		Name:          DefaultInstanceName,
		TorrcPath:     DefaultTorrc,
		DataDir:       "/var/lib/tor",
		KeyDir:        "/var/lib/tor/keys",
		User:          DefaultUser,
		Unit:          "tor@" + DefaultInstanceName,
		DefaultsTorrc: ServiceDefaultsTorrc,
	}
}

// ValidInstanceName reports whether name can be passed to
// tor-instance-create: 1-27 ASCII letters and digits, and not "default".
func ValidInstanceName(name string) bool {
	return len(name) <= maxInstanceName && instanceNameRe.MatchString(name) && name != DefaultInstanceName
}

// Named returns the instance called name. An empty name and "default" mean
// the default instance.
func Named(name string) (Instance, error) {
	if name == "" || name == DefaultInstanceName {
		return DefaultInstance(), nil
	}
	if !ValidInstanceName(name) {
		return Instance{}, fmt.Errorf("invalid instance name %q: use 1-%d letters and digits (tor-instance-create allows nothing else)", name, maxInstanceName)
	}
	data := InstancesDataDir + "/" + name
	return Instance{
		Name:          name,
		TorrcPath:     InstancesDir + "/" + name + "/torrc",
		DataDir:       data,
		KeyDir:        data + "/keys",
		User:          "_tor-" + name,
		Unit:          "tor@" + name,
		DefaultsTorrc: InstanceDefaultsTemplate,
	}, nil
}

// IsDefault reports whether i is the default instance (the zero Instance
// counts as default).
func (i Instance) IsDefault() bool { return i.Name == "" || i.Name == DefaultInstanceName }

// OrDefault returns i, or the default instance for the zero value.
func (i Instance) OrDefault() Instance {
	if i.TorrcPath == "" {
		return DefaultInstance()
	}
	return i
}

// InstanceConfig is a discovered relay instance with its parsed torrc.
type InstanceConfig struct {
	Instance
	Doc *Document
}

// DataDirectory is the DataDirectory the instance's tor uses.
func (c InstanceConfig) DataDirectory() string { return c.Doc.DataDirectoryOr(c.DataDir) }

// DiscoverConfigs finds the relays on this host: the default instance when
// /etc/tor/torrc configures an ORPort, then every named instance (sorted)
// whose /etc/tor/instances/NAME/torrc configures one. Instances that are
// not relays (clients, onion services) and names the tor package ignores
// are skipped.
func DiscoverConfigs(h host.Host) ([]InstanceConfig, error) {
	var out []InstanceConfig
	add := func(inst Instance) {
		data, err := h.ReadFile(inst.TorrcPath)
		if err != nil {
			return
		}
		if doc := ParseDocument(data); len(doc.ORPorts()) > 0 {
			out = append(out, InstanceConfig{Instance: inst, Doc: doc})
		}
	}
	add(DefaultInstance())
	paths, err := h.Glob(InstancesDir + "/*/torrc")
	if err != nil {
		return out, err
	}
	slices.Sort(paths)
	for _, p := range paths {
		if inst, err := Named(filepath.Base(filepath.Dir(p))); err == nil && !inst.IsDefault() {
			add(inst)
		}
	}
	return out, nil
}

// Discover returns the relay instances DiscoverConfigs finds.
func Discover(h host.Host) ([]Instance, error) {
	configs, err := DiscoverConfigs(h)
	out := make([]Instance, len(configs))
	for i, c := range configs {
		out[i] = c.Instance
	}
	return out, err
}

// Find returns the instance called name among list.
func Find(list []Instance, name string) (Instance, bool) {
	if name == "" {
		name = DefaultInstanceName
	}
	for _, inst := range list {
		if inst.Name == name {
			return inst, true
		}
	}
	return Instance{}, false
}

// First metrics ports: the default instance keeps the long-standing 9035;
// named instances count up from 9036.
const (
	defaultMetricsPort = 9035
	firstNamedMetrics  = 9036
)

// MetricsAddress picks a local MetricsPort address for inst. current is the
// address its torrc already uses, kept when its port is free so a re-apply
// does not move it; used lists ports other instances already take (ORPorts
// and MetricsPorts).
func MetricsAddress(inst Instance, current string, used []int) string {
	if p := PortNumber(current); p > 0 && !slices.Contains(used, p) && validMetricsAddr(current) {
		return current
	}
	port := firstNamedMetrics
	if inst.IsDefault() {
		port = defaultMetricsPort
	}
	for slices.Contains(used, port) {
		port++
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// NextFreePort returns the first port from start upwards that is not in used.
func NextFreePort(start int, used []int) int {
	p := start
	for slices.Contains(used, p) && p < 65535 {
		p++
	}
	return p
}
