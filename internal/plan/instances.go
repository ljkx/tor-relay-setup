package plan

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
	idkeys "github.com/ljkx/tor-relay-setup/internal/keys"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// OtherInstances returns the relay instances on the host other than inst.
func OtherInstances(h host.Host, inst relay.Instance) []relay.InstanceConfig {
	all, _ := relay.DiscoverConfigs(h)
	inst = inst.OrDefault()
	return slices.DeleteFunc(all, func(c relay.InstanceConfig) bool { return c.Name == inst.Name })
}

// usedPorts lists the ORPorts, MetricsPorts, transport ports and DirPorts
// of instances.
func usedPorts(instances []relay.InstanceConfig) []int {
	var used []int
	for _, o := range instances {
		used = append(used, instancePorts(o.Doc)...)
	}
	return used
}

// instancePorts lists every TCP port a torrc listens on.
func instancePorts(doc *relay.Document) []int {
	ports := append(doc.ORPortNumbers(), doc.BridgePorts()...)
	ports = append(ports, doc.DirPortNumbers()...)
	if p := doc.MetricsPortNumber(); p > 0 {
		ports = append(ports, p)
	}
	return ports
}

// setupPorts lists the ports s needs on this host, each with what it is.
func setupPorts(s config.Setup) map[int]string {
	ports := map[int]string{}
	if !s.IsWebTunnel() {
		ports[s.Relay.ORPort] = "ORPort"
	}
	switch {
	case s.IsWebTunnel():
		ports[s.WebTunnelPort()] = "WebTunnel port"
		if s.ManagedNginx() {
			ports[443] = "nginx HTTPS port"
			if s.UsesCertbot() {
				ports[80] = "nginx HTTP port"
			}
		}
	case s.IsBridge():
		ports[s.Bridge.Obfs4Port] = "obfs4 port"
	case s.IsExit() && s.Exit.Notice:
		ports[relay.ExitNoticePort] = "exit notice port"
	}
	return ports
}

// ResolveMetricsAddress picks the MetricsPort address for s on this host:
// the address the instance already uses when it is still free, otherwise
// 127.0.0.1:9035 for the default instance and the first free port from 9036
// for a named one. It returns "" when MetricsPort is off.
func ResolveMetricsAddress(h host.Host, s config.Setup) string {
	if !s.Relay.MetricsPort {
		return ""
	}
	inst := s.Instance()
	used := append([]int{s.Relay.ORPort}, usedPorts(OtherInstances(h, inst))...)
	current := ""
	if data, err := h.ReadFile(inst.TorrcPath); err == nil {
		current, _ = relay.ParseDocument(data).Get("MetricsPort")
	}
	return relay.MetricsAddress(inst, current, used)
}

// Conflicts reports ORPort and MetricsPort collisions between s and the
// other relay instances on the host. s.Relay.MetricsAddress should already
// be resolved.
func Conflicts(s config.Setup, others []relay.InstanceConfig) error {
	var problems []string
	metrics := 0
	if s.Relay.MetricsPort {
		metrics = relay.PortNumber(s.RelayConfig(nil).MetricsPort)
	}
	mine := setupPorts(s)
	keys := slices.Sorted(maps.Keys(mine))
	for _, o := range others {
		theirs := instancePorts(o.Doc)
		for _, p := range keys {
			if slices.Contains(theirs, p) {
				problems = append(problems, fmt.Sprintf("%s %d is already used by tor instance %s (%s)", mine[p], p, o.Name, o.TorrcPath))
			}
		}
		if metrics > 0 && slices.Contains(theirs, metrics) {
			problems = append(problems, fmt.Sprintf("MetricsPort %d is already used by tor instance %s (%s)", metrics, o.Name, o.TorrcPath))
		}
		if s.IsWebTunnel() {
			if b, ok := o.Doc.BridgeSettings(); ok {
				if d, _, _ := relay.SplitWebTunnelURL(b.URL); d != "" && strings.EqualFold(d, s.Bridge.Domain) {
					problems = append(problems, fmt.Sprintf("tor instance %s already runs a WebTunnel bridge on %s; use another domain", o.Name, d))
				}
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s; every relay on a server needs its own ports", strings.Join(problems, "; "))
}

// RelaysPerIPv4Warning returns a warning when count relays on one server
// exceed what the directory authorities accept per IPv4 address, or "".
func RelaysPerIPv4Warning(count int) string {
	if count <= relay.MaxRelaysPerIPv4 {
		return ""
	}
	return fmt.Sprintf("this server would run %d relays, but the directory authorities list at most %d per IPv4 address; relays beyond that are not used unless they have their own IPv4 address (%s)",
		count, relay.MaxRelaysPerIPv4, relay.RelaysPerIPv4URL)
}

// SharedFamilyKey is a family key another instance on this host already has.
type SharedFamilyKey struct {
	Instance string // the instance it was found in
	Key      family.Key
}

// sharedFamily decides where a generated family key comes from when the
// server already runs other relays. All relays on one server must be one
// family (they share an operator and an IP address), so a second family is
// never created next to an existing one:
//   - another instance has a key named s.Family.KeyName: reuse it;
//   - another instance uses a different family key: refuse, naming it;
//   - otherwise: generate a new key.
func sharedFamily(h host.Host, s config.Setup, others []relay.InstanceConfig) (*SharedFamilyKey, error) {
	if s.Family.Mode != "generate" {
		return nil, nil
	}
	var inUse []SharedFamilyKey
	for _, o := range others {
		fkd, _ := o.Doc.Get("FamilyKeyDirectory")
		kd, _ := o.Doc.Get("KeyDirectory")
		keys, _ := family.Installed(h, family.KeyDirectory(fkd, kd, o.DataDirectory()))
		ids := o.Doc.FamilyIDs()
		for _, k := range keys {
			if k.ID == "" {
				continue
			}
			if k.Name == s.Family.KeyName {
				return &SharedFamilyKey{Instance: o.Name, Key: k}, nil
			}
			if slices.Contains(ids, k.ID) {
				inUse = append(inUse, SharedFamilyKey{Instance: o.Name, Key: k})
			}
		}
	}
	if len(inUse) > 0 {
		k := inUse[0]
		return nil, fmt.Errorf("tor instance %s on this server already uses family key %q (FamilyId %s); all relays on one server must share one family: set the family key name to %q to reuse it",
			k.Instance, k.Key.Name, k.Key.ID, k.Key.Name)
	}
	return nil, nil
}

// checkOwnFamilyKey refuses to generate a key whose name already exists in
// the instance's key directory (existing keys are never overwritten), unless
// it is the very key being shared from another instance.
func checkOwnFamilyKey(h host.Host, s config.Setup, shared *SharedFamilyKey) error {
	if s.Family.Mode != "generate" {
		return nil
	}
	key := s.Instance().KeyDir + "/" + s.Family.KeyName + ".secret_family_key"
	if _, err := h.Stat(key); err != nil {
		return nil
	}
	if shared != nil {
		own, err1 := h.ReadFile(key)
		theirs, err2 := h.ReadFile(shared.Key.Path)
		if err1 == nil && err2 == nil && bytes.Equal(own, theirs) {
			return nil
		}
	}
	return fmt.Errorf("a family key named %q already exists (%s); choose another name or import it instead", s.Family.KeyName, key)
}

func instanceStep(inst relay.Instance) Step {
	return Step{
		ID:    "instance",
		Title: "Create tor instance " + inst.Name,
		Changes: []string{fmt.Sprintf("Create tor instance %s with %s %s if it does not exist (user %s, %s, DataDirectory %s, unit %s)",
			inst.Name, relay.InstanceCreateCommand, inst.Name, inst.User, inst.TorrcPath, inst.DataDir, inst.Unit)},
		Weight: 1,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			if _, err := e.Host.Stat(inst.TorrcPath); err == nil {
				r.Note(Info, "tor instance "+inst.Name+" already exists")
				return nil
			}
			if _, err := e.Host.Run(ctx, host.Command{Name: relay.InstanceCreateCommand, Args: []string{inst.Name}, Mutates: true}); err != nil {
				return err
			}
			if !e.Host.DryRun() {
				r.Note(Success, "Created "+inst.Unit+" (user "+inst.User+")")
			}
			return nil
		},
	}
}

// offlineKeyGone reports a relay whose ed25519 master key has been taken
// offline: the key directory holds the master public key but no secret key.
func offlineKeyGone(h host.Host, inst relay.Instance) bool {
	inst = inst.OrDefault()
	if _, err := h.Stat(inst.KeyDir + "/" + idkeys.MasterPublic); err != nil {
		return false
	}
	for _, name := range []string{idkeys.MasterSecret, idkeys.MasterSecretEncrypted} {
		if _, err := h.Stat(inst.KeyDir + "/" + name); err == nil {
			return false
		}
	}
	return true
}

// instanceLabel is "" for the default instance (keeping single-relay state
// files as before) and the name otherwise.
func instanceLabel(inst relay.Instance) string {
	if inst.IsDefault() {
		return ""
	}
	return inst.Name
}

// CheckFamily reports, before anything runs, whether s can generate its
// family key on this host: the name must not clash with a different key of
// the same instance, and the server must not end up with two families.
func CheckFamily(h host.Host, s config.Setup) error {
	shared, err := sharedFamily(h, s, OtherInstances(h, s.Instance()))
	if err != nil {
		return err
	}
	return checkOwnFamilyKey(h, s, shared)
}
