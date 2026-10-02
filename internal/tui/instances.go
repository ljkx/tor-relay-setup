package tui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/status"
)

// InstancePrefill returns the wizard answers for instance name: its current
// torrc when it already runs a relay, otherwise defaults for a new relay
// next to the others on this host (see NewInstanceSetup).
func InstancePrefill(h host.Host, name string) config.Setup {
	inst, err := relay.Named(name)
	if err != nil {
		return config.Default()
	}
	if s, ok := instanceSetup(h, inst); ok {
		return s
	}
	if inst.IsDefault() {
		return config.Default()
	}
	s := NewInstanceSetup(h, relay.DefaultInstance())
	s.Relay.Instance = inst.Name
	return s
}

// instanceSetup reads inst's torrc back into answers, if it is a relay.
func instanceSetup(h host.Host, inst relay.Instance) (config.Setup, bool) {
	data, err := h.ReadFile(inst.TorrcPath)
	if err != nil {
		return config.Setup{}, false
	}
	doc := relay.ParseDocument(data)
	if len(doc.ORPorts()) == 0 {
		return config.Setup{}, false
	}
	s := config.FromDocument(doc)
	if !inst.IsDefault() {
		s.Relay.Instance = inst.Name
	}
	return s, true
}

// NewInstanceSetup suggests answers for another relay on this server, based
// on the relay instance from (or the first one found): same contact, mode,
// IPv6 address, sandbox and MetricsPort choice; the next free instance name,
// ORPort and a numbered nickname; and the family key the server already
// uses, which the apply then shares (all relays on a server are one family).
// Quota-based bandwidth limits are not copied: two relays pacing the same
// monthly quota would use it twice, so the operator sets a new budget.
func NewInstanceSetup(h host.Host, from relay.Instance) config.Setup {
	s := config.Default()
	configs, _ := relay.DiscoverConfigs(h)
	var base *relay.InstanceConfig
	for i := range configs {
		if configs[i].Name == from.OrDefault().Name {
			base = &configs[i]
		}
	}
	if base == nil && len(configs) > 0 {
		base = &configs[0]
	}
	var used []int
	for _, c := range configs {
		used = append(used, c.Doc.ORPortNumbers()...)
		if p := c.Doc.MetricsPortNumber(); p > 0 {
			used = append(used, p)
		}
	}
	s.Relay.Instance = nextInstanceName(h, configs)
	if base == nil {
		s.Relay.ORPort = relay.NextFreePort(s.Relay.ORPort, used)
		return s
	}

	from0 := config.FromDocument(base.Doc)
	s.Relay.Contact, s.Relay.Mode, s.Relay.IPv6 = from0.Relay.Contact, from0.Relay.Mode, from0.Relay.IPv6
	s.Relay.Sandbox, s.Relay.MetricsPort = from0.Relay.Sandbox, from0.Relay.MetricsPort
	s.Exit = from0.Exit
	s.Relay.ORPort = relay.NextFreePort(max(from0.Relay.ORPort, 1), used)
	s.Relay.Nickname = numberedNickname(from0.Relay.Nickname, len(configs)+1)
	switch b := from0.Bandwidth; {
	case b.Mode == string(relay.BandwidthNone):
		s.Bandwidth = b
	case b.Mode == string(relay.BandwidthManual) && b.AccountingGBytes == 0:
		s.Bandwidth = b
	}
	if key, ok := familyKeyOf(h, *base); ok {
		s.Family.Mode, s.Family.KeyName = "generate", key.Name
	}
	return s
}

// familyKeyOf returns the installed family key a relay instance uses.
func familyKeyOf(h host.Host, c relay.InstanceConfig) (family.Key, bool) {
	fkd, _ := c.Doc.Get("FamilyKeyDirectory")
	kd, _ := c.Doc.Get("KeyDirectory")
	keys, _ := family.Installed(h, family.KeyDirectory(fkd, kd, c.DataDirectory()))
	ids := c.Doc.FamilyIDs()
	for _, k := range keys {
		if k.ID != "" && slices.Contains(ids, k.ID) {
			return k, true
		}
	}
	return family.Key{}, false
}

// nextInstanceName returns relay2, relay3, ... : the first name that is not
// a discovered relay and has no instance directory yet.
func nextInstanceName(h host.Host, configs []relay.InstanceConfig) string {
	for n := 2; ; n++ {
		name := "relay" + strconv.Itoa(n)
		taken := slices.ContainsFunc(configs, func(c relay.InstanceConfig) bool { return c.Name == name })
		if _, err := h.Stat(relay.InstancesDir + "/" + name + "/torrc"); err == nil {
			taken = true
		}
		if !taken {
			return name
		}
	}
}

// numberedNickname appends n to base (without its trailing digits), within
// Tor's 19-character nickname limit: MyRelay -> MyRelay2.
func numberedNickname(base string, n int) string {
	base = strings.TrimRight(base, "0123456789")
	if base == "" {
		return ""
	}
	suffix := strconv.Itoa(n)
	if len(base)+len(suffix) > 19 {
		base = base[:19-len(suffix)]
	}
	return base + suffix
}

// instanceTitle labels a named instance for screen titles: " · relay2".
func instanceTitle(inst relay.Instance) string {
	if inst.OrDefault().IsDefault() {
		return ""
	}
	return " · instance " + inst.Name
}

// overviewLine summarises every relay instance's health in one line.
func overviewLine(t Theme, reports []status.Report) string {
	var bad []string
	for _, r := range reports {
		if !r.Healthy() {
			bad = append(bad, r.Instance+" ("+r.Warnings[0]+")")
		}
	}
	line := statusIcon(t, true, false) + fmt.Sprintf(" all %d relays on this server are healthy", len(reports))
	if len(bad) > 0 {
		line = statusIcon(t, false, true) + fmt.Sprintf(" %d of %d relays need attention: ", len(bad), len(reports)) + strings.Join(bad, "; ")
	}
	if len(reports) > relay.MaxRelaysPerIPv4 {
		line += t.WarnText.Render(fmt.Sprintf("  · more than %d relays per IPv4 address are not listed", relay.MaxRelaysPerIPv4))
	}
	return line
}
