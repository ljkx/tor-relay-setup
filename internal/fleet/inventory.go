// Package fleet describes relays that are run together: the fleet.toml
// inventory (one base relay.toml plus per-host overrides), the probe
// document every host reports (`tor-relay-setup fleet-probe`), and the
// dashboard model that aggregates probes and Tor Metrics data into totals
// and checks. It never connects anywhere itself; internal/remote does.
package fleet

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ljkx/tor-relay-setup/internal/config"
)

// DefaultInventory is the inventory file used when none is given.
const DefaultInventory = "fleet.toml"

// DefaultInstance names the relay of a server that has only one.
const DefaultInstance = "default"

// maxParallel caps the parallel setting.
const maxParallel = 64

// Inventory is a parsed fleet.toml: one Entry per relay, in file order.
type Inventory struct {
	Path       string // the inventory file; empty for a one-off --host list
	ConfigPath string // the base relay.toml
	Parallel   int    // servers applied concurrently after the family host (at least 1)
	Nickname   string // the nickname template, if any
	Entries    []Entry
	// SharedNickname is set for one-off --host lists, which give every
	// relay the base config's nickname (as before inventories existed).
	SharedNickname bool
}

// Entry is one relay of the fleet.
type Entry struct {
	Index    int          // 1-based position in the inventory
	Address  string       // ssh destination, [user@]host
	Instance string       // relay.instance, DefaultInstance when unset
	Config   []byte       // the relay.toml to apply: the base with this host's overrides
	Setup    config.Setup // Config, parsed and validated
}

// Nickname is the relay's nickname.
func (e Entry) Nickname() string { return e.Setup.Relay.Nickname }

// Host is the address without the user and IPv6 brackets.
func (e Entry) Host() string { return HostOf(e.Address) }

// HostOf strips the user and IPv6 brackets from an ssh destination.
func HostOf(address string) string {
	if i := strings.LastIndex(address, "@"); i >= 0 {
		address = address[i+1:]
	}
	return strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
}

var addressPattern = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._-]*@)?(?:[A-Za-z0-9_][A-Za-z0-9._-]*|\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*)$`)

// ValidAddress accepts plausible ssh destinations: [user@]host, where host
// is a name, an ssh_config alias, or an IP address (IPv6 optionally in
// brackets). Whitespace, a leading '-', URIs and shell syntax are rejected.
func ValidAddress(s string) error {
	if s == "" || len(s) > 255 || strings.HasPrefix(s, "-") || !addressPattern.MatchString(s) {
		return fmt.Errorf("%q is not an ssh destination; use [user@]host (ports and options belong in ~/.ssh/config)", s)
	}
	return nil
}

// rawInventory is the fleet.toml layout; hosts stay generic tables so that
// any relay.toml setting can be overridden per host.
type rawInventory struct {
	Config   string           `toml:"config"`
	Parallel int              `toml:"parallel"`
	Nickname string           `toml:"nickname"`
	Hosts    []map[string]any `toml:"host"`
}

// Load reads an inventory file. The base config path in it is relative to
// the inventory's directory.
func Load(path string) (Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Inventory{}, err
	}
	inv, err := Parse(data, filepath.Dir(path))
	if err != nil {
		return Inventory{}, fmt.Errorf("%s: %w", path, err)
	}
	inv.Path = path
	return inv, nil
}

// Parse decodes an inventory, merges every host's overrides onto the base
// config and validates the result: each relay's config, unique nicknames,
// and no relay or ORPort listed twice on one server. dir resolves a
// relative base config path.
func Parse(data []byte, dir string) (Inventory, error) {
	var raw rawInventory
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return Inventory{}, fmt.Errorf("parse inventory: %w", err)
	}
	// Keys inside [[host]] are relay.toml overrides; config.Parse checks
	// them after the merge, so only the inventory's own keys count here.
	var unknown []string
	for _, k := range md.Undecoded() {
		if len(k) == 0 || k[0] != "host" {
			unknown = append(unknown, k.String())
		}
	}
	if len(unknown) > 0 {
		return Inventory{}, fmt.Errorf("unknown inventory keys: %s (relay settings go in relay.toml or a [host.TABLE] override)", strings.Join(unknown, ", "))
	}
	if raw.Config == "" {
		return Inventory{}, errors.New(`config: set the base relay.toml, e.g. config = "relay.toml"`)
	}
	if raw.Parallel < 0 || raw.Parallel > maxParallel {
		return Inventory{}, fmt.Errorf("parallel: must be 1–%d", maxParallel)
	}
	if len(raw.Hosts) == 0 {
		return Inventory{}, errors.New("no [[host]] entries")
	}
	cfgPath := raw.Config
	if !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(dir, cfgPath)
	}
	base, err := os.ReadFile(cfgPath)
	if err != nil {
		return Inventory{}, fmt.Errorf("base config: %w", err)
	}
	inv := Inventory{ConfigPath: cfgPath, Parallel: max(raw.Parallel, 1), Nickname: raw.Nickname}
	for i, h := range raw.Hosts {
		e, err := entry(i+1, h, base, raw.Nickname)
		if err != nil {
			return Inventory{}, err
		}
		inv.Entries = append(inv.Entries, e)
	}
	if err := inv.validate(); err != nil {
		return Inventory{}, err
	}
	return inv, nil
}

// FromHosts is the one-off inventory behind `apply --config FILE --host
// ...`: the same config, byte for byte, on every host, one at a time.
func FromHosts(configPath string, hosts []string) (Inventory, error) {
	if len(hosts) == 0 {
		return Inventory{}, errors.New("no hosts given")
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if err := ValidAddress(h); err != nil {
			return Inventory{}, err
		}
		if seen[h] {
			return Inventory{}, fmt.Errorf("host %s is listed twice", h)
		}
		seen[h] = true
	}
	if configPath == "" {
		return Inventory{}, errors.New("apply --host needs --config FILE")
	}
	base, err := os.ReadFile(configPath)
	if err != nil {
		return Inventory{}, err
	}
	inv := Inventory{ConfigPath: configPath, Parallel: 1, SharedNickname: true}
	for i, h := range hosts {
		e, err := entry(i+1, map[string]any{"address": h}, base, "")
		if err != nil {
			return Inventory{}, err
		}
		inv.Entries = append(inv.Entries, e)
	}
	if err := inv.validate(); err != nil {
		return Inventory{}, err
	}
	return inv, nil
}

// entry builds one relay from a [[host]] table.
func entry(index int, h map[string]any, base []byte, nickTemplate string) (Entry, error) {
	where := fmt.Sprintf("host %d", index)
	address, ok := h["address"].(string)
	if !ok || address == "" {
		return Entry{}, fmt.Errorf("%s: address is required, e.g. address = \"root@relay1.example.org\"", where)
	}
	if err := ValidAddress(address); err != nil {
		return Entry{}, fmt.Errorf("%s: %w", where, err)
	}
	where += " (" + address + ")"
	overrides := maps.Clone(h)
	delete(overrides, "address")

	merged, err := decodeTable(base)
	if err != nil {
		return Entry{}, fmt.Errorf("base config: %w", err)
	}
	mergeTables(merged, overrides)
	relayTable, _ := merged["relay"].(map[string]any)
	if nickTemplate != "" && !hasKey(overrides, "relay", "nickname") {
		if relayTable == nil {
			relayTable = map[string]any{}
			merged["relay"] = relayTable
		}
		relayTable["nickname"] = ExpandNickname(nickTemplate, index, address)
	}

	data := base
	if len(overrides) > 0 || nickTemplate != "" {
		var buf bytes.Buffer
		buf.WriteString("# tor-relay-setup configuration for " + address + ", merged from the fleet inventory.\n\n")
		if err := toml.NewEncoder(&buf).Encode(merged); err != nil {
			return Entry{}, fmt.Errorf("%s: %w", where, err)
		}
		data = buf.Bytes()
	}
	s, err := config.Parse(data)
	if err != nil {
		return Entry{}, fmt.Errorf("%s: %w", where, err)
	}
	if err := s.Validate(); err != nil {
		return Entry{}, fmt.Errorf("%s: %w", where, err)
	}
	return Entry{Index: index, Address: address, Instance: instanceOf(merged), Config: data, Setup: s}, nil
}

// instanceOf reads relay.instance (multi-instance relay.toml) from merged
// tables; without it the relay is the server's default instance.
func instanceOf(merged map[string]any) string {
	relayTable, _ := merged["relay"].(map[string]any)
	if v, ok := relayTable["instance"].(string); ok && v != "" {
		return v
	}
	return DefaultInstance
}

// decodeTable decodes TOML into generic tables.
func decodeTable(data []byte) (map[string]any, error) {
	m := map[string]any{}
	if _, err := toml.Decode(string(data), &m); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return m, nil
}

// mergeTables merges src into dst: tables merge key by key, everything
// else (values, arrays) replaces what dst had.
func mergeTables(dst, src map[string]any) {
	for k, v := range src {
		if sv, ok := v.(map[string]any); ok {
			if dv, ok := dst[k].(map[string]any); ok {
				mergeTables(dv, sv)
				continue
			}
			nv := map[string]any{}
			mergeTables(nv, sv)
			dst[k] = nv
			continue
		}
		dst[k] = v
	}
}

func hasKey(m map[string]any, table, key string) bool {
	t, ok := m[table].(map[string]any)
	if !ok {
		return false
	}
	_, ok = t[key]
	return ok
}

// maxNickname is Tor's nickname length limit.
const maxNickname = 19

// ExpandNickname fills a nickname template: {n} is the 1-based index and
// {host} the short hostname reduced to letters and digits, shortened so the
// result fits Tor's 19 characters.
func ExpandNickname(template string, index int, address string) string {
	n := strconv.Itoa(index)
	host := shortHost(address)
	if strings.Contains(template, "{host}") {
		rest := len(strings.ReplaceAll(strings.ReplaceAll(template, "{n}", n), "{host}", ""))
		count := strings.Count(template, "{host}")
		room := max(maxNickname-rest, 0) / count
		if len(host) > room {
			host = host[:room]
		}
	}
	return strings.NewReplacer("{n}", n, "{host}", host).Replace(template)
}

// shortHost is the first DNS label of the address's host (all of an IP
// address), letters and digits only.
func shortHost(address string) string {
	h := HostOf(address)
	if net.ParseIP(h) == nil {
		h, _, _ = strings.Cut(h, ".")
	}
	return strings.Map(func(r rune) rune {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, h)
}

// validate checks the fleet as a whole.
func (inv Inventory) validate() error {
	var errs []error
	nick := map[string]Entry{}
	relays := map[string]Entry{}
	ports := map[string]Entry{}
	name := func(e Entry) string { return fmt.Sprintf("host %d (%s)", e.Index, e.Address) }
	for _, e := range inv.Entries {
		if !inv.SharedNickname {
			key := strings.ToLower(e.Nickname())
			if prev, ok := nick[key]; ok {
				errs = append(errs, fmt.Errorf("nickname %q is used by %s and %s; give each relay its own, e.g. nickname = \"%s{n}\"", e.Nickname(), name(prev), name(e), e.Nickname()))
			}
			nick[key] = e
		}
		server := strings.ToLower(e.Address)
		if prev, ok := relays[server+" "+e.Instance]; ok {
			errs = append(errs, fmt.Errorf("%s and %s are the same relay (instance %q); set relay.instance to run several relays on one server", name(prev), name(e), e.Instance))
		}
		relays[server+" "+e.Instance] = e
		port := fmt.Sprintf("%s %d", server, e.Setup.Relay.ORPort)
		if prev, ok := ports[port]; ok && prev.Instance != e.Instance {
			errs = append(errs, fmt.Errorf("%s and %s both use ORPort %d on the same server", name(prev), name(e), e.Setup.Relay.ORPort))
		}
		ports[port] = e
	}
	return errors.Join(errs...)
}

// Only keeps the entries matching any of the names: an address, its host
// part, or a nickname (case-insensitive). A name that matches nothing is an
// error, so a typo never silently runs on nothing.
func (inv Inventory) Only(names []string) (Inventory, error) {
	if len(names) == 0 {
		return inv, nil
	}
	keep := make([]bool, len(inv.Entries))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		found := false
		for i, e := range inv.Entries {
			if strings.EqualFold(n, e.Address) || strings.EqualFold(n, e.Host()) || strings.EqualFold(n, e.Nickname()) {
				keep[i], found = true, true
			}
		}
		if !found {
			return Inventory{}, fmt.Errorf("--only %s matches no relay in the inventory", n)
		}
	}
	out := inv
	out.Entries = nil
	for i, e := range inv.Entries {
		if keep[i] {
			out.Entries = append(out.Entries, e)
		}
	}
	return out, nil
}

// Servers groups the entries by address, in order of first appearance: one
// ssh connection per server, its relays one after another.
func (inv Inventory) Servers() [][]Entry {
	var out [][]Entry
	at := map[string]int{}
	for _, e := range inv.Entries {
		key := strings.ToLower(e.Address)
		i, ok := at[key]
		if !ok {
			i = len(out)
			at[key] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], e)
	}
	return out
}

// Addresses lists each server once, in inventory order.
func (inv Inventory) Addresses() []string {
	var out []string
	for _, s := range inv.Servers() {
		out = append(out, s[0].Address)
	}
	return out
}
