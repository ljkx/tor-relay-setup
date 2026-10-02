package plan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/apt"
	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
	"github.com/ljkx/tor-relay-setup/internal/system"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// TorUser owns the default instance's data and key directories on Debian
// and Ubuntu; a named instance uses relay.Instance.User (_tor-NAME).
const TorUser = relay.DefaultUser

const resolvConf = "/etc/resolv.conf"

// Build returns the ordered steps for a setup on a host with these facts.
func Build(s config.Setup, f system.Facts) []Step {
	steps := []Step{preflightStep(s, f)}
	if s.System.Hostname != "" && s.System.Hostname != f.Hostname {
		steps = append(steps, hostnameStep(s.System.Hostname))
	}
	steps = append(steps,
		repositoryStep(f),
		updateStep(),
		packagesStep(s, f),
	)
	if inst := s.Instance(); !inst.IsDefault() {
		steps = append(steps, instanceStep(inst))
	}
	if s.System.Tuning {
		steps = append(steps, tuningStep(s))
	}
	if s.Family.Mode == "generate" || s.Family.Mode == "import" {
		steps = append(steps, familyStep(s))
	}
	if s.IsExit() && s.Exit.Unbound {
		steps = append(steps, exitDNSStep(s))
	}
	if s.System.UnattendedUpgrades {
		steps = append(steps, unattendedStep(f))
	}
	if bridgeStepNeeded(s) {
		steps = append(steps, bridgeStep(s))
	}
	fw := firewallPlan(s, f)
	if s.ManagedNginx() {
		// certbot's HTTP-01 challenge needs port 80 open before it runs.
		if fw.enabled {
			steps = append(steps, firewallStep(s, f, fw))
		}
		steps = append(steps, webTunnelStep(s))
	}
	if s.IsExit() && s.Exit.Notice {
		steps = append(steps, exitNoticeStep(s))
	}
	steps = append(steps, torrcStep(s))
	if fw.enabled && !s.ManagedNginx() {
		steps = append(steps, firewallStep(s, f, fw))
	}
	steps = append(steps, serviceStep(s), stateStep())
	return steps
}

// Packages lists what the single apt transaction installs.
func Packages(s config.Setup, f system.Facts) []string {
	pkgs := []string{"tor", "deb.torproject.org-keyring"}
	if s.System.Nyx {
		pkgs = append(pkgs, "nyx")
	}
	if s.IsExit() && s.Exit.Unbound {
		pkgs = append(pkgs, "unbound")
	}
	pkgs = append(pkgs, bridgePackages(s)...)
	if s.System.UnattendedUpgrades {
		pkgs = append(pkgs, "unattended-upgrades", "apt-listchanges")
	}
	if fw := firewallPlan(s, f); fw.installUFW {
		pkgs = append(pkgs, "ufw")
	}
	return pkgs
}

func preflightStep(s config.Setup, f system.Facts) Step {
	return Step{
		ID:     "preflight",
		Title:  "Check this server",
		Weight: 2,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			if problems := e.Facts.Problems(); len(problems) > 0 {
				return errors.New(strings.Join(problems, "; "))
			}
			if !e.Host.DryRun() && e.Facts.EUID != 0 {
				return errors.New("run as root, for example: sudo tor-relay-setup")
			}
			if e.Facts.DiskFreeMiB > 0 && e.Facts.DiskFreeMiB < 512 {
				return fmt.Errorf("only %d MiB free under /var; apt needs at least 512 MiB (check df -h)", e.Facts.DiskFreeMiB)
			}
			// Other relays on this server: ports, family and the per-IP limit.
			others := OtherInstances(e.Host, e.instance())
			e.Setup.Relay.MetricsAddress = ResolveMetricsAddress(e.Host, e.Setup)
			if e.Setup.IsWebTunnel() {
				if resolveWebTunnelPath(e.Host, &e.Setup) {
					r.Note(Info, "Generated the secret WebTunnel path "+e.Setup.Bridge.Path+"; torrc keeps it (or pin it with path = \""+e.Setup.Bridge.Path+"\" under [bridge] in relay.toml)")
				}
				if e.Setup.Bridge.LocalPort == 0 {
					e.Setup.Bridge.LocalPort = relay.NextFreePort(relay.DefaultWebTunnelPort, usedPorts(others))
				}
			}
			if err := Conflicts(e.Setup, others); err != nil {
				return err
			}
			if offlineKeyGone(e.Host, e.instance()) && !e.Setup.Relay.OfflineMasterKey {
				e.Setup.Relay.OfflineMasterKey = true
				r.Note(Warn, "The ed25519 master key is not on this server: keeping OfflineMasterKey 1 so tor never creates a new identity")
			}
			for _, w := range e.Setup.Warnings() {
				r.Note(Warn, w)
			}
			shared, err := sharedFamily(e.Host, e.Setup, others)
			if err != nil {
				return err
			}
			if err := checkOwnFamilyKey(e.Host, e.Setup, shared); err != nil {
				return err
			}
			e.SharedFamily = shared
			if w := RelaysPerIPv4Warning(len(others) + 1); w != "" {
				r.Note(Warn, w)
			}
			if len(others) > 0 {
				r.Note(Info, fmt.Sprintf("%d other relay instance(s) on this server; configuring %s", len(others), e.instance().Unit))
			}
			need := system.RequiredRAMMiB(s.IsExit()) * (len(others) + 1)
			if e.Facts.MemTotalMiB > 0 && e.Facts.MemTotalMiB < need {
				r.Note(Warn, fmt.Sprintf("%d MiB RAM is below Tor's recommended %d MiB for %d relay(s) of this type", e.Facts.MemTotalMiB, need, len(others)+1))
			}
			r.Progress(50, "Checking the Tor Project repository for "+f.Codename)
			ok, err := torproject.SuiteAvailable(ctx, e.HTTP, f.Codename)
			switch {
			case err != nil:
				return fmt.Errorf("cannot reach deb.torproject.org: %w", err)
			case !ok:
				return fmt.Errorf("the Tor Project repository does not publish %q yet; use a supported Debian/Ubuntu release", f.Codename)
			}
			r.Note(Success, fmt.Sprintf("%s %s on %s is supported", f.PrettyName, f.Codename, f.Arch))
			return nil
		},
	}
}

func hostnameStep(name string) Step {
	return Step{
		ID:      "hostname",
		Title:   "Set hostname to " + name,
		Changes: []string{"Set the hostname to " + name + " and update /etc/hosts"},
		Weight:  1,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			if _, err := e.Host.Run(ctx, host.Command{Name: "hostnamectl", Args: []string{"set-hostname", name}, Mutates: true}); err != nil {
				return err
			}
			old, _ := e.Host.ReadFile("/etc/hosts")
			_, err := e.Host.WriteFile("/etc/hosts", HostsFile(old, name), host.FileOptions{Mode: 0o644, Backup: true})
			return err
		},
	}
}

// HostsFile points the 127.0.1.1 line of an /etc/hosts file at name.
func HostsFile(old []byte, name string) []byte {
	entry := name
	if short, _, ok := strings.Cut(name, "."); ok {
		entry = name + " " + short
	}
	if len(old) == 0 {
		return []byte("127.0.0.1\tlocalhost\n127.0.1.1\t" + entry + "\n::1\tlocalhost ip6-localhost ip6-loopback\n")
	}
	var b strings.Builder
	replaced := false
	for _, line := range strings.SplitAfter(string(old), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == "127.0.1.1" {
			if !replaced {
				b.WriteString("127.0.1.1\t" + entry + "\n")
				replaced = true
			}
			continue
		}
		b.WriteString(line)
	}
	if !replaced {
		if !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}
		b.WriteString("127.0.1.1\t" + entry + "\n")
	}
	return []byte(b.String())
}

func repositoryStep(f system.Facts) Step {
	return Step{
		ID:    "repository",
		Title: "Add the Tor Project apt repository",
		Changes: []string{
			"Verify the Tor Project signing key (" + torproject.SigningKeyFingerprint + ") and install " + torproject.KeyringPath,
			"Write " + torproject.SourcesPath + " for " + f.Codename,
		},
		Weight: 3,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			r.Progress(10, "Downloading the signing key")
			armored, err := torproject.FetchSigningKey(ctx, e.HTTP)
			if err != nil {
				return err
			}
			keyring, err := torproject.VerifySigningKey(armored)
			if err != nil {
				return err
			}
			r.Note(Success, "Signing key fingerprint verified")
			if _, err := e.Host.WriteFile(torproject.KeyringPath, keyring, host.FileOptions{Mode: 0o644}); err != nil {
				return err
			}
			if _, err := e.Host.WriteFile(torproject.SourcesPath, torproject.Sources(e.Facts.Codename), host.FileOptions{Mode: 0o644, Backup: true}); err != nil {
				return err
			}
			if _, err := e.Host.Stat(torproject.LegacySourcesPath); err == nil {
				r.Note(Warn, torproject.LegacySourcesPath+" also exists; remove it to avoid a duplicate Tor repository")
			}
			return nil
		},
	}
}

func updateStep() Step {
	return Step{
		ID:     "update",
		Title:  "Refresh package lists",
		Weight: 10,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			c := apt.Client{Host: e.Host}
			return c.Update(ctx, func(p apt.Progress) { r.Progress(p.Percent, p.Detail) }, r.Log)
		},
	}
}

func packagesStep(s config.Setup, f system.Facts) Step {
	pkgs := Packages(s, f)
	change := "Install packages in one apt transaction: " + strings.Join(pkgs, " ")
	if slices.Contains(pkgs, "obfs4proxy") {
		change += " (lyrebird instead of obfs4proxy where apt offers it)"
	}
	return Step{
		ID:      "packages",
		Title:   "Install " + strings.Join(pkgs, ", "),
		Changes: []string{change},
		Weight:  30,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			c := apt.Client{Host: e.Host}
			if !e.Host.DryRun() {
				policy, err := c.Policy(ctx, "tor")
				if err != nil {
					return err
				}
				if !torproject.CandidateFromTorProject(policy) {
					return errors.New("the apt candidate for tor does not come from deb.torproject.org (check apt-cache policy tor)")
				}
			}
			want := Packages(e.Setup, e.Facts)
			install := make([]string, 0, len(want))
			for _, p := range want {
				if p == "obfs4proxy" {
					// lyrebird is obfs4proxy's successor; Debian packages it
					// from forky on. Both serve obfs4 the same way.
					p = obfs4Package(ctx, c)
					e.Setup.Bridge.Plugin = relay.Obfs4ProxyPath
					if p == "lyrebird" {
						e.Setup.Bridge.Plugin = relay.LyrebirdPath
					}
					r.Note(Info, "obfs4 transport: "+p+" ("+e.Setup.Bridge.Plugin+")")
				}
				if p == "deb.torproject.org-keyring" && !e.Host.DryRun() {
					if ok, _ := c.CandidateAvailable(ctx, p); !ok {
						r.Note(Warn, "deb.torproject.org-keyring is not published for "+e.Facts.Codename+"; keeping the verified key file")
						continue
					}
				}
				if installed, _ := c.Installed(ctx, p); !installed {
					e.NewPackages = append(e.NewPackages, p)
				}
				install = append(install, p)
			}
			progress := func(p apt.Progress) {
				// Downloads fill the first 40%, unpacking and setup the rest.
				pct := p.Percent * 0.4
				if p.Phase == "install" {
					pct = 40 + p.Percent*0.6
				}
				r.Progress(pct, p.Detail)
			}
			if err := c.Install(ctx, install, progress, r.Log); err != nil {
				return err
			}
			if e.Host.DryRun() {
				return nil
			}
			res, err := e.Host.Run(ctx, host.Command{Name: "tor", Args: []string{"--version"}})
			if err != nil {
				return err
			}
			version, err := torproject.ParseTorVersion(res.Output)
			if err != nil {
				return err
			}
			if !torproject.VersionAtLeast(version, torproject.MinVersion) {
				return fmt.Errorf("tor %s is installed, but the Tor network rejects relays older than %s", version, torproject.MinVersion)
			}
			r.Note(Success, "tor "+version+" installed")
			return nil
		},
	}
}

// obfs4Package picks lyrebird when it is installed or apt has a candidate
// for it, else obfs4proxy.
func obfs4Package(ctx context.Context, c apt.Client) string {
	if ok, _ := c.Installed(ctx, "lyrebird"); ok {
		return "lyrebird"
	}
	if ok, _ := c.CandidateAvailable(ctx, "lyrebird"); ok {
		return "lyrebird"
	}
	return "obfs4proxy"
}

func familyStep(s config.Setup) Step {
	inst := s.Instance()
	title := "Create relay family key " + s.Family.KeyName
	change := "Generate a family key with tor --keygen-family and install it in " + inst.KeyDir + " for " + inst.User
	if !inst.IsDefault() {
		change += " (another relay on this server that already has the key shares it instead)"
	}
	if s.Family.Mode == "import" {
		title = "Import relay family key"
		change = "Install family key " + s.Family.ImportKey + " in " + inst.KeyDir + " for " + inst.User
	}
	return Step{
		ID:      "family",
		Title:   title,
		Changes: []string{change},
		Weight:  2,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			inst := e.instance()
			dir := inst.KeyDir
			var (
				name   string
				secret []byte
				id     string
			)
			switch e.Setup.Family.Mode {
			case "generate":
				if sh := e.SharedFamily; sh != nil {
					// All relays on one server share one family key.
					data, err := e.Host.ReadFile(sh.Key.Path)
					if err != nil {
						return fmt.Errorf("read family key of tor instance %s: %w", sh.Instance, err)
					}
					name, secret, id = sh.Key.Name, data, sh.Key.ID
					r.Note(Info, "Sharing family key "+name+" of tor instance "+sh.Instance+": all relays on this server are one family")
					break
				}
				name = e.Setup.Family.KeyName
				work, err := os.MkdirTemp("", "tor-family-")
				if err != nil {
					return err
				}
				defer os.RemoveAll(work)
				secret, id, err = family.Generate(ctx, e.Host, work, name)
				if err != nil {
					return err
				}
			case "import":
				path := e.Setup.Family.ImportKey
				name = strings.TrimSuffix(filepath.Base(path), ".secret_family_key")
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if !family.ValidKey(data) {
					return fmt.Errorf("%s is not a Tor family key (expected 96 bytes starting with %q)", path, family.KeyHeader)
				}
				secret = data
				id = e.Setup.Family.FamilyID
				if pub, err := os.ReadFile(strings.TrimSuffix(path, ".secret_family_key") + ".public_family_id"); err == nil {
					id = strings.TrimSpace(string(pub))
				}
				if !relay.ValidFamilyID(id) {
					return errors.New("no FamilyId: copy NAME.public_family_id next to the key, or set family.family_id")
				}
			}
			if err := family.Install(e.Host, dir, name, secret, id, inst.User); err != nil {
				return err
			}
			e.FamilyID = id
			if id != "" {
				r.Note(Success, "FamilyId "+id)
			}
			return nil
		},
	}
}

func exitDNSStep(s config.Setup) Step {
	changes := []string{"Enable Unbound and point " + resolvConf + " at 127.0.0.1 (restored automatically if DNS fails)"}
	if s.Exit.LockResolvConf {
		changes = append(changes, "Lock "+resolvConf+" with chattr +i")
	}
	return Step{
		ID:      "exit-dns",
		Title:   "Switch exit DNS to local Unbound",
		Changes: changes,
		Weight:  3,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			h := e.Host
			if res, err := h.Run(ctx, host.Command{Name: "lsattr", Args: []string{"-d", resolvConf}}); err == nil {
				if attrs := strings.Fields(res.Output); len(attrs) > 0 && strings.Contains(attrs[0], "i") {
					return errors.New(resolvConf + " is immutable; unlock it first with: chattr -i " + resolvConf)
				}
			}
			if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"enable", "--now", "unbound"}, Mutates: true}); err != nil {
				return err
			}
			if _, err := h.Run(ctx, host.Command{Name: "unbound-checkconf"}); err != nil && !h.DryRun() {
				return err
			}
			if h.DryRun() {
				_, _ = h.WriteFile(resolvConf, []byte("nameserver 127.0.0.1\n"), host.FileOptions{Backup: true})
				return nil
			}
			if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"is-active", "--quiet", "unbound"}}); err != nil {
				return errors.New("unbound is not active; check journalctl -u unbound")
			}

			link, linkErr := h.Readlink(resolvConf)
			ch, err := h.WriteFile(resolvConf, []byte("# Managed by tor-relay-setup for Tor exit DNS.\nnameserver 127.0.0.1\n"), host.FileOptions{Mode: 0o644, Backup: true})
			if err != nil {
				return err
			}
			if _, err := h.Run(ctx, host.Command{Name: "getent", Args: []string{"hosts", "deb.torproject.org"}}); err != nil {
				// Put the previous resolver configuration back before failing.
				switch {
				case linkErr == nil:
					_ = h.Symlink(link, resolvConf)
				case ch.BackupOf != "":
					if old, rerr := h.ReadFile(ch.BackupOf); rerr == nil {
						_, _ = h.WriteFile(resolvConf, old, host.FileOptions{Mode: 0o644})
					}
				}
				return errors.New("DNS stopped resolving through Unbound; the previous " + resolvConf + " was restored")
			}
			r.Note(Success, "DNS resolves through local Unbound")
			if e.Setup.Exit.LockResolvConf {
				if _, err := h.Run(ctx, host.Command{Name: "chattr", Args: []string{"+i", resolvConf}, Mutates: true}); err != nil {
					r.Note(Warn, "could not lock "+resolvConf+": "+err.Error())
				}
			}
			return nil
		},
	}
}

func unattendedStep(f system.Facts) Step {
	return Step{
		ID:    "unattended",
		Title: "Enable automatic security and Tor updates",
		Changes: []string{
			"Write " + torproject.UnattendedPath + " (security updates + Tor Project packages)",
			"Write " + torproject.AutoUpgradesPath,
		},
		Weight: 1,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			if _, err := e.Host.WriteFile(torproject.UnattendedPath, torproject.UnattendedConfig(e.Facts.OSID), host.FileOptions{Mode: 0o644, Backup: true}); err != nil {
				return err
			}
			_, err := e.Host.WriteFile(torproject.AutoUpgradesPath, torproject.AutoUpgradesConfig(), host.FileOptions{Mode: 0o644, Backup: true})
			return err
		},
	}
}

func torrcStep(s config.Setup) Step {
	return Step{
		ID:      "torrc",
		Title:   "Write and verify torrc",
		Changes: []string{"Back up and replace " + s.Instance().TorrcPath + " after tor --verify-config accepts the new version"},
		Weight:  3,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			var ids []string
			if e.FamilyID != "" {
				ids = []string{e.FamilyID}
			}
			inst := e.instance()
			if e.Setup.Relay.MetricsPort && e.Setup.Relay.MetricsAddress == "" {
				e.Setup.Relay.MetricsAddress = ResolveMetricsAddress(e.Host, e.Setup)
			}
			if e.Setup.IsWebTunnel() && e.Setup.Bridge.Path == "" {
				return errNoPath
			}
			cfg := e.Setup.RelayConfig(ids)
			if err := cfg.Validate(); err != nil {
				return err
			}
			data := cfg.Render(e.Program, e.Now())

			candidate, err := os.CreateTemp("", "torrc-candidate-")
			if err != nil {
				return err
			}
			defer os.Remove(candidate.Name())
			if _, err := candidate.Write(data); err != nil {
				_ = candidate.Close()
				return err
			}
			if err := candidate.Close(); err != nil {
				return err
			}
			r.Progress(40, "tor --verify-config")
			_, statErr := e.Host.Stat(inst.TorrcPath)
			switch err := relay.VerifyInstance(ctx, e.Host, inst, candidate.Name()); {
			case errors.Is(err, relay.ErrTorMissing) && e.Host.DryRun():
				r.Note(Info, "tor --verify-config runs once tor is installed")
			case err != nil && e.Host.DryRun() && !inst.IsDefault() && statErr != nil:
				// tor rejects the defaults' User _tor-NAME until it exists.
				r.Note(Info, "tor --verify-config runs once "+relay.InstanceCreateCommand+" has created instance "+inst.Name)
			case err != nil:
				return fmt.Errorf("tor rejected the generated torrc: %w", err)
			default:
				r.Note(Success, "tor --verify-config accepted the new torrc")
			}
			ch, err := e.Host.WriteFile(inst.TorrcPath, data, host.FileOptions{Mode: 0o644, Backup: true})
			if err != nil {
				return err
			}
			if ch.BackupOf != "" {
				r.Note(Info, "Previous torrc saved as "+ch.BackupOf)
			}
			return nil
		},
	}
}

type firewallChoice struct {
	enabled    bool
	installUFW bool
	fw         system.Firewall
}

func firewallPlan(s config.Setup, f system.Facts) firewallChoice {
	if s.System.Firewall == "none" {
		return firewallChoice{}
	}
	fw := f.Firewall
	switch fw.Kind {
	case "none", "":
		return firewallChoice{enabled: true, installUFW: true, fw: system.Firewall{Kind: "ufw"}}
	case "firewalld":
		return firewallChoice{enabled: fw.Active, fw: fw}
	case "nftables":
		return firewallChoice{enabled: strings.Contains(fw.Detail, "found"), fw: fw}
	default:
		return firewallChoice{enabled: true, fw: fw}
	}
}

func firewallStep(s config.Setup, f system.Facts, choice firewallChoice) Step {
	var ports []system.Port
	var numbers []string
	for _, p := range s.PublicPorts() {
		ports = append(ports, system.Port{Number: p.Number, Label: p.Label})
		numbers = append(numbers, strconv.Itoa(p.Number))
	}
	cmds := system.FirewallCommandsFor(choice.fw, ports, f.SSHPorts, s.System.EnableUFW, choice.installUFW)
	changes := make([]string, 0, len(cmds))
	for _, c := range cmds {
		changes = append(changes, c.String())
	}
	title := "Open ORPort " + strconv.Itoa(s.Relay.ORPort) + " in " + choice.fw.Kind
	if len(ports) > 1 || s.IsWebTunnel() {
		title = "Open TCP " + strings.Join(numbers, ", ") + " in " + choice.fw.Kind
	}
	return Step{
		ID:      "firewall",
		Title:   title,
		Changes: changes,
		Weight:  2,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			for _, c := range cmds {
				if _, err := e.Host.Run(ctx, c); err != nil {
					return err
				}
			}
			r.Note(Info, "Open TCP "+strings.Join(numbers, ", ")+" in your provider's cloud firewall too")
			return nil
		},
	}
}

func serviceStep(s config.Setup) Step {
	return Step{
		ID:      "service",
		Title:   "Start Tor",
		Changes: []string{"Enable and restart " + s.Instance().Unit},
		Weight:  6,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			unit := e.instance().Unit
			tor := service.Tor{Host: e.Host, Unit: unit}
			if err := tor.Enable(ctx); err != nil {
				return err
			}
			e.RestartedAt = e.Now()
			if err := tor.Restart(ctx); err != nil {
				return err
			}
			if e.Host.DryRun() {
				return nil
			}
			r.Progress(40, "Waiting for "+unit)
			if !waitFor(ctx, 15*time.Second, func() bool { return tor.Active(ctx) }) {
				return errors.New(unit + " is not active; check journalctl -u " + unit + " -n 100")
			}
			type listener struct {
				port int
				what string
			}
			var wait []listener
			switch s := e.Setup; {
			case s.IsWebTunnel():
				wait = []listener{{s.WebTunnelPort(), "the webtunnel transport"}}
			case s.IsBridge():
				wait = []listener{{s.Relay.ORPort, "Tor"}, {s.Bridge.Obfs4Port, "the obfs4 transport"}}
			default:
				wait = []listener{{s.Relay.ORPort, "Tor"}}
			}
			r.Progress(70, "Waiting for the listeners")
			for _, l := range wait {
				if waitFor(ctx, 20*time.Second, func() bool {
					v4, v6, _ := system.Listening(e.Host, l.port)
					return v4 || v6
				}) {
					r.Note(Success, fmt.Sprintf("%s is listening on TCP %d", l.what, l.port))
				} else {
					r.Note(Warn, fmt.Sprintf("no listener on TCP %d yet; check the Tor log", l.port))
				}
			}
			if e.Setup.IsBridge() {
				r.Note(Info, "The bridge line appears in the console (Bridge line) once tor has started the transport; Tor Metrics lists new bridges after about three hours")
			}
			if warnings, _ := tor.FamilyWarnings(ctx, e.RestartedAt); len(warnings) > 0 {
				for _, w := range warnings {
					r.Note(Warn, w)
				}
			}
			return nil
		},
	}
}

func waitFor(ctx context.Context, limit time.Duration, ok func() bool) bool {
	deadline := time.Now().Add(limit)
	for {
		if ok() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// State is what the installer remembers about its own run.
type State struct {
	Version     string    `json:"version"`
	AppliedAt   time.Time `json:"applied_at"`
	NewPackages []string  `json:"new_packages,omitempty"`
	FamilyID    string    `json:"family_id,omitempty"`
	Instance    string    `json:"instance,omitempty"`
}

// StateFile is where stateStep records a run for inst: state.json for the
// default instance, state-NAME.json for a named one, so applying a second
// instance does not overwrite the first one's record.
func StateFile(stateDir string, inst relay.Instance) string {
	if inst.IsDefault() {
		return filepath.Join(stateDir, "state.json")
	}
	return filepath.Join(stateDir, "state-"+inst.Name+".json")
}

func stateStep() Step {
	return Step{
		ID:     "state",
		Title:  "Record setup state",
		Weight: 1,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			if err := e.Host.MkdirAll(e.StateDir, 0o700, ""); err != nil {
				return err
			}
			data, err := json.MarshalIndent(State{
				Version:     e.Program,
				AppliedAt:   e.Now().UTC(),
				NewPackages: e.NewPackages,
				FamilyID:    e.FamilyID,
				Instance:    instanceLabel(e.instance()),
			}, "", "  ")
			if err != nil {
				return err
			}
			_, err = e.Host.WriteFile(StateFile(e.StateDir, e.instance()), append(data, '\n'), host.FileOptions{Mode: 0o600})
			return err
		},
	}
}
