package plan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// TorUser owns Tor's data and key directories on Debian and Ubuntu.
const TorUser = "debian-tor"

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
	if s.Family.Mode == "generate" || s.Family.Mode == "import" {
		steps = append(steps, familyStep(s))
	}
	if s.IsExit() && s.Exit.Unbound {
		steps = append(steps, exitDNSStep(s))
	}
	if s.System.UnattendedUpgrades {
		steps = append(steps, unattendedStep(f))
	}
	steps = append(steps, torrcStep())
	if fw := firewallPlan(s, f); fw.enabled {
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
			if s.Family.Mode == "generate" {
				key := family.KeyDirectory("", "", "/var/lib/tor") + "/" + s.Family.KeyName + ".secret_family_key"
				if _, err := e.Host.Stat(key); err == nil {
					return fmt.Errorf("a family key named %q already exists (%s); choose another name or import it instead", s.Family.KeyName, key)
				}
			}
			need := system.RequiredRAMMiB(s.IsExit())
			if e.Facts.MemTotalMiB > 0 && e.Facts.MemTotalMiB < need {
				r.Note(Warn, fmt.Sprintf("%d MiB RAM is below Tor's recommended %d MiB for this relay type", e.Facts.MemTotalMiB, need))
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
	return Step{
		ID:      "packages",
		Title:   "Install " + strings.Join(pkgs, ", "),
		Changes: []string{"Install packages in one apt transaction: " + strings.Join(pkgs, " ")},
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

func familyStep(s config.Setup) Step {
	title := "Create relay family key " + s.Family.KeyName
	change := "Generate a family key with tor --keygen-family and install it for " + TorUser
	if s.Family.Mode == "import" {
		title = "Import relay family key"
		change = "Install family key " + s.Family.ImportKey + " for " + TorUser
	}
	return Step{
		ID:      "family",
		Title:   title,
		Changes: []string{change},
		Weight:  2,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			dir := family.KeyDirectory("", "", "/var/lib/tor")
			var (
				name   string
				secret []byte
				id     string
			)
			switch e.Setup.Family.Mode {
			case "generate":
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
			if err := family.Install(e.Host, dir, name, secret, id, TorUser); err != nil {
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

func torrcStep() Step {
	return Step{
		ID:      "torrc",
		Title:   "Write and verify torrc",
		Changes: []string{"Back up and replace /etc/tor/torrc after tor --verify-config accepts the new version"},
		Weight:  3,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			var ids []string
			if e.FamilyID != "" {
				ids = []string{e.FamilyID}
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
			switch err := relay.Verify(ctx, e.Host, candidate.Name()); {
			case errors.Is(err, relay.ErrTorMissing) && e.Host.DryRun():
				r.Note(Info, "tor --verify-config runs once tor is installed")
			case err != nil:
				return fmt.Errorf("tor rejected the generated torrc: %w", err)
			default:
				r.Note(Success, "tor --verify-config accepted the new torrc")
			}
			ch, err := e.Host.WriteFile(e.TorrcPath, data, host.FileOptions{Mode: 0o644, Backup: true})
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
	cmds := system.FirewallCommands(choice.fw, s.Relay.ORPort, f.SSHPorts, s.System.EnableUFW, choice.installUFW)
	changes := make([]string, 0, len(cmds))
	for _, c := range cmds {
		changes = append(changes, c.String())
	}
	return Step{
		ID:      "firewall",
		Title:   "Open ORPort " + strconv.Itoa(s.Relay.ORPort) + " in " + choice.fw.Kind,
		Changes: changes,
		Weight:  2,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			for _, c := range cmds {
				if _, err := e.Host.Run(ctx, c); err != nil {
					return err
				}
			}
			r.Note(Info, "Open TCP "+strconv.Itoa(e.Setup.Relay.ORPort)+" in your provider's cloud firewall too")
			return nil
		},
	}
}

func serviceStep(s config.Setup) Step {
	return Step{
		ID:      "service",
		Title:   "Start Tor",
		Changes: []string{"Enable and restart " + service.DefaultUnit},
		Weight:  6,
		Run: func(ctx context.Context, e *Env, r Reporter) error {
			tor := service.Tor{Host: e.Host, Unit: service.DefaultUnit}
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
			r.Progress(40, "Waiting for "+service.DefaultUnit)
			if !waitFor(ctx, 15*time.Second, func() bool { return tor.Active(ctx) }) {
				return errors.New(service.DefaultUnit + " is not active; check journalctl -u " + service.DefaultUnit + " -n 100")
			}
			r.Progress(70, "Waiting for the ORPort listener")
			if waitFor(ctx, 20*time.Second, func() bool {
				v4, v6, _ := system.Listening(e.Host, e.Setup.Relay.ORPort)
				return v4 || v6
			}) {
				r.Note(Success, fmt.Sprintf("Tor is listening on TCP %d", e.Setup.Relay.ORPort))
			} else {
				r.Note(Warn, fmt.Sprintf("no listener on TCP %d yet; check the Tor log", e.Setup.Relay.ORPort))
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
			}, "", "  ")
			if err != nil {
				return err
			}
			_, err = e.Host.WriteFile(filepath.Join(e.StateDir, "state.json"), append(data, '\n'), host.FileOptions{Mode: 0o600})
			return err
		},
	}
}
