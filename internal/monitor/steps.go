package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/ljkx/tor-relay-setup/internal/apt"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

// Install is one `monitor install` run: Steps builds the plan, the steps
// fill in what the summary shows.
type Install struct {
	Opt     Options
	Facts   system.Facts
	Release Release

	// Health waits until url answers 200; tests replace it.
	Health func(ctx context.Context, url string) error
	// LookupHost resolves the domain for the preflight note.
	LookupHost func(ctx context.Context, name string) ([]string, error)

	// Filled in while running.
	NewPackages []string
	Password    string // set when this run generated the admin password
	PublicKey   string // the monitor's SSH public key
	ExistingDB  bool   // Grafana already had a database before this run
	token       string
	changed     map[string]bool // service -> its configuration changed
}

// NewInstall prepares a run on a host with these facts.
func NewInstall(o Options, f system.Facts) (*Install, error) {
	if err := o.Normalize(); err != nil {
		return nil, err
	}
	rel, ok := ReleaseFor(f)
	if !ok {
		names := make([]string, len(Releases))
		for i, r := range Releases {
			names[i] = r.Name + " (" + r.Codename + ")"
		}
		return nil, fmt.Errorf("monitor install supports %s; this is %s", strings.Join(names, ", "), orUnknown(f.PrettyName))
	}
	return &Install{
		Opt: o, Facts: f, Release: rel,
		Health:     waitHealthy,
		LookupHost: net.DefaultResolver.LookupHost,
		changed:    map[string]bool{},
	}, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown system"
	}
	return s
}

// Packages is the single apt transaction.
func (in *Install) Packages() []string {
	pkgs := []string{"prometheus", "grafana", "caddy", "openssh-client"}
	if in.installUFW() {
		pkgs = append(pkgs, "ufw")
	}
	return pkgs
}

func (in *Install) installUFW() bool {
	k := in.Facts.Firewall.Kind
	return k == "" || k == system.KindNone
}

// Repos are the third-party repositories this release needs.
func (in *Install) Repos() []Repo {
	repos := []Repo{GrafanaRepo}
	if in.Release.CaddyRepo {
		repos = append(repos, CaddyRepo)
	}
	return repos
}

// Steps returns the ordered plan. Firewall and the Prometheus defaults
// come before anything listens: Prometheus starts on loopback right away,
// and Grafana gets its administrator password before its first start.
func (in *Install) Steps() []plan.Step {
	return []plan.Step{
		in.preflightStep(),
		in.repositoryStep(),
		in.prometheusDefaultsStep(),
		in.updateStep(),
		in.packagesStep(),
		in.firewallStep(),
		in.monitorUserStep(),
		in.prometheusStep(),
		in.fleetServiceStep(),
		in.grafanaStep(),
		in.caddyStep(),
		in.stateStep(),
	}
}

func (in *Install) preflightStep() plan.Step {
	return plan.Step{
		ID: "preflight", Title: "Check this management server", Weight: 2,
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			if problems := in.Facts.Problems(); len(problems) > 0 {
				return errors.New(strings.Join(problems, "; "))
			}
			if !h.DryRun() && in.Facts.EUID != 0 {
				return errors.New("run as root, for example: sudo tor-relay-setup monitor install --domain " + in.Opt.Domain)
			}
			if in.Facts.MemTotalMiB > 0 && in.Facts.MemTotalMiB < 1024 {
				r.Note(plan.Warn, fmt.Sprintf("%d MiB RAM: Grafana and Prometheus want at least 1 GiB", in.Facts.MemTotalMiB))
			}
			if in.Facts.DiskFreeMiB > 0 && in.Facts.DiskFreeMiB < 4096 {
				r.Note(plan.Warn, fmt.Sprintf("only %d MiB free under /var; Prometheus keeps up to %s of history", in.Facts.DiskFreeMiB, RetentionSize))
			}
			if found, _ := relay.Discover(h); len(found) > 0 {
				r.Note(plan.Warn, "This server also runs a Tor relay. A separate management server is recommended: a relay's address is public, and Grafana does not need to be next to it")
			}
			for _, repo := range in.Repos() {
				if dup := duplicateSources(h, repo); len(dup) > 0 {
					return fmt.Errorf("%s already configures the %s repository; remove it (apt rejects the same repository with two different Signed-By keys)", strings.Join(dup, ", "), repo.Name)
				}
			}
			if in.LookupHost != nil {
				lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				addrs, err := in.LookupHost(lctx, in.Opt.Domain)
				cancel()
				if err != nil || len(addrs) == 0 {
					r.Note(plan.Warn, in.Opt.Domain+" does not resolve yet: point its A/AAAA records at this server, or Caddy cannot get a certificate")
				} else {
					r.Note(plan.Info, in.Opt.Domain+" resolves to "+strings.Join(addrs, ", ")+" (must be this server for Let's Encrypt)")
				}
			}
			if exe := in.Opt.Executable; !strings.HasPrefix(exe, "/usr/") && !strings.HasPrefix(exe, "/opt/") {
				r.Note(plan.Warn, "The fleet service will run "+exe+" as "+MonitorUser+", which may not be able to reach it there; install tor-relay-setup to /usr/local/bin (install.sh) and run monitor install from there")
			}
			in.checkInventory(h, r)
			r.Note(plan.Success, fmt.Sprintf("%s (%s) on %s is supported", in.Release.Name, in.Facts.Codename, in.Facts.Arch))
			return nil
		},
	}
}

// duplicateSources lists other apt sources that point at repo.
func duplicateSources(h host.Host, repo Repo) []string {
	var out []string
	files, _ := h.Glob("/etc/apt/sources.list.d/*")
	for _, p := range append(files, "/etc/apt/sources.list") {
		if p == repo.SourcesPath || strings.Contains(p, ".bak.") {
			continue
		}
		data, err := h.ReadFile(p)
		if err != nil {
			continue
		}
		for l := range strings.Lines(string(data)) {
			l = strings.TrimSpace(l)
			if !strings.HasPrefix(l, "#") && strings.Contains(l, repo.Host) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// checkInventory notes what fleet serve will need from the inventory.
func (in *Install) checkInventory(h host.Host, r plan.Reporter) {
	data, err := h.ReadFile(in.Opt.Inventory)
	if err != nil {
		r.Note(plan.Warn, "No inventory at "+in.Opt.Inventory+" yet: copy your fleet.toml (and the relay.toml it names) there; the fleet service starts once it exists")
		return
	}
	var inv struct {
		Hosts []struct {
			Address string `toml:"address"`
		} `toml:"host"`
	}
	if _, err := toml.Decode(string(data), &inv); err != nil {
		r.Note(plan.Warn, in.Opt.Inventory+": "+err.Error())
		return
	}
	var users []string
	for _, hst := range inv.Hosts {
		if u, _, ok := strings.Cut(hst.Address, "@"); ok && u != ProbeUser {
			users = append(users, hst.Address)
		}
	}
	if len(users) > 0 {
		r.Note(plan.Warn, "These inventory addresses name another ssh user, so fleet serve logs in as that user instead of "+ProbeUser+": "+strings.Join(users, ", ")+" (drop the user@ part in the inventory the monitoring server uses)")
	}
	r.Note(plan.Info, fmt.Sprintf("Inventory %s lists %d relay(s)", in.Opt.Inventory, len(inv.Hosts)))
}

func (in *Install) repositoryStep() plan.Step {
	var changes []string
	for _, repo := range in.Repos() {
		changes = append(changes,
			"Verify the "+repo.Name+" apt signing key ("+repo.Fingerprint+") and install "+repo.KeyringPath,
			"Write "+repo.SourcesPath+" ("+repo.URI+" "+repo.Suite+" "+repo.Components+", Signed-By that key only)")
	}
	title := "Add the Grafana apt repository"
	if in.Release.CaddyRepo {
		title = "Add the Grafana and Caddy apt repositories"
	}
	return plan.Step{
		ID: "repository", Title: title, Changes: changes, Weight: 3,
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			for _, repo := range in.Repos() {
				armored, err := repo.FetchKey(ctx, e.HTTP)
				if err != nil {
					return err
				}
				keyring, err := repo.VerifyKey(armored)
				if err != nil {
					return err
				}
				r.Note(plan.Success, repo.Name+" signing key fingerprint verified")
				if _, err := e.Host.WriteFile(repo.KeyringPath, keyring, host.FileOptions{Mode: 0o644}); err != nil {
					return err
				}
				if _, err := e.Host.WriteFile(repo.SourcesPath, repo.Sources(), host.FileOptions{Mode: 0o644, Backup: true}); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func (in *Install) prometheusDefaultsStep() plan.Step {
	return plan.Step{
		ID: "prometheus-defaults", Title: "Keep Prometheus on loopback from its first start", Weight: 1,
		Changes: []string{"Write " + PrometheusDefaults + " before the package is installed: listen on " + PrometheusListen + ", keep " + RetentionTime + " or " + RetentionSize + " of history"},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			ch, err := e.Host.WriteFile(PrometheusDefaults, PrometheusDefaultsFile(), host.FileOptions{Mode: 0o644, Backup: true})
			if !ch.Unchanged {
				in.changed["prometheus"] = true
			}
			return err
		},
	}
}

func (in *Install) updateStep() plan.Step {
	return plan.Step{
		ID: "update", Title: "Refresh package lists", Weight: 10,
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			c := apt.Client{Host: e.Host}
			return c.Update(ctx, func(p apt.Progress) { r.Progress(p.Percent, p.Detail) }, r.Log)
		},
	}
}

func (in *Install) packagesStep() plan.Step {
	pkgs := in.Packages()
	src := "Prometheus and Caddy from " + in.Release.Name + ", Grafana OSS from apt.grafana.com"
	if in.Release.CaddyRepo {
		src = "Prometheus from " + in.Release.Name + ", Grafana OSS from apt.grafana.com, Caddy from Caddy's repository"
	}
	return plan.Step{
		ID: "packages", Title: "Install " + strings.Join(pkgs, ", "), Weight: 40,
		Changes: []string{"Install packages in one apt transaction without recommended packages: " + strings.Join(pkgs, " ") + " (" + src + ")"},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			c := apt.Client{Host: e.Host, NoRecommends: true}
			for _, p := range pkgs {
				if ok, _ := c.Installed(ctx, p); !ok {
					in.NewPackages = append(in.NewPackages, p)
				}
			}
			progress := func(p apt.Progress) {
				pct := p.Percent * 0.4
				if p.Phase == "install" {
					pct = 40 + p.Percent*0.6
				}
				r.Progress(pct, p.Detail)
			}
			if err := c.Install(ctx, pkgs, progress, r.Log); err != nil {
				return err
			}
			if len(in.NewPackages) > 0 {
				r.Note(plan.Success, "Installed "+strings.Join(in.NewPackages, ", "))
			}
			return nil
		},
	}
}

// firewallCommands opens TCP 80 and 443 next to the existing SSH ports.
func (in *Install) firewallCommands() []host.Command {
	ports := []system.Port{{Number: 80, Label: "HTTP (Caddy: ACME and redirect)"}, {Number: 443, Label: "HTTPS (Caddy: Grafana)"}}
	fw := in.Facts.Firewall
	return system.FirewallCommandsFor(fw, ports, in.Facts.SSHPorts, true, in.installUFW())
}

func (in *Install) firewallStep() plan.Step {
	cmds := in.firewallCommands()
	changes := make([]string, 0, len(cmds))
	for _, c := range cmds {
		changes = append(changes, c.String())
	}
	if len(cmds) == 0 {
		changes = []string{"No firewall change: " + in.Facts.Firewall.Kind + " is " + in.Facts.Firewall.Detail + "; allow TCP 80 and 443 yourself"}
	}
	return plan.Step{
		ID: "firewall", Title: "Allow SSH, HTTP and HTTPS only", Changes: changes, Weight: 2,
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			for _, c := range cmds {
				if _, err := e.Host.Run(ctx, c); err != nil {
					return err
				}
			}
			r.Note(plan.Info, "Grafana (3000), Prometheus (9090) and fleet serve (9850) listen on loopback only; open TCP 80 and 443 in your provider's firewall too")
			return nil
		},
	}
}

func (in *Install) monitorUserStep() plan.Step {
	keyPath := MonitorHome + "/.ssh/id_ed25519"
	return plan.Step{
		ID: "monitor-user", Title: "Create the " + MonitorUser + " user and its SSH key", Weight: 2,
		Changes: []string{
			"Create system user " + MonitorUser + " (home " + MonitorHome + ", no login shell) unless it exists",
			"Generate " + keyPath + " (ed25519) unless it exists; write " + MonitorHome + "/.ssh/config (log in as " + ProbeUser + ", strict host key checking)",
		},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			if !userExists(ctx, h, MonitorUser) {
				if _, err := h.Run(ctx, host.Command{Name: "useradd", Args: []string{
					"--system", "--user-group", "--home-dir", MonitorHome, "--create-home",
					"--shell", "/usr/sbin/nologin", "--comment", "tor-relay-setup fleet monitor", MonitorUser,
				}, Mutates: true}); err != nil {
					return err
				}
			}
			if err := h.MkdirAll(MonitorHome+"/.ssh", 0o700, MonitorUser); err != nil {
				return err
			}
			if _, err := h.Stat(keyPath); err != nil {
				name := in.Facts.Hostname
				if name == "" {
					name = "monitor"
				}
				if _, err := h.Run(ctx, host.Command{Name: "runuser", Args: []string{
					"-u", MonitorUser, "--", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", MonitorUser + "@" + name, "-f", keyPath,
				}, Mutates: true}); err != nil {
					return err
				}
				if !h.DryRun() {
					r.Note(plan.Success, "Generated the monitoring SSH key "+keyPath)
				}
			}
			if pub, err := h.ReadFile(keyPath + ".pub"); err == nil {
				in.PublicKey = strings.TrimSpace(string(pub))
			}
			if _, err := h.WriteFile(MonitorHome+"/.ssh/config", SSHConfigFile(), host.FileOptions{Mode: 0o600, Owner: MonitorUser, Backup: true}); err != nil {
				return err
			}
			if _, err := h.Stat(MonitorHome + "/.ssh/known_hosts"); err != nil {
				if _, err := h.WriteFile(MonitorHome+"/.ssh/known_hosts", []byte("# Relay host keys: add the line `tor-relay-setup fleet authorize` prints on each relay.\n"), host.FileOptions{Mode: 0o644, Owner: MonitorUser}); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// userExists asks getent, which also sees users from NSS sources.
func userExists(ctx context.Context, h host.Host, name string) bool {
	_, err := h.Run(ctx, host.Command{Name: "getent", Args: []string{"passwd", name}})
	return err == nil
}

// writeGroupFile writes a root-owned file readable by group (mode 0640
// root:GROUP, the way the packages keep their own configuration).
func writeGroupFile(ctx context.Context, h host.Host, path string, data []byte, group string, backup bool) (host.Change, error) {
	ch, err := h.WriteFile(path, data, host.FileOptions{Mode: 0o640, Backup: backup})
	if err != nil {
		return ch, err
	}
	_, err = h.Run(ctx, host.Command{Name: "chown", Args: []string{"root:" + group, path}, Mutates: true})
	return ch, err
}

func (in *Install) prometheusStep() plan.Step {
	return plan.Step{
		ID: "prometheus", Title: "Configure Prometheus", Weight: 4,
		Changes: []string{
			"Write " + PrometheusToken + " (metrics bearer token, 0640 root:prometheus; kept unless --rotate-token)",
			"Write " + PrometheusRules + " (fleet alert rules) and " + PrometheusConfig + " (scrape fleet serve on " + ServeListen + " every " + ScrapeInterval + ") after promtool accepts them",
			"Enable and (re)start prometheus",
		},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			if old, err := h.ReadFile(PrometheusToken); err == nil && !in.Opt.RotateToken && len(strings.TrimSpace(string(old))) >= 32 {
				in.token = strings.TrimSpace(string(old))
			} else {
				in.token = NewToken()
				if in.Opt.RotateToken {
					r.Note(plan.Info, "New metrics token: Prometheus and fleet serve both switch to it")
				}
			}
			if err := checkPrometheus(ctx, h, in.token, r); err != nil {
				return err
			}
			if err := h.MkdirAll(filepath.Dir(PrometheusRules), 0o755, ""); err != nil {
				return err
			}
			files := []struct {
				path string
				data []byte
			}{
				{PrometheusToken, []byte(in.token + "\n")},
				{PrometheusRules, FleetRulesFile()},
				{PrometheusConfig, PrometheusConfigFile(PrometheusRules, PrometheusToken, ServeListen)},
			}
			for _, f := range files {
				ch, err := writeGroupFile(ctx, h, f.path, f.data, "prometheus", f.path != PrometheusToken)
				if err != nil {
					return err
				}
				if !ch.Unchanged {
					in.changed["prometheus"] = true
				}
			}
			return restartIfChanged(ctx, h, "prometheus", in.changed["prometheus"])
		},
	}
}

// checkPrometheus runs promtool on candidates of the config and rule file
// before they replace the real ones. promtool is read-only, so a dry run on
// a server with Prometheus installed checks them too.
func checkPrometheus(ctx context.Context, h host.Host, token string, r plan.Reporter) error {
	if _, err := h.LookPath("promtool"); err != nil {
		if h.DryRun() {
			r.Note(plan.Info, "promtool checks the configuration once Prometheus is installed")
			return nil
		}
		return errors.New("promtool not found (it comes with the prometheus package)")
	}
	dir, err := os.MkdirTemp("", "trs-prometheus-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	rules, tok, cfg := filepath.Join(dir, "rules.yml"), filepath.Join(dir, "token"), filepath.Join(dir, "prometheus.yml")
	for p, data := range map[string][]byte{rules: FleetRulesFile(), tok: []byte(token), cfg: PrometheusConfigFile(rules, tok, ServeListen)} {
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return err
		}
	}
	if _, err := h.Run(ctx, host.Command{Name: "promtool", Args: []string{"check", "config", cfg}}); err != nil {
		return fmt.Errorf("promtool rejected the generated Prometheus configuration: %w", err)
	}
	r.Note(plan.Success, "promtool accepted the configuration and the fleet rules")
	return nil
}

// restartIfChanged enables a unit and restarts it when its configuration
// changed or it is not running, so a repeated install restarts nothing.
func restartIfChanged(ctx context.Context, h host.Host, unit string, changed bool) error {
	if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"enable", unit}, Mutates: true}); err != nil {
		return err
	}
	if !changed {
		if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"is-active", "--quiet", unit}}); err == nil {
			return nil
		}
	}
	_, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"restart", unit}, Mutates: true})
	return err
}

func (in *Install) fleetServiceStep() plan.Step {
	exe := in.Opt.Executable
	return plan.Step{
		ID: "fleet-service", Title: "Run fleet serve as " + FleetUnit + ".service", Weight: 2,
		Changes: []string{
			"Write " + ServeConfigPath + " (0600 " + MonitorUser + "): listen " + ServeListen + ", inventory " + in.Opt.Inventory + ", metrics token SHA-256; your users and settings are kept",
			"Write " + FleetUnitPath + " (hardened, runs " + exe + " fleet serve as " + MonitorUser + ") and enable it",
		},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			if err := h.MkdirAll(ConfigDir, 0o755, ""); err != nil {
				return err
			}
			old, _ := h.ReadFile(ServeConfigPath)
			if old != nil && tomlValue(old, "metrics_token_sha256") != TokenSHA256(in.token) && !in.Opt.RotateToken {
				r.Note(plan.Info, "serve.toml had a different metrics token; it now matches Prometheus's")
			}
			ch, err := h.WriteFile(ServeConfigPath, ServeConfig(old, in.Opt, TokenSHA256(in.token)), host.FileOptions{Mode: 0o600, Owner: MonitorUser, Backup: true})
			if err != nil {
				return err
			}
			changed := !ch.Unchanged
			ch, err = h.WriteFile(FleetUnitPath, FleetUnitFile(exe), host.FileOptions{Mode: 0o644, Backup: true})
			if err != nil {
				return err
			}
			if !ch.Unchanged {
				changed = true
				if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"daemon-reload"}, Mutates: true}); err != nil {
					return err
				}
			}
			if _, err := h.Stat(in.Opt.Inventory); err != nil {
				_, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"enable", FleetUnit}, Mutates: true})
				r.Note(plan.Warn, FleetUnit+" is enabled but not started: no inventory at "+in.Opt.Inventory+" yet (then: systemctl start "+FleetUnit+")")
				return err
			}
			warnUnreadable(h, in.Opt.Inventory, r)
			return restartIfChanged(ctx, h, FleetUnit, changed)
		},
	}
}

// warnUnreadable notes when the inventory may be unreadable for the
// service user (it is not root and not in the file's group).
func warnUnreadable(h host.Host, path string, r plan.Reporter) {
	info, err := h.Stat(path)
	if err != nil || info.Mode().Perm()&0o004 != 0 {
		return
	}
	r.Note(plan.Warn, path+" is not world-readable: make it readable for "+MonitorUser+" (for example chgrp "+MonitorUser+" "+path+" && chmod 0640 "+path+"), and the relay.toml it names too")
}

func (in *Install) grafanaStep() plan.Step {
	return plan.Step{
		ID: "grafana", Title: "Configure Grafana", Weight: 6,
		Changes: []string{
			"Back up and replace " + GrafanaINI + " (127.0.0.1:3000, root_url " + in.Opt.URL() + ", hardened; admin user " + in.Opt.AdminUser + ")",
			"Provision data source " + DatasourceUID + " (" + GrafanaDatasource + ") and the \"Tor relays\" dashboards (" + GrafanaProvider + ", " + GrafanaDashboards + ")",
			"Generate the Grafana administrator password into " + AdminPasswordPath + " (0600 root) unless it exists, and set it with grafana cli",
			"Enable and (re)start grafana-server",
		},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			_, dbErr := h.Stat(GrafanaDB)
			in.ExistingDB = dbErr == nil
			oldINI, _ := h.ReadFile(GrafanaINI)
			secret := ExistingSecretKey(oldINI)
			if secret == "" {
				if in.ExistingDB {
					r.Note(plan.Warn, "Grafana's existing database was encrypted with its default secret_key; keeping a new random one means re-entering data source passwords you saved before")
				}
				secret = newSecretKey()
			}
			changed := false
			write := func(path string, data []byte, backup bool) error {
				ch, err := writeGroupFile(ctx, h, path, data, "grafana", backup)
				if !ch.Unchanged {
					changed = true
				}
				return err
			}
			if err := write(GrafanaINI, GrafanaINIFile(in.Opt, secret), true); err != nil {
				return err
			}
			if err := write(GrafanaDatasource, GrafanaDatasourceFile(), true); err != nil {
				return err
			}
			if err := write(GrafanaProvider, GrafanaProviderFile(GrafanaDashboards), true); err != nil {
				return err
			}
			if err := h.MkdirAll(GrafanaDashboards, 0o755, ""); err != nil {
				return err
			}
			dash := DashboardFiles()
			for _, name := range slices.Sorted(maps.Keys(dash)) {
				if err := write(GrafanaDashboards+"/"+name, dash[name], false); err != nil {
					return err
				}
			}

			password, created, err := adminPassword(h)
			if err != nil {
				return err
			}
			if created {
				in.Password = password
			}
			if created || !in.ExistingDB {
				if err := setAdminPassword(ctx, h, password); err != nil {
					return err
				}
				changed = true
				r.Note(plan.Success, "Administrator "+in.Opt.AdminUser+" has the password in "+AdminPasswordPath)
			}
			if in.ExistingDB && created {
				r.Note(plan.Info, "Grafana already had a database: the administrator (user id 1) got the new password but keeps its login name")
			}
			if err := restartIfChanged(ctx, h, "grafana-server", changed); err != nil {
				return err
			}
			if h.DryRun() || in.Health == nil {
				return nil
			}
			r.Progress(80, "Waiting for Grafana")
			if err := in.Health(ctx, "http://"+GrafanaListen+"/api/health"); err != nil {
				return fmt.Errorf("grafana-server did not become healthy (journalctl -u grafana-server -n 50): %w", err)
			}
			r.Note(plan.Success, "Grafana answers on "+GrafanaListen)
			return nil
		},
	}
}

// adminPassword reads the stored administrator password, or creates it.
func adminPassword(h host.Host) (password string, created bool, err error) {
	if data, err := h.ReadFile(AdminPasswordPath); err == nil {
		if p := strings.TrimSpace(string(data)); len(p) >= 16 {
			return p, false, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	if err := h.MkdirAll(ConfigDir, 0o755, ""); err != nil {
		return "", false, err
	}
	p := NewPassword()
	if _, err := h.WriteFile(AdminPasswordPath, []byte(p+"\n"), host.FileOptions{Mode: 0o600}); err != nil {
		return "", false, err
	}
	return p, true, nil
}

// setAdminPassword runs grafana cli as the grafana user (so its database
// files stay grafana's) with the password on standard input, never on the
// command line. On a fresh install it also creates the database and the
// administrator, so Grafana never starts with admin/admin.
func setAdminPassword(ctx context.Context, h host.Host, password string) error {
	_, err := h.Run(ctx, host.Command{
		Name: "runuser",
		Args: []string{"-u", "grafana", "--", GrafanaHome + "/bin/grafana", "cli",
			"--homepath", GrafanaHome, "--config", GrafanaINI,
			"admin", "reset-admin-password", "--password-from-stdin"},
		Stdin:   []byte(password + "\n"),
		Mutates: true,
	})
	if err != nil {
		return fmt.Errorf("set the Grafana administrator password: %w", err)
	}
	return nil
}

func (in *Install) caddyStep() plan.Step {
	what := "Grafana"
	if in.Opt.FleetPath != "" {
		what += " and the fleet UI at " + in.Opt.FleetPath + "/"
	}
	return plan.Step{
		ID: "caddy", Title: "Publish Grafana over HTTPS with Caddy", Weight: 3,
		Changes: []string{
			"Back up and replace " + Caddyfile + " after caddy validate accepts it: https://" + in.Opt.Domain + "/ serves " + what + " with automatic HTTPS and security headers",
			"Enable and reload caddy",
		},
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			data := CaddyfileContent(in.Opt)
			if err := checkCaddy(ctx, h, data, r); err != nil {
				return err
			}
			ch, err := h.WriteFile(Caddyfile, data, host.FileOptions{Mode: 0o644, Backup: true})
			if err != nil {
				return err
			}
			if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"enable", "caddy"}, Mutates: true}); err != nil {
				return err
			}
			if !ch.Unchanged {
				if _, err := h.Run(ctx, host.Command{Name: "systemctl", Args: []string{"reload-or-restart", "caddy"}, Mutates: true}); err != nil {
					return err
				}
			}
			r.Note(plan.Info, "Caddy requests the certificate for "+in.Opt.Domain+" on the first visit or within a minute; journalctl -u caddy shows the ACME log")
			return nil
		},
	}
}

func checkCaddy(ctx context.Context, h host.Host, data []byte, r plan.Reporter) error {
	if _, err := h.LookPath("caddy"); err != nil {
		if h.DryRun() {
			r.Note(plan.Info, "caddy validate checks the Caddyfile once Caddy is installed")
			return nil
		}
		return errors.New("caddy not found after installing the caddy package")
	}
	dir, err := os.MkdirTemp("", "trs-caddy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return err
	}
	if _, err := h.Run(ctx, host.Command{Name: "caddy", Args: []string{"validate", "--adapter", "caddyfile", "--config", p}}); err != nil {
		return fmt.Errorf("caddy rejected the generated Caddyfile: %w", err)
	}
	return nil
}

// State is what monitor install remembers, for status and uninstall.
type State struct {
	Version     string    `json:"version"`
	InstalledAt time.Time `json:"installed_at"`
	Domain      string    `json:"domain"`
	AdminUser   string    `json:"admin_user"`
	FleetPath   string    `json:"fleet_path,omitempty"`
	Inventory   string    `json:"inventory"`
	NewPackages []string  `json:"new_packages,omitempty"`
	Repos       []string  `json:"repos,omitempty"` // sources files this tool wrote
}

// ReadState reads the state file; a missing file is the zero State.
func ReadState(h host.Host) (State, error) {
	var s State
	data, err := h.ReadFile(StatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

func (in *Install) stateStep() plan.Step {
	return plan.Step{
		ID: "state", Title: "Record the monitoring setup", Weight: 1,
		Run: func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			h := e.Host
			old, _ := ReadState(h)
			s := State{
				Version: in.Opt.Version, InstalledAt: e.Now().UTC(), Domain: in.Opt.Domain,
				AdminUser: in.Opt.AdminUser, FleetPath: in.Opt.FleetPath, Inventory: in.Opt.Inventory,
			}
			// Packages this tool installed at any run stay "ours".
			s.NewPackages = slices.Compact(slices.Sorted(slices.Values(append(old.NewPackages, in.NewPackages...))))
			for _, repo := range in.Repos() {
				s.Repos = append(s.Repos, repo.SourcesPath)
			}
			if err := h.MkdirAll(filepath.Dir(StatePath), 0o700, ""); err != nil {
				return err
			}
			data, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				return err
			}
			_, err = h.WriteFile(StatePath, append(data, '\n'), host.FileOptions{Mode: 0o600})
			return err
		},
	}
}

// waitHealthy polls url until it answers 200 OK, for up to a minute.
func waitHealthy(ctx context.Context, url string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(time.Minute)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("%s returned %s", url, resp.Status)
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return last
}

// SummaryLines is the final message of a successful install.
func (in *Install) SummaryLines() []string {
	lines := []string{
		"Grafana        " + in.Opt.URL(),
		"Admin user     " + in.Opt.AdminUser,
		"Password file  " + AdminPasswordPath + " (root only; back it up in your password manager)",
	}
	if in.Password != "" {
		lines = append(lines, "Password       "+in.Password+"   (shown once)")
	}
	if in.Opt.FleetPath != "" {
		lines = append(lines, "Fleet UI       https://"+in.Opt.Domain+in.Opt.FleetPath+"/  (add a login: sudo tor-relay-setup fleet serve passwd NAME)")
	}
	pub := in.PublicKey
	if pub == "" {
		pub = "ssh-ed25519 AAAA… " + MonitorUser + "@" + orUnknown(in.Facts.Hostname)
	}
	lines = append(lines,
		"",
		"Monitoring SSH key ("+MonitorHome+"/.ssh/id_ed25519.pub):",
		"  "+pub,
		"",
		"On every relay, let this server probe it (installs a forced-command key for user "+ProbeUser+"):",
		"  "+AuthorizeCommand(pub),
		"Or add this line to ~"+ProbeUser+"/.ssh/authorized_keys yourself (plus the sudoers rule in docs/monitoring/README.md):",
		"  "+AuthorizedKeysLine(pub, "/usr/local/bin/tor-relay-setup", []string{"MONITOR_IP"}),
		"",
		"Then add each relay's host key line (fleet authorize prints it) to "+MonitorHome+"/.ssh/known_hosts,",
		"and check one with: sudo -u "+MonitorUser+" ssh RELAY | head -c 300",
	)
	return lines
}
