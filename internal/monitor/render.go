package monitor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/ljkx/tor-relay-setup/docs/monitoring"
)

const header = "Written by tor-relay-setup monitor install; re-running it rewrites this file (the previous version is kept as a .bak.* copy next to it)."

// PrometheusDefaultsFile is /etc/default/prometheus: loopback only, and
// RetentionTime or RetentionSize of history, whichever is reached first.
// It is written before the package is installed, so the very first start
// of Debian's prometheus service already listens on loopback only.
func PrometheusDefaultsFile() []byte {
	return []byte("# " + header + `
# Prometheus listens on loopback only; Grafana reads it there. History is kept
# for ` + RetentionTime + ` or until it takes ` + RetentionSize + `, whichever comes first.
ARGS="--web.listen-address=` + PrometheusListen + ` --storage.tsdb.retention.time=` + RetentionTime + ` --storage.tsdb.retention.size=` + RetentionSize + `"
`)
}

// PrometheusConfigFile renders prometheus.yml. rules and token are the
// rule file and the bearer-token file (parameters so a candidate can be
// checked with promtool before it replaces the real one); target is the
// fleet serve address.
func PrometheusConfigFile(rules, token, target string) []byte {
	return []byte("# " + header + `
global:
  scrape_interval: ` + ScrapeInterval + `
  scrape_timeout: 20s
  evaluation_interval: ` + ScrapeInterval + `

rule_files:
  - ` + rules + `

scrape_configs:
  # tor-relay-setup fleet serve: one scrape returns the whole fleet
  # (docs/monitoring/fleet-metrics.md). The bearer token file is shared
  # with fleet serve, which stores only its SHA-256.
  - job_name: tor-relay-fleet
    metrics_path: ` + MetricsPath + `
    authorization:
      type: Bearer
      credentials_file: ` + token + `
    static_configs:
      - targets: ["` + target + `"]

  - job_name: prometheus
    static_configs:
      - targets: ["` + PrometheusListen + `"]
`)
}

// FleetRulesFile is the Prometheus rule file for the fleet metrics.
func FleetRulesFile() []byte { return monitoring.FleetRules }

// GrafanaINIFile renders grafana.ini. secretKey encrypts secrets in
// Grafana's database and must stay the same across runs.
func GrafanaINIFile(o Options, secretKey string) []byte {
	host, port, _ := strings.Cut(GrafanaListen, ":")
	// Public mode: only Caddy talks to Grafana, over loopback, and the
	// browser sees HTTPS. Local mode: the browser talks to Grafana through
	// an SSH tunnel as http://localhost:3000, so the Host header is
	// localhost:3000, the connection is plain HTTP (the tunnel is the
	// encryption), and Secure cookies or HSTS would break the login.
	server := `; Only Caddy talks to Grafana; it terminates HTTPS for ` + o.Domain + `.
protocol = http
http_addr = ` + host + `
http_port = ` + port + `
domain = ` + o.Domain + `
enforce_domain = true
root_url = ` + o.URL() + `
serve_from_sub_path = false
router_logging = false
; Caddy compresses responses.
enable_gzip = false
`
	transport := `cookie_secure = true
cookie_samesite = strict
allow_embedding = false
strict_transport_security = true
`
	if o.Local {
		server = `; Local mode: Grafana listens on loopback only and is reached through an SSH
; tunnel (ssh -N -L 3000:127.0.0.1:3000 ...) as http://localhost:3000. The
; tunnel encrypts; nothing else can connect.
protocol = http
http_addr = ` + host + `
http_port = ` + port + `
domain = localhost
enforce_domain = false
root_url = ` + o.URL() + `
serve_from_sub_path = false
router_logging = false
; No compression (ssh -C compresses the tunnel if wanted).
enable_gzip = false
`
		transport = `; Plain HTTP inside the SSH tunnel: Secure cookies and HSTS would stop the
; browser from keeping the login at http://localhost:3000.
cookie_secure = false
cookie_samesite = strict
allow_embedding = false
strict_transport_security = false
`
	}
	return []byte("; " + header + `
; The administrator password is not stored here: it is in
; ` + AdminPasswordPath + ` (root only) and set with grafana cli.

[paths]
data = /var/lib/grafana
logs = /var/log/grafana
plugins = /var/lib/grafana/plugins
provisioning = /etc/grafana/provisioning

[server]
` + server + `
[analytics]
; No usage reports, update checks or feedback links: nothing leaves this
; server unless an operator opens a link.
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
feedback_links_enabled = false

[security]
admin_user = ` + o.AdminUser + `
secret_key = ` + secretKey + `
disable_gravatar = true
` + transport + `strict_transport_security_max_age_seconds = 31536000
strict_transport_security_preload = false
strict_transport_security_subdomains = false
x_content_type_options = true
x_xss_protection = true
content_security_policy = true
disable_brute_force_login_protection = false
; The data source proxy may only reach the local Prometheus.
data_source_proxy_whitelist = ` + PrometheusListen + `

[users]
allow_sign_up = false
allow_org_create = false
auto_assign_org_role = Viewer
viewers_can_edit = false
; Neutral login form hints.
login_hint = username
password_hint = password

[auth]
disable_login_form = false
login_maximum_inactive_lifetime_duration = 7d
login_maximum_lifetime_duration = 30d

[auth.anonymous]
enabled = false

[auth.basic]
; No HTTP basic authentication on the API: log in through the form.
enabled = false

[snapshots]
enabled = false
external_enabled = false

[public_dashboards]
enabled = false

[news]
news_feed_enabled = false

[plugins]
; Only the built-in panels are used; nothing is installed or updated from
; grafana.com.
plugin_admin_enabled = false
preinstall_disabled = true
preinstall_auto_update = false

[cloud_migration]
enabled = false

[dashboards]
default_home_dashboard_path = ` + GrafanaDashboards + `/` + monitoring.OverviewFile + `

[unified_alerting]
; Prometheus evaluates the alert rules; Grafana lists them (Alerting ->
; Alert rules, data source-managed) and the overview shows firing ones.
enabled = true
`)
}

// GrafanaDatasourceFile provisions the Prometheus data source.
func GrafanaDatasourceFile() []byte {
	return []byte("# " + header + `
apiVersion: 1
datasources:
  - name: Tor Prometheus
    uid: ` + DatasourceUID + `
    type: prometheus
    access: proxy
    url: http://` + PrometheusListen + `
    isDefault: true
    editable: false
    jsonData:
      httpMethod: POST
      timeInterval: ` + ScrapeInterval + `
      prometheusType: Prometheus
      manageAlerts: false
`)
}

// GrafanaProviderFile provisions the dashboards in dir into the
// "Tor relays" folder. They are read-only in the UI: edits would be lost
// on the next install anyway (save a copy instead).
func GrafanaProviderFile(dir string) []byte {
	return []byte("# " + header + `
apiVersion: 1
providers:
  - name: tor-relay-setup
    orgId: 1
    folder: Tor relays
    folderUid: ` + FolderUID + `
    type: file
    disableDeletion: true
    allowUiUpdates: false
    updateIntervalSeconds: 60
    options:
      path: ` + dir + `
      foldersFromFilesStructure: false
`)
}

// DashboardFiles returns the provisioned dashboards by file name.
func DashboardFiles() map[string][]byte { return monitoring.Dashboards() }

// CaddyfileContent renders the Caddyfile: automatic HTTPS for the domain,
// security headers, Grafana at /, and the fleet web UI at FleetPath when
// enabled. HTTP/3 (UDP 443) is off so the firewall needs TCP 80/443 only.
func CaddyfileContent(o Options) []byte {
	var b strings.Builder
	b.WriteString("# " + header + "\n{\n")
	if o.Email != "" {
		b.WriteString("\temail " + o.Email + "\n")
	}
	b.WriteString(`	servers {
		protocols h1 h2
	}
}

` + o.Domain + ` {
	encode zstd gzip
	header {
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
		Referrer-Policy "same-origin"
		Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
		Cross-Origin-Opener-Policy "same-origin"
		-Server
	}
`)
	if o.FleetPath != "" {
		p := o.FleetPath
		b.WriteString(`
	# The fleet web UI (tor-relay-setup fleet serve, base_path ` + p + `). Its
	# metrics are for the local Prometheus only; Caddy tries the more
	# specific handle first.
	redir ` + p + ` ` + p + `/ 308
	handle ` + p + `/metrics* {
		respond 404
	}
	handle ` + p + `/* {
		reverse_proxy ` + ServeListen + `
	}
`)
	}
	b.WriteString(`
	handle {
		reverse_proxy ` + GrafanaListen + `
	}
}
`)
	return []byte(b.String())
}

// FleetUnitFile is the systemd unit that runs fleet serve as MonitorUser.
//
// The service needs outbound TCP (ssh to every relay, Tor Metrics over
// HTTPS) and a loopback listener, reads its config, the inventory and its
// SSH key, and writes only its cache directory. Everything else is taken
// away; each line says why it is safe.
func FleetUnitFile(exe string) []byte {
	return []byte("# " + header + `
[Unit]
Description=tor-relay-setup fleet monitor (SSH probes, metrics on ` + ServeListen + `)
Documentation=https://github.com/ljkx/tor-relay-setup/blob/main/docs/monitoring/README.md
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=` + MonitorUser + `
Group=` + MonitorUser + `
ExecStart=` + exe + ` fleet serve --config ` + ServeConfigPath + `
Restart=on-failure
RestartSec=10s
# The flag cache (os.UserCacheDir); systemd creates the directory owned by
# the service user, and it is the only place the service can write.
CacheDirectory=tor-relay-setup-fleet
CacheDirectoryMode=0700
Environment=XDG_CACHE_HOME=/var/cache/tor-relay-setup-fleet
# Files it creates are private.
UMask=0077
# No privileges at all: the service needs none and can never gain any
# (setuid programs such as sudo do not work inside it either).
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
# The whole file system is read-only except the cache directory; ssh reads
# its key, config and known_hosts from ` + MonitorHome + `/.ssh.
ProtectSystem=strict
# /home, /root and /run/user are invisible (the service user's home is in /var/lib).
ProtectHome=yes
# ssh's ControlMaster sockets go to a private /tmp.
PrivateTmp=yes
# No physical devices; ssh and HTTPS need none.
PrivateDevices=yes
# Never changes kernel settings, modules, logs, cgroups, the clock or the host name.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
# Sees only its own processes in /proc.
ProtectProc=invisible
ProcSubset=pid
# IPv4/IPv6 for ssh, HTTPS and the listener; unix sockets for ssh's
# connection sharing and the journal.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
# Go and OpenSSH never need writable executable memory.
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
# Not set: PrivateNetwork/IPAddressDeny (it must reach every relay over
# ssh, and relays can be anywhere), PrivateUsers (ssh checks that its
# config and key files belong to the user and root).

[Install]
WantedBy=multi-user.target
`)
}

// SSHConfigFile is MonitorUser's ~/.ssh/config: log in as ProbeUser with
// the generated key only, never ask anything, and never trust an unknown
// host key (add relays to known_hosts with the line fleet authorize prints).
func SSHConfigFile() []byte {
	return []byte("# " + header + `
# Relays are reached as ` + ProbeUser + `; a forced command there runs only
# "sudo -n tor-relay-setup fleet-probe". Inventory addresses should have no
# user@ part (or ` + ProbeUser + `@), because user@ overrides User below.
Host *
    User ` + ProbeUser + `
    IdentityFile ` + MonitorHome + `/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking yes
    UpdateHostKeys no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 2
    ForwardAgent no
    ForwardX11 no
    ClearAllForwardings yes
    RequestTTY no
`)
}

// Managed serve.toml keys are rewritten on every install; the others
// (users added with `fleet serve passwd`, privacy, probe_interval, ...)
// are written once and then belong to the operator.
func serveManaged(o Options, tokenSHA256 string) map[string]string {
	// Caddy passes the prefix on; fleet serve accepts it either way.
	base := o.FleetPath + "/"
	// Caddy on loopback: its X-Forwarded-For/-Proto are believed (login
	// rate limits per client, Secure cookies).
	proxies := `["127.0.0.1", "::1"]`
	if o.Local {
		// No proxy in local mode: requests come straight through the SSH
		// tunnel, so no forwarded header is believed. An empty base_path is
		// the root.
		base, proxies = "", "[]"
	}
	return map[string]string{
		"listen":               quote(ServeListen),
		"base_path":            quote(base),
		"inventory":            quote(o.Inventory),
		"metrics_auth":         "true",
		"metrics_token_sha256": quote(tokenSHA256),
		"trusted_proxies":      proxies,
	}
}

var serveDefaults = map[string]string{
	"probe_interval": quote("30s"),
	"privacy":        "false",
}

// ServeConfig returns serve.toml: old with the managed keys set (and the
// defaults added when missing), or a new file when old is empty.
func ServeConfig(old []byte, o Options, tokenSHA256 string) []byte {
	managed := serveManaged(o, tokenSHA256)
	if len(strings.TrimSpace(string(old))) == 0 {
		old = []byte(`# tor-relay-setup fleet serve configuration, written by monitor install.
# monitor install keeps listen, base_path, inventory, metrics_auth,
# metrics_token_sha256 and trusted_proxies in sync; everything else is yours.
# Add web UI users with: sudo tor-relay-setup fleet serve passwd NAME
# privacy = true leaves per-relay traffic and connection series out of
# /metrics (fleet totals stay).
`)
		maps.Copy(managed, serveDefaults)
	}
	return upsertTOML(old, managed)
}

var tomlKeyRE = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=`)

// upsertTOML sets top-level keys (those before the first table header) in
// a TOML document, replacing existing assignments and appending new ones
// in sorted order at the end of the top-level section.
func upsertTOML(doc []byte, keys map[string]string) []byte {
	lines := strings.SplitAfter(string(doc), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	end := len(lines)
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "[") {
			end = i
			break
		}
	}
	done := map[string]bool{}
	for i := range end {
		m := tomlKeyRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		if v, ok := keys[m[1]]; ok {
			lines[i] = m[1] + " = " + v + "\n"
			done[m[1]] = true
		}
	}
	var add []string
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		if !done[k] {
			add = append(add, k+" = "+keys[k]+"\n")
		}
	}
	// New keys go after the last top-level line, before blank lines that
	// separate the first table.
	at := end
	for at > 0 && strings.TrimSpace(lines[at-1]) == "" {
		at--
	}
	if at > 0 && !strings.HasSuffix(lines[at-1], "\n") {
		lines[at-1] += "\n"
	}
	out := slices.Concat(lines[:at], add, lines[at:])
	return []byte(strings.Join(out, ""))
}

// tomlValue returns the raw value of a top-level key, or "".
func tomlValue(doc []byte, key string) string {
	for l := range strings.Lines(string(doc)) {
		if strings.HasPrefix(strings.TrimSpace(l), "[") {
			break
		}
		if m := tomlKeyRE.FindStringSubmatch(l); m != nil && m[1] == key {
			_, v, _ := strings.Cut(l, "=")
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func quote(s string) string { return `"` + s + `"` }

// NewToken returns a fresh 256-bit metrics bearer token (hex).
func NewToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

// TokenSHA256 is what serve.toml stores instead of the token.
func TokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewPassword returns a random administrator password: 32 characters from
// 57 letters and digits that cannot be mistaken for each other (about
// 186 bits).
func NewPassword() string {
	return randomString("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", 32)
}

// newSecretKey returns a Grafana secret_key.
func newSecretKey() string {
	return randomString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 40)
}

func randomString(alphabet string, n int) string {
	out := make([]byte, n)
	buf := make([]byte, 1)
	limit := 256 - 256%len(alphabet) // reject bytes that would bias the result
	for i := 0; i < n; {
		_, _ = rand.Read(buf)
		if int(buf[0]) >= limit {
			continue
		}
		out[i] = alphabet[int(buf[0])%len(alphabet)]
		i++
	}
	return string(out)
}

// grafanaDefaultSecret is the well-known secret_key in Grafana's defaults.
const grafanaDefaultSecret = "SW2YcwTIb9zpOOhoPsMm" //nolint:gosec // Grafana's published default, recognised so it is replaced

var iniSecretRE = regexp.MustCompile(`(?m)^\s*secret_key\s*=\s*(\S+)\s*$`)

// ExistingSecretKey returns the secret_key of an existing grafana.ini,
// unless it is missing, commented out, or Grafana's public default.
func ExistingSecretKey(ini []byte) string {
	m := iniSecretRE.FindSubmatch(ini)
	if m == nil || string(m[1]) == grafanaDefaultSecret {
		return ""
	}
	return string(m[1])
}

// AuthorizeCommand is what an operator runs on each relay to let this
// monitoring server in.
func AuthorizeCommand(pubKey string) string {
	return fmt.Sprintf("sudo tor-relay-setup fleet authorize --key '%s' --from MONITOR_IP", strings.TrimSpace(pubKey))
}
