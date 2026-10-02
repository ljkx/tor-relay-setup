package alert

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultConfigPath is where `alert run` reads its configuration. The file
// may hold access tokens, so it should be mode 0600.
const DefaultConfigPath = "/etc/tor-relay-setup/alerts.toml"

// Config is alerts.toml. Notifier sections are TOML arrays of tables
// ([[ntfy]], [[webhook]], [[email]], [[command]]), so several of each kind
// can be configured; every notifier receives every message.
type Config struct {
	// Name labels the relay in messages; default: the nickname, else the
	// host name.
	Name string `toml:"name"`
	// MinSeverity drops less severe alerts from notifications (they are
	// still tracked). Default "warning".
	MinSeverity Severity `toml:"min_severity"`
	// RemindEvery repeats a notification for a problem that is still
	// present; "0s" never repeats. Default 24h.
	RemindEvery Duration `toml:"remind_every"`
	// AccountingThreshold is the share of AccountingMax, in percent, from
	// which accounting warns. Default 90.
	AccountingThreshold int `toml:"accounting_threshold"`
	// OverloadHold keeps an overload alert open this long after the signal
	// last fired, so a flapping signal does not notify every run. Default
	// 6h, tor's onionskin assessment period.
	OverloadHold Duration `toml:"overload_hold"`
	// WatchFlags are the consensus flags whose loss is reported. Default
	// Guard, Stable, Fast, HSDir.
	WatchFlags []string `toml:"watch_flags"`
	// CheckUpdates reports a newer tor package (apt-cache policy, from the
	// package lists apt last downloaded). Default false.
	CheckUpdates bool `toml:"check_updates"`

	Ntfy    []NtfyConfig    `toml:"ntfy"`
	Webhook []WebhookConfig `toml:"webhook"`
	Email   []EmailConfig   `toml:"email"`
	Command []CommandConfig `toml:"command"`
}

// NtfyConfig posts to an ntfy topic (https://ntfy.sh or a self-hosted
// server).
type NtfyConfig struct {
	URL   string   `toml:"url"`   // topic URL, e.g. https://ntfy.sh/my-relay-alerts
	Token string   `toml:"token"` // optional access token (Authorization: Bearer)
	Tags  []string `toml:"tags"`  // extra tags; severity tags are added automatically
}

// WebhookConfig posts JSON to a URL. Format "json" (default) sends the
// whole Message; "slack" sends {"text": ...}, which Slack, Mattermost,
// Rocket.Chat, Discord's /slack endpoint and Matrix hookshot accept.
type WebhookConfig struct {
	URL     string            `toml:"url"`
	Format  string            `toml:"format"`
	Headers map[string]string `toml:"headers"` // e.g. Authorization
}

// EmailConfig sends mail through the local MTA's sendmail -t.
type EmailConfig struct {
	To       []string `toml:"to"`
	From     string   `toml:"from"`     // default: the MTA's default sender
	Sendmail string   `toml:"sendmail"` // default /usr/sbin/sendmail
}

// CommandConfig runs a program with the Message as JSON on standard input.
type CommandConfig struct {
	Argv    []string `toml:"argv"` // argv[0] must be an absolute path
	Timeout Duration `toml:"timeout"`
}

// Duration is a time.Duration written as a Go duration string ("24h").
type Duration struct{ time.Duration }

// UnmarshalText parses a Go duration string.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", b)
	}
	d.Duration = v
	return nil
}

// MarshalText writes the duration string.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Defaults.
const (
	defaultRemind      = 24 * time.Hour
	defaultHold        = 6 * time.Hour
	defaultThreshold   = 90
	defaultSendmail    = "/usr/sbin/sendmail"
	defaultCommandWait = 30 * time.Second
)

// DefaultWatchFlags are the flags whose loss is reported by default.
var DefaultWatchFlags = []string{"Guard", "Stable", "Fast", "HSDir"}

// DefaultConfig is the configuration before alerts.toml is applied.
func DefaultConfig() Config {
	return Config{
		MinSeverity:         Warning,
		RemindEvery:         Duration{defaultRemind},
		AccountingThreshold: defaultThreshold,
		OverloadHold:        Duration{defaultHold},
		WatchFlags:          slices.Clone(DefaultWatchFlags),
	}
}

// ParseConfig decodes alerts.toml on top of DefaultConfig, rejecting
// unknown keys, and validates it. Errors never contain tokens or URLs.
func ParseConfig(data []byte) (Config, error) {
	c := DefaultConfig()
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		var perr toml.ParseError
		if errors.As(err, &perr) {
			// The default message quotes the offending line, which may hold a token.
			where := fmt.Sprintf("line %d", perr.Position.Line)
			if perr.LastKey != "" {
				where += " (" + perr.LastKey + ")"
			}
			return Config{}, fmt.Errorf("parse alert config: %s: %s", where, perr.Message)
		}
		return Config{}, fmt.Errorf("parse alert config: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("unknown alert config keys: %s", strings.Join(keys, ", "))
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks every setting and returns all problems at once.
func (c Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if c.AccountingThreshold < 1 || c.AccountingThreshold > 100 {
		add("accounting_threshold: must be 1-100")
	}
	for _, f := range c.WatchFlags {
		if !validFlag(f) {
			add("watch_flags: %q is not a relay flag name", f)
		}
	}
	if strings.ContainsAny(c.Name, "\r\n") || len(c.Name) > 64 {
		add("name: at most 64 characters on one line")
	}
	for i, n := range c.Ntfy {
		if err := checkURL(n.URL, true); err != nil {
			add("ntfy[%d].url: %v", i, err)
		}
		if strings.ContainsAny(n.Token, "\r\n ") {
			add("ntfy[%d].token: must not contain spaces or line breaks", i)
		}
		for _, t := range n.Tags {
			if t == "" || strings.ContainsAny(t, ",\r\n") {
				add("ntfy[%d].tags: tags must be non-empty and contain no comma", i)
			}
		}
	}
	for i, w := range c.Webhook {
		if err := checkURL(w.URL, false); err != nil {
			add("webhook[%d].url: %v", i, err)
		}
		switch w.Format {
		case "", "json", "slack":
		default:
			add("webhook[%d].format: want \"json\" or \"slack\"", i)
		}
		for k, v := range w.Headers {
			if !validHeaderName(k) || strings.ContainsAny(v, "\r\n") {
				add("webhook[%d].headers: invalid header %q", i, k)
			}
		}
	}
	for i, e := range c.Email {
		if len(e.To) == 0 {
			add("email[%d].to: at least one address", i)
		}
		for _, a := range e.To {
			if !validAddress(a) {
				add("email[%d].to: %q is not an email address", i, a)
			}
		}
		if e.From != "" && !validAddress(e.From) {
			add("email[%d].from: %q is not an email address", i, e.From)
		}
		if e.Sendmail != "" && !filepath.IsAbs(e.Sendmail) {
			add("email[%d].sendmail: must be an absolute path", i)
		}
	}
	for i, cmd := range c.Command {
		if len(cmd.Argv) == 0 || !filepath.IsAbs(cmd.Argv[0]) {
			add("command[%d].argv: the program must be an absolute path", i)
		}
	}
	return errors.Join(errs...)
}

// Empty reports whether no notifier is configured.
func (c Config) Empty() bool {
	return len(c.Ntfy)+len(c.Webhook)+len(c.Email)+len(c.Command) == 0
}

// checkURL accepts absolute http(s) URLs without credentials. The URL
// itself is never echoed, since a topic or webhook path is a secret.
func checkURL(raw string, needPath bool) error {
	u, err := url.Parse(raw)
	switch {
	case raw == "":
		return errors.New("required")
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
		return errors.New("must be an absolute http:// or https:// URL")
	case u.User != nil:
		return errors.New("must not contain a user name or password; use token or headers")
	case needPath && strings.Trim(u.Path, "/") == "":
		return errors.New("must name a topic, e.g. https://ntfy.sh/my-relay-alerts")
	}
	return nil
}

func validFlag(f string) bool {
	if f == "" || len(f) > 32 {
		return false
	}
	for _, r := range f {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func validHeaderName(k string) bool {
	if k == "" {
		return false
	}
	for _, r := range k {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// validAddress accepts a bare addr-spec ("ops@example.org"): no display
// name, no line breaks, nothing a mail header could be injected through.
func validAddress(a string) bool {
	if strings.ContainsAny(a, "\r\n<>,; ") {
		return false
	}
	p, err := mail.ParseAddress(a)
	return err == nil && p.Address == a && p.Name == ""
}
