package alert

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile("../../docs/monitoring/alerts.toml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Ntfy) != 1 || c.MinSeverity != Warning || c.RemindEvery.Duration != 24*time.Hour || c.Empty() {
		t.Errorf("%+v", c)
	}
	// Uncommenting every example still parses.
	var b strings.Builder
	for line := range strings.Lines(string(data)) {
		u := strings.TrimPrefix(line, "# ")
		if u != line && (strings.HasPrefix(u, "[[") || strings.Contains(u, " = ") && !strings.HasPrefix(u, "#")) {
			line = u
		}
		b.WriteString(line)
	}
	all, err := ParseConfig([]byte(b.String()))
	if err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	if all.Name != "relay-fra-1" || len(all.Ntfy) != 1 || all.Ntfy[0].Token != "tk_..." || len(all.Webhook) != 2 ||
		all.Webhook[1].Format != "slack" || all.Webhook[0].Headers["Authorization"] != "Bearer replace-me" ||
		len(all.Email) != 1 || len(all.Command) != 1 || all.Command[0].Timeout.Duration != 30*time.Second {
		t.Errorf("%+v", all)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	c, err := ParseConfig([]byte("[[command]]\nargv = [\"/bin/true\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := DefaultConfig()
	if c.MinSeverity != d.MinSeverity || c.RemindEvery != d.RemindEvery || c.AccountingThreshold != 90 ||
		c.OverloadHold.Duration != 6*time.Hour || strings.Join(c.WatchFlags, ",") != "Guard,Stable,Fast,HSDir" || c.CheckUpdates {
		t.Errorf("%+v", c)
	}
	if !(Config{}).Empty() || c.Empty() {
		t.Error("Empty")
	}
}

func TestParseConfigErrors(t *testing.T) {
	const secret = "tk_SECRET123"
	tests := []struct {
		name, toml, want string
	}{
		{"unknown key", "min_severty = \"info\"\n", "unknown alert config keys: min_severty"},
		{"unknown notifier key", "[[ntfy]]\nurl = \"https://ntfy.sh/x\"\ntoken_file = \"x\"\n", "ntfy.token_file"},
		{"bad severity", "min_severity = \"loud\"\n", "unknown severity"},
		{"bad duration", "remind_every = \"daily\"\n", "remind_every"},
		{"threshold", "accounting_threshold = 0\n", "accounting_threshold: must be 1-100"},
		{"flag", "watch_flags = [\"Guard!\"]\n", `"Guard!" is not a relay flag name`},
		{"ntfy without topic", "[[ntfy]]\nurl = \"https://ntfy.sh/\"\n", "ntfy[0].url: must name a topic"},
		{"ntfy scheme", "[[ntfy]]\nurl = \"ftp://ntfy.sh/x\"\n", "ntfy[0].url: must be an absolute"},
		{"credentials in URL", "[[webhook]]\nurl = \"https://user:" + secret + "@example.org/h\"\n", "must not contain a user name"},
		{"webhook format", "[[webhook]]\nurl = \"https://example.org/h\"\nformat = \"xml\"\n", "webhook[0].format"},
		{"header injection", "[[webhook]]\nurl = \"https://example.org/h\"\nheaders = { \"X-A\" = \"a\\r\\nX-B: b\" }\n", "invalid header"},
		{"email without to", "[[email]]\nfrom = \"a@example.org\"\n", "email[0].to: at least one address"},
		{"email injection", "[[email]]\nto = [\"a@example.org\\nBcc: evil@example.org\"]\n", "is not an email address"},
		{"display name", "[[email]]\nto = [\"Ops <ops@example.org>\"]\n", "is not an email address"},
		{"relative sendmail", "[[email]]\nto = [\"a@example.org\"]\nsendmail = \"sendmail\"\n", "absolute path"},
		{"relative command", "[[command]]\nargv = [\"notify\"]\n", "command[0].argv"},
		{"empty command", "[[command]]\nargv = []\n", "command[0].argv"},
		{"syntax error hides the line", "[[ntfy]]\ntoken = " + secret + "\n", "line 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.toml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks the secret: %v", err)
			}
		})
	}
	// All problems at once.
	_, err := ParseConfig([]byte("accounting_threshold = 101\n[[ntfy]]\nurl = \"\"\n"))
	if err == nil || !strings.Contains(err.Error(), "accounting_threshold") || !strings.Contains(err.Error(), "ntfy[0].url: required") {
		t.Errorf("err = %v", err)
	}
}

func TestSeverityText(t *testing.T) {
	for _, s := range []Severity{Info, Warning, Critical} {
		b, _ := s.MarshalText()
		var back Severity
		if err := back.UnmarshalText(b); err != nil || back != s {
			t.Errorf("%v round trip: %v %v", s, back, err)
		}
	}
	var s Severity
	if err := s.UnmarshalText([]byte(" CRITICAL ")); err != nil || s != Critical {
		t.Error("case-insensitive")
	}
	var d Duration
	if err := d.UnmarshalText([]byte("-5m")); err == nil {
		t.Error("negative duration")
	}
}
