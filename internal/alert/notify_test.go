package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// recorder is an HTTP endpoint that records requests.
type recorder struct {
	*httptest.Server
	mu     sync.Mutex
	reqs   []*http.Request
	bodies []string
	status int
}

func newRecorder(t *testing.T, status int) *recorder {
	t.Helper()
	r := &recorder{status: status}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, req.Clone(context.Background()))
		r.bodies = append(r.bodies, string(body))
		r.mu.Unlock()
		w.WriteHeader(r.status)
		_, _ = w.Write([]byte("server echo: secret-topic tk_TOKEN"))
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *recorder) req(i int) *http.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reqs[i]
}

func (r *recorder) body(i int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bodies[i]
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func testMessage() Message {
	return Message{
		Relay: "MyRelay", Nickname: "MyRelay", Fingerprint: testFP, Host: "relay1", Time: testNow,
		Alerts: []Notification{
			{Alert: Alert{ID: "service-inactive", Severity: Critical, Title: "tor@default is not running", Body: "Look at: systemctl status tor@default"}, Status: StatusFiring, Since: testNow},
			{Alert: Alert{ID: "family-key-missing", Severity: Warning, Title: "family key missing", Body: "copy the key"}, Status: StatusReminder, Since: testNow.Add(-24 * time.Hour)},
			{Alert: Alert{ID: "orport-unreachable", Severity: Critical, Title: "the ORPort is not reachable from outside"}, Status: StatusResolved, Since: testNow.Add(-time.Hour)},
		},
	}
}

func TestMessageText(t *testing.T) {
	m := testMessage()
	if got := m.Subject(); got != "MyRelay: [CRITICAL] tor@default is not running (+2 more)" {
		t.Errorf("subject %q", got)
	}
	text := m.Text()
	for _, want := range []string{
		"tor-relay-setup on MyRelay (relay1, " + testFP + ") at 2026-10-02 12:00 UTC\n",
		"\n[CRITICAL] tor@default is not running\n  Look at: systemctl status tor@default\n",
		"\n[WARNING, still] family key missing\n  copy the key\n  first seen 2026-10-01 12:00 UTC\n",
		"\n[RESOLVED] the ORPort is not reachable from outside\n  first seen 2026-10-02 11:00 UTC\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if m.MaxSeverity() != Critical || m.AllResolved() {
		t.Error("severity")
	}
	resolved := Message{Relay: "R", Alerts: []Notification{{Alert: Alert{Severity: Critical, Title: "x\r\nBcc: evil"}, Status: StatusResolved}}}
	if resolved.MaxSeverity() != Info || !resolved.AllResolved() || resolved.Subject() != "R: [RESOLVED] x Bcc: evil" {
		t.Errorf("resolved: %v %v %q", resolved.MaxSeverity(), resolved.AllResolved(), resolved.Subject())
	}
}

func TestNtfy(t *testing.T) {
	tests := []struct {
		name           string
		msg            Message
		priority, tags string
	}{
		{"critical", testMessage(), "5", "rotating_light,tor,fra"},
		{"warning", Message{Relay: "R", Alerts: []Notification{{Alert: Alert{Severity: Warning, Title: "w"}, Status: StatusFiring}}}, "4", "warning,tor,fra"},
		{"resolved", Message{Relay: "R", Alerts: []Notification{{Alert: Alert{Severity: Critical, Title: "c"}, Status: StatusResolved}}}, "3", "white_check_mark,tor,fra"},
		{"test", Message{Relay: "R", Test: true, Alerts: []Notification{{Alert: Alert{Title: "test notification"}, Status: StatusTest}}}, "3", "test_tube,tor,fra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newRecorder(t, http.StatusOK)
			n := Ntfy{Config: NtfyConfig{URL: srv.URL + "/secret-topic", Token: "tk_TOKEN", Tags: []string{"fra"}}, HTTP: srv.Client()}
			if err := n.Send(context.Background(), tt.msg); err != nil {
				t.Fatal(err)
			}
			req := srv.req(0)
			if req.Method != http.MethodPost || req.URL.Path != "/secret-topic" {
				t.Errorf("%s %s", req.Method, req.URL.Path)
			}
			h := req.Header
			if h.Get("Title") != tt.msg.Subject() || h.Get("Priority") != tt.priority || h.Get("Tags") != tt.tags ||
				h.Get("Authorization") != "Bearer tk_TOKEN" || h.Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Errorf("headers %v", h)
			}
			if srv.body(0) != tt.msg.Text() {
				t.Errorf("body %q", srv.body(0))
			}
			if strings.Contains(n.Name(), "secret-topic") || n.Name() != "ntfy[0] (127.0.0.1)" {
				t.Errorf("name %q", n.Name())
			}
		})
	}

	// Non-ASCII titles are RFC 2047-encoded; no token, no Authorization.
	srv := newRecorder(t, http.StatusOK)
	m := Message{Relay: "Rélais", Alerts: []Notification{{Alert: Alert{Severity: Warning, Title: "über"}, Status: StatusFiring}}}
	if err := (Ntfy{Config: NtfyConfig{URL: srv.URL + "/t"}, HTTP: srv.Client()}).Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if h := srv.req(0).Header; !strings.HasPrefix(h.Get("Title"), "=?utf-8?q?") || h.Get("Authorization") != "" {
		t.Errorf("headers %v", h)
	}
}

func TestWebhook(t *testing.T) {
	srv := newRecorder(t, http.StatusNoContent)
	w := Webhook{Config: WebhookConfig{URL: srv.URL + "/hooks/secret", Headers: map[string]string{"Authorization": "Bearer abc"}}, HTTP: srv.Client()}
	m := testMessage()
	if err := w.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	req := srv.req(0)
	if req.Header.Get("Content-Type") != "application/json" || req.Header.Get("Authorization") != "Bearer abc" || req.Header.Get("User-Agent") != "tor-relay-setup" {
		t.Errorf("headers %v", req.Header)
	}
	var got struct {
		Relay, Nickname, Fingerprint, Host string
		Time                               time.Time
		Alerts                             []struct {
			ID, Severity, Status, Title, Body string
			Since                             time.Time
		}
	}
	dec := json.NewDecoder(strings.NewReader(srv.body(0)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("%v\n%s", err, srv.body(0))
	}
	if got.Relay != "MyRelay" || got.Fingerprint != testFP || got.Host != "relay1" || !got.Time.Equal(testNow) || len(got.Alerts) != 3 {
		t.Errorf("%+v", got)
	}
	if a := got.Alerts[0]; a.ID != "service-inactive" || a.Severity != "critical" || a.Status != "firing" || !a.Since.Equal(testNow) {
		t.Errorf("alert %+v", a)
	}

	slack := newRecorder(t, http.StatusOK)
	if err := (Webhook{Config: WebhookConfig{URL: slack.URL, Format: "slack"}, HTTP: slack.Client()}).Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	var s map[string]string
	if err := json.Unmarshal([]byte(slack.body(0)), &s); err != nil || len(s) != 1 || s["text"] != m.Subject()+"\n\n"+m.Text() {
		t.Errorf("slack body %q (%v)", slack.body(0), err)
	}
}

func TestHTTPErrorsHideSecrets(t *testing.T) {
	srv := newRecorder(t, http.StatusForbidden)
	for _, n := range []Notifier{
		Ntfy{Config: NtfyConfig{URL: srv.URL + "/secret-topic", Token: "tk_TOKEN"}, HTTP: srv.Client()},
		Webhook{Config: WebhookConfig{URL: srv.URL + "/hooks/secret-topic"}, HTTP: srv.Client()},
	} {
		err := n.Send(context.Background(), testMessage())
		if err == nil || !strings.Contains(err.Error(), "server answered 403 Forbidden") {
			t.Errorf("%s: %v", n.Name(), err)
		}
		if err != nil && (strings.Contains(err.Error(), "secret-topic") || strings.Contains(err.Error(), "tk_TOKEN")) {
			t.Errorf("error leaks a secret: %v", err)
		}
	}
	// Connection errors: url.Error would quote the whole URL.
	srv.Close()
	err := Ntfy{Config: NtfyConfig{URL: srv.URL + "/secret-topic"}}.Send(context.Background(), testMessage())
	if err == nil || strings.Contains(err.Error(), "secret-topic") {
		t.Errorf("error %v", err)
	}
}

func TestEmail(t *testing.T) {
	fake := host.NewFake()
	e := Email{Config: EmailConfig{To: []string{"ops@example.org", "noc@example.org"}, From: "relay@example.org"}, Host: fake}
	if err := e.Send(context.Background(), testMessage()); err == nil || !strings.Contains(err.Error(), "/usr/sbin/sendmail not found") {
		t.Fatalf("without sendmail: %v", err)
	}
	fake.Files["/usr/sbin/sendmail"] = []byte("bin")
	if err := e.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	c := fake.Commands[len(fake.Commands)-1]
	if c.String() != "/usr/sbin/sendmail -t -i" || !c.Mutates {
		t.Errorf("command %q mutates=%v", c.String(), c.Mutates)
	}
	mail := string(c.Stdin)
	head, body, ok := strings.Cut(mail, "\r\n\r\n")
	if !ok {
		t.Fatalf("no header/body split:\n%s", mail)
	}
	for _, want := range []string{
		"From: relay@example.org\r\n", "To: ops@example.org, noc@example.org\r\n",
		"Subject: [tor-relay-setup] MyRelay: [CRITICAL] tor@default is not running (+2 more)\r\n",
		"Date: Fri, 02 Oct 2026 12:00:00 +0000\r\n", "Content-Type: text/plain; charset=utf-8\r\n", "Auto-Submitted: auto-generated",
	} {
		if !strings.Contains(head+"\r\n", want) {
			t.Errorf("headers lack %q:\n%s", want, head)
		}
	}
	if !strings.Contains(body, "[CRITICAL] tor@default is not running\r\n") || strings.Contains(strings.ReplaceAll(body, "\r\n", ""), "\n") {
		t.Errorf("body:\n%s", body)
	}

	// A failing MTA: the error names the exit status only.
	fake.Handler = func(host.Command) (host.Result, error) {
		return host.Result{ExitCode: 75, Output: "mail body echo"}, &host.ExitError{Command: "sendmail -t -i", ExitCode: 75, Output: "mail body echo"}
	}
	err := e.Send(context.Background(), testMessage())
	if err == nil || err.Error() != "email[0] (ops@example.org, noc@example.org): /usr/sbin/sendmail exited with status 75" {
		t.Errorf("error %v", err)
	}
}

func TestCommandNotifier(t *testing.T) {
	fake := host.NewFake()
	c := Command{Config: CommandConfig{Argv: []string{"/usr/local/bin/notify", "--token", "SECRET"}}, Host: fake}
	m := testMessage()
	if err := c.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	got := fake.Commands[0]
	if got.Name != "/usr/local/bin/notify" || strings.Join(got.Args, " ") != "--token SECRET" || !got.Mutates {
		t.Errorf("command %+v", got)
	}
	var back Message
	if err := json.Unmarshal(got.Stdin, &back); err != nil || back.Relay != "MyRelay" || len(back.Alerts) != 3 || back.Alerts[2].Status != StatusResolved {
		t.Errorf("stdin %s (%v)", got.Stdin, err)
	}

	fake.Handler = func(host.Command) (host.Result, error) {
		return host.Result{ExitCode: 2}, &host.ExitError{Command: "/usr/local/bin/notify --token SECRET", ExitCode: 2}
	}
	err := c.Send(context.Background(), m)
	if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "exited with status 2") {
		t.Errorf("error %v", err)
	}

	// The timeout applies: a real program that sleeps is stopped.
	slow := Command{Config: CommandConfig{Argv: []string{"/bin/sh", "-c", "exec sleep 5"}, Timeout: Duration{50 * time.Millisecond}}, Host: host.NewLocal()}
	start := time.Now()
	err = slow.Send(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "timed out after 50ms") || time.Since(start) > 4*time.Second {
		t.Errorf("slow command: %v after %v", err, time.Since(start))
	}
}

func TestNotifiersFromConfig(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
[[ntfy]]
url = "https://ntfy.example.org/topic"
[[webhook]]
url = "https://hooks.example.org/x"
format = "slack"
[[email]]
to = ["ops@example.org"]
[[command]]
argv = ["/bin/true"]
`))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, n := range cfg.Notifiers(host.NewFake(), nil) {
		names = append(names, n.Name())
	}
	want := "ntfy[0] (ntfy.example.org); webhook[0] (hooks.example.org); email[0] (ops@example.org); command[0] (/bin/true)"
	if strings.Join(names, "; ") != want {
		t.Errorf("names %q", names)
	}
}
