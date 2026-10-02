package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// Notifier delivers a Message somewhere.
type Notifier interface {
	// Name identifies the notifier in output without revealing secrets:
	// the kind and host name, never a URL path or token.
	Name() string
	Send(ctx context.Context, m Message) error
}

// httpTimeout bounds every notification request.
const httpTimeout = 10 * time.Second

var defaultHTTP = &http.Client{Timeout: httpTimeout}

// Notifiers builds the configured notifiers in config order: ntfy,
// webhooks, email, commands. client may be nil.
func (c Config) Notifiers(h host.Host, client *http.Client) []Notifier {
	if client == nil {
		client = defaultHTTP
	}
	var out []Notifier
	for i, n := range c.Ntfy {
		out = append(out, Ntfy{Index: i, Config: n, HTTP: client})
	}
	for i, w := range c.Webhook {
		out = append(out, Webhook{Index: i, Config: w, HTTP: client})
	}
	for i, e := range c.Email {
		out = append(out, Email{Index: i, Config: e, Host: h})
	}
	for i, cmd := range c.Command {
		out = append(out, Command{Index: i, Config: cmd, Host: h})
	}
	return out
}

// Ntfy posts the message text to an ntfy topic with the Title, Priority
// and Tags headers (https://docs.ntfy.sh/publish/).
type Ntfy struct {
	Index  int
	Config NtfyConfig
	HTTP   *http.Client
}

func (n Ntfy) Name() string { return fmt.Sprintf("ntfy[%d] (%s)", n.Index, hostOf(n.Config.URL)) }

func (n Ntfy) Send(ctx context.Context, m Message) error {
	headers := map[string]string{
		"Title":    headerValue(m.Subject()),
		"Priority": ntfyPriority(m),
		"Tags":     strings.Join(append(ntfyTags(m), n.Config.Tags...), ","),
	}
	if n.Config.Token != "" {
		headers["Authorization"] = "Bearer " + n.Config.Token
	}
	return post(ctx, n.HTTP, n.Name(), n.Config.URL, "text/plain; charset=utf-8", []byte(m.Text()), headers)
}

// ntfyPriority maps the most severe open alert to ntfy's 1-5 scale.
func ntfyPriority(m Message) string {
	switch {
	case m.Test, m.AllResolved():
		return "3"
	case m.MaxSeverity() == Critical:
		return "5"
	case m.MaxSeverity() == Warning:
		return "4"
	default:
		return "3"
	}
}

// ntfyTags become emoji in ntfy clients.
func ntfyTags(m Message) []string {
	tag := "information_source"
	switch {
	case m.Test:
		tag = "test_tube"
	case m.AllResolved():
		tag = "white_check_mark"
	case m.MaxSeverity() == Critical:
		tag = "rotating_light"
	case m.MaxSeverity() == Warning:
		tag = "warning"
	}
	return []string{tag, "tor"}
}

// Webhook posts JSON: the Message itself ("json") or {"text": ...}
// ("slack").
type Webhook struct {
	Index  int
	Config WebhookConfig
	HTTP   *http.Client
}

func (w Webhook) Name() string { return fmt.Sprintf("webhook[%d] (%s)", w.Index, hostOf(w.Config.URL)) }

func (w Webhook) Send(ctx context.Context, m Message) error {
	var body []byte
	var err error
	if w.Config.Format == "slack" {
		body, err = json.Marshal(map[string]string{"text": m.Subject() + "\n\n" + m.Text()})
	} else {
		body, err = json.Marshal(m)
	}
	if err != nil {
		return err
	}
	return post(ctx, w.HTTP, w.Name(), w.Config.URL, "application/json", body, w.Config.Headers)
}

// post sends one request. Errors name the notifier but never the URL or
// the response body, which could echo a secret.
func post(ctx context.Context, client *http.Client, name, target, contentType string, body []byte, headers map[string]string) error {
	if client == nil {
		client = defaultHTTP
	}
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: invalid request", name)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "tor-relay-setup")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // url.Error quotes the full URL
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: server answered %s", name, resp.Status)
	}
	return nil
}

// Email hands a plain-text mail to the local MTA with `sendmail -t -i`.
type Email struct {
	Index  int
	Config EmailConfig
	Host   host.Host
}

func (e Email) Name() string {
	return fmt.Sprintf("email[%d] (%s)", e.Index, strings.Join(e.Config.To, ", "))
}

func (e Email) sendmail() string {
	if e.Config.Sendmail != "" {
		return e.Config.Sendmail
	}
	return defaultSendmail
}

func (e Email) Send(ctx context.Context, m Message) error {
	bin := e.sendmail()
	if _, err := e.Host.Stat(bin); err != nil {
		return fmt.Errorf("%s: %s not found; install a mail transfer agent (for example postfix or msmtp-mta) or set sendmail", e.Name(), bin)
	}
	ctx, cancel := context.WithTimeout(ctx, defaultCommandWait)
	defer cancel()
	_, err := e.Host.Run(ctx, host.Command{Name: bin, Args: []string{"-t", "-i"}, Stdin: e.message(m), Mutates: true})
	if err != nil {
		return fmt.Errorf("%s: %s", e.Name(), commandFailure(bin, err))
	}
	return nil
}

// message renders an RFC 5322 mail. Addresses are validated bare
// addr-specs and every header value is a single line.
func (e Email) message(m Message) []byte {
	var b strings.Builder
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	if e.Config.From != "" {
		header("From", e.Config.From)
	}
	header("To", strings.Join(e.Config.To, ", "))
	header("Subject", headerValue("[tor-relay-setup] "+m.Subject()))
	header("Date", m.Time.Format(time.RFC1123Z))
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(m.Text(), "\n", "\r\n"))
	return []byte(b.String())
}

// Command runs a program with the Message as JSON on standard input.
type Command struct {
	Index  int
	Config CommandConfig
	Host   host.Host
}

func (c Command) Name() string { return fmt.Sprintf("command[%d] (%s)", c.Index, c.Config.Argv[0]) }

func (c Command) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	wait := c.Config.Timeout.Duration
	if wait == 0 {
		wait = defaultCommandWait
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	_, err = c.Host.Run(ctx, host.Command{Name: c.Config.Argv[0], Args: c.Config.Argv[1:], Stdin: append(body, '\n'), Mutates: true})
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s: timed out after %s", c.Name(), wait)
		}
		return fmt.Errorf("%s: %s", c.Name(), commandFailure(c.Config.Argv[0], err))
	}
	return nil
}

// commandFailure describes a failed program by its exit status only: the
// arguments may hold tokens and the output may echo the message.
func commandFailure(name string, err error) string {
	var exit *host.ExitError
	if errors.As(err, &exit) {
		return fmt.Sprintf("%s exited with status %d", name, exit.ExitCode)
	}
	return name + " could not be started"
}

// hostOf returns the host name of a URL for display.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "?"
	}
	return u.Hostname()
}

// headerValue makes s a single-line header value, RFC 2047-encoded when it
// is not plain ASCII.
func headerValue(s string) string {
	s = oneLine(s)
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return mime.QEncoding.Encode("utf-8", s)
		}
	}
	return s
}
