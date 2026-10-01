package tui

import (
	"context"
	"net/http"
	"os"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/system"
	"github.com/ljkx/tor-relay-setup/internal/torproject"
)

// Background checks start the moment the program launches, so their results
// are ready by the time the operator reaches the questions that need them.

type factsMsg struct {
	facts system.Facts
	err   error
}

type suiteMsg struct {
	ok  bool
	err error
}

type ipv6Msg struct{ reachable, total int }

// Checks is what the background probes found so far.
type Checks struct {
	Facts      system.Facts
	FactsReady bool
	FactsErr   error

	SuiteDone bool
	SuiteOK   bool
	SuiteErr  error

	IPv6Done      bool
	IPv6Reachable int
	IPv6Total     int
}

func detectFacts(h host.Host) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		f, err := system.Detect(ctx, h, os.Getenv)
		return factsMsg{facts: f, err: err}
	}
}

func checkSuite(codename string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		ok, err := torproject.SuiteAvailable(ctx, &http.Client{Timeout: 8 * time.Second}, codename)
		return suiteMsg{ok: ok, err: err}
	}
}

func checkIPv6() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		n, total := system.CheckIPv6Outbound(ctx, nil)
		return ipv6Msg{reachable: n, total: total}
	}
}

// update folds a background result into the checks and returns follow-up
// commands (the suite check needs the codename from the facts).
func (c *Checks) update(msg tea.Msg) (bool, tea.Cmd) {
	switch msg := msg.(type) {
	case factsMsg:
		c.Facts, c.FactsErr, c.FactsReady = msg.facts, msg.err, true
		var cmds []tea.Cmd
		if msg.err == nil && msg.facts.Codename != "" {
			cmds = append(cmds, checkSuite(msg.facts.Codename))
		}
		if len(msg.facts.IPv6) > 0 {
			cmds = append(cmds, checkIPv6())
		} else {
			c.IPv6Done = true
		}
		return true, tea.Batch(cmds...)
	case suiteMsg:
		c.SuiteDone, c.SuiteOK, c.SuiteErr = true, msg.ok, msg.err
		return true, nil
	case ipv6Msg:
		c.IPv6Done, c.IPv6Reachable, c.IPv6Total = true, msg.reachable, msg.total
		return true, nil
	}
	return false, nil
}

// view renders the "This server" panel body.
func (c Checks) view(t Theme, spin string) string {
	if !c.FactsReady {
		return spin + " " + t.Subtle.Render("Inspecting this server…")
	}
	if c.FactsErr != nil {
		return statusIcon(t, false, false) + " " + c.FactsErr.Error()
	}
	f := c.Facts
	rows := [][2]string{
		{"System", f.PrettyName + " (" + f.Codename + ", " + f.Arch + ")"},
		{"Memory", itoa(f.MemTotalMiB) + " MiB"},
	}
	var suite string
	switch {
	case !c.SuiteDone:
		suite = spin + " checking"
	case c.SuiteErr != nil:
		suite = statusIcon(t, false, true) + " unreachable"
	case c.SuiteOK:
		suite = statusIcon(t, true, false) + " " + f.Codename + " published"
	default:
		suite = statusIcon(t, false, false) + " no " + f.Codename + " suite"
	}
	rows = append(rows, [2]string{"Tor repo", suite})

	switch {
	case len(f.IPv6) == 0:
		rows = append(rows, [2]string{"IPv6", t.Subtle.Render("no global address")})
	case !c.IPv6Done:
		rows = append(rows, [2]string{"IPv6", spin + " testing " + f.IPv6[0]})
	default:
		ok := c.IPv6Reachable == c.IPv6Total && c.IPv6Total > 0
		rows = append(rows, [2]string{"IPv6", statusIcon(t, ok, c.IPv6Reachable > 0) + " " +
			itoa(c.IPv6Reachable) + "/" + itoa(c.IPv6Total) + " authorities reachable"})
	}
	fw := f.Firewall.Kind
	if fw == "" || fw == "none" {
		fw = "none detected"
	} else if f.Firewall.Detail != "" {
		fw += " (" + f.Firewall.Detail + ")"
	}
	rows = append(rows, [2]string{"Firewall", fw})
	ports := make([]string, len(f.SSHPorts))
	for i, p := range f.SSHPorts {
		ports[i] = itoa(p)
	}
	rows = append(rows, [2]string{"SSH", joinOr(ports, "22")})
	return kv(t, rows)
}
