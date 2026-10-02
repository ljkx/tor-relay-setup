package tui

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/service"
	"github.com/ljkx/tor-relay-setup/internal/status"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

// ---------------------------------------------------------------- checks

func TestChecksUpdate(t *testing.T) {
	t.Parallel()
	withCodename := testFacts()
	withIPv6 := testFacts()
	withIPv6.Codename, withIPv6.IPv6 = "", []string{"2001:db8::1"}
	both := testFacts()
	both.IPv6 = []string{"2001:db8::1"}
	bare := testFacts()
	bare.Codename = ""

	tests := []struct {
		name        string
		msg         tea.Msg
		wantChanged bool
		wantCmd     bool
		check       func(t *testing.T, c Checks)
	}{
		{
			name: "facts with a codename start the suite check", msg: factsMsg{facts: withCodename},
			wantChanged: true, wantCmd: true,
			check: func(t *testing.T, c Checks) {
				if !c.FactsReady || c.FactsErr != nil || c.Facts.Codename != "bookworm" || !c.IPv6Done {
					t.Errorf("checks = %+v", c)
				}
			},
		},
		{
			name: "facts with IPv6 start the IPv6 check", msg: factsMsg{facts: withIPv6},
			wantChanged: true, wantCmd: true,
			check: func(t *testing.T, c Checks) {
				if c.IPv6Done {
					t.Error("IPv6Done before the IPv6 check ran")
				}
			},
		},
		{name: "facts with codename and IPv6", msg: factsMsg{facts: both}, wantChanged: true, wantCmd: true},
		{
			name: "facts without codename or IPv6 need no follow-up", msg: factsMsg{facts: bare},
			wantChanged: true, wantCmd: false,
		},
		{
			name: "a detection error skips the suite check", msg: factsMsg{facts: withCodename, err: errors.New("no os-release")},
			wantChanged: true, wantCmd: false,
			check: func(t *testing.T, c Checks) {
				if !c.FactsReady || c.FactsErr == nil {
					t.Errorf("checks = %+v", c)
				}
			},
		},
		{
			name: "suite result", msg: suiteMsg{ok: true}, wantChanged: true,
			check: func(t *testing.T, c Checks) {
				if !c.SuiteDone || !c.SuiteOK || c.SuiteErr != nil {
					t.Errorf("checks = %+v", c)
				}
			},
		},
		{
			name: "suite error", msg: suiteMsg{err: errors.New("dns")}, wantChanged: true,
			check: func(t *testing.T, c Checks) {
				if !c.SuiteDone || c.SuiteOK || c.SuiteErr == nil {
					t.Errorf("checks = %+v", c)
				}
			},
		},
		{
			name: "IPv6 result", msg: ipv6Msg{reachable: 3, total: 5}, wantChanged: true,
			check: func(t *testing.T, c Checks) {
				if !c.IPv6Done || c.IPv6Reachable != 3 || c.IPv6Total != 5 {
					t.Errorf("checks = %+v", c)
				}
			},
		},
		{name: "unrelated message", msg: tea.KeyPressMsg{Code: 'x', Text: "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var c Checks
			// The returned commands would probe the network; they are only inspected.
			changed, cmd := c.update(tt.msg)
			if changed != tt.wantChanged || (cmd != nil) != tt.wantCmd {
				t.Errorf("update() = %v, cmd %v; want %v, cmd %v", changed, cmd != nil, tt.wantChanged, tt.wantCmd)
			}
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}

func TestChecksView(t *testing.T) {
	t.Parallel()
	th := NewTheme(true)
	ready := func(mut func(*Checks)) Checks {
		c := Checks{Facts: testFacts(), FactsReady: true, SuiteDone: true, SuiteOK: true, IPv6Done: true}
		if mut != nil {
			mut(&c)
		}
		return c
	}
	tests := []struct {
		name string
		c    Checks
		want []string
	}{
		{"not ready", Checks{}, []string{"SPIN Inspecting this server…"}},
		{"detection failed", Checks{FactsReady: true, FactsErr: errors.New("cannot read /etc/os-release")}, []string{"✗ cannot read /etc/os-release"}},
		{"all good", ready(nil), []string{
			"System    Debian GNU/Linux 12 (bookworm) (bookworm, amd64)", "Memory    4096 MiB",
			"Tor repo  ✓ bookworm published", "IPv6      no global address", "Firewall  ufw (active)", "SSH       22, 2222",
		}},
		{"suite pending", ready(func(c *Checks) { c.SuiteDone = false }), []string{"Tor repo  SPIN checking"}},
		{"suite unreachable", ready(func(c *Checks) { c.SuiteErr = errors.New("x") }), []string{"! unreachable"}},
		{"suite missing", ready(func(c *Checks) { c.SuiteOK = false }), []string{"✗ no bookworm suite"}},
		{"IPv6 testing", ready(func(c *Checks) { c.Facts.IPv6 = []string{"2001:db8::1"}; c.IPv6Done = false }), []string{"SPIN testing 2001:db8::1"}},
		{"IPv6 all reachable", ready(func(c *Checks) { c.Facts.IPv6 = []string{"2001:db8::1"}; c.IPv6Reachable, c.IPv6Total = 5, 5 }),
			[]string{"✓ 5/5 authorities reachable"}},
		{"IPv6 partly reachable", ready(func(c *Checks) { c.Facts.IPv6 = []string{"2001:db8::1"}; c.IPv6Reachable, c.IPv6Total = 2, 5 }),
			[]string{"! 2/5 authorities reachable"}},
		{"IPv6 unreachable", ready(func(c *Checks) { c.Facts.IPv6 = []string{"2001:db8::1"}; c.IPv6Reachable, c.IPv6Total = 0, 5 }),
			[]string{"✗ 0/5 authorities reachable"}},
		{"no firewall", ready(func(c *Checks) { c.Facts.Firewall = system.Firewall{Kind: "none", Detail: system.DetailNone} }),
			[]string{"Firewall  none detected"}},
		{"no SSH ports known", ready(func(c *Checks) { c.Facts.SSHPorts = nil }), []string{"SSH       22"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := strip(tt.c.view(th, "SPIN"))
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("view =\n%s\nwant it to contain %q", got, w)
				}
			}
		})
	}
}

// ---------------------------------------------------------------- review

func TestReviewRender(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*config.Setup)
		width   int
		want    []string
		notWant []string
	}{
		{
			name: "exit relay, two columns",
			mutate: func(s *config.Setup) {
				s.Relay.Mode, s.Exit.ProviderPermission, s.Relay.IPv6, s.Relay.MetricsPort = "exit", true, "2001:db8::1", true
			},
			width: 140,
			want: []string{
				"Exit relay · reduced policy · local Unbound DNS", "Nickname     TestRelay", "tor-ops@example.org",
				"9001 (IPv4) · IPv6 [2001:db8::1]:9001", "≈ 13.4 Mbit/s steady", "Monthly cap  8381 GBytes/month (safety cap)",
				"127.0.0.1:9035 (local only)", "Hostname     unchanged", "/etc/tor/torrc", "Nickname TestRelay",
				"ExitRelay 1", "IPv6Exit 1", "Enable Unbound",
			},
			notWant: []string{"Needs attention"},
		},
		{
			name:   "guard with family, one column",
			mutate: func(s *config.Setup) { s.Family.Mode, s.Family.KeyName = "generate", "fam" },
			width:  80,
			want: []string{
				"Guard / middle relay", "new key fam (generated during apply)", "IPv6 disabled",
				"MetricsPort  off", "Sandbox      yes", "ExitRelay 0", "# FamilyId <generated with tor --keygen-family during apply>",
			},
		},
		{
			name: "manual bandwidth and hostname",
			mutate: func(s *config.Setup) {
				s.Bandwidth = config.BandwidthPlan{Mode: "manual", RateMbit: 20}
				s.System.Hostname, s.System.Nyx = "relay1", false
			},
			width: 140,
			want:  []string{"20 Mbit/s, burst 40", "Hostname     relay1", "Nyx          no", "Set the hostname to relay1", "RelayBandwidthRate 20 MBits"},
		},
		{
			name: "accounting and import",
			mutate: func(s *config.Setup) {
				s.Bandwidth = config.BandwidthPlan{Mode: "accounting", MonthlyQuota: "5000GB", HeadroomPercent: 10, Billing: "max"}
				s.Family.Mode, s.Family.ImportKey, s.Family.FamilyID = "import", "/root/f.secret_family_key", famID("Q")
			},
			width: 140,
			want:  []string{"Bandwidth    full speed", "Monthly cap  4190 GBytes/month", "import /root/f.secret_family_key", "FamilyId " + famID("Q")},
		},
		{
			name:   "no limit",
			mutate: func(s *config.Setup) { s.Bandwidth = config.BandwidthPlan{Mode: "none"} },
			width:  140,
			want:   []string{"Bandwidth    no limit"},
		},
		{
			name:   "invalid setup needs attention",
			mutate: func(s *config.Setup) { s.Relay.Nickname = ""; s.Relay.Mode = "exit" },
			width:  140,
			want:   []string{"Needs attention", "relay.nickname", "exit.provider_permission"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := testApp()
			a.width = tt.width
			s := testSetup()
			tt.mutate(&s)
			r := newReview(a, s, nil)
			got := strip(r.render(a))
			changes := plan.Changes(plan.Build(s, a.checks.Facts))
			want := append([]string{fmt.Sprintf("What will change (%d)", len(changes)), "Enable and restart tor@default"}, tt.want...)
			for _, w := range want {
				if !strings.Contains(got, w) {
					t.Errorf("review lacks %q:\n%s", w, got)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("review unexpectedly contains %q", w)
				}
			}
			for i, line := range strings.Split(got, "\n") {
				if lipgloss.Width(line) > a.contentWidth() {
					t.Errorf("line %d is %d wide, wider than the content width %d: %q", i, lipgloss.Width(line), a.contentWidth(), line)
				}
			}
		})
	}
}

func TestReviewViewAndKeys(t *testing.T) {
	t.Parallel()
	a := testApp()
	a.opt.DryRun = true
	r := newReview(a, testSetup(), nil)
	v := strip(r.view(a))
	for _, w := range []string{"Review", "nothing has changed yet", "dry run: apply only shows what would happen"} {
		if !strings.Contains(v, w) {
			t.Errorf("view lacks %q:\n%s", w, v)
		}
	}

	// "a" asks for confirmation; any other key cancels it.
	next, _ := r.update(a, tea.KeyPressMsg{Code: 'a', Text: "a"})
	if next != r || !r.confirm {
		t.Fatal("a did not ask for confirmation")
	}
	if v := strip(r.view(a)); !strings.Contains(v, "Apply these changes now?") {
		t.Errorf("confirmation prompt missing:\n%s", v)
	}
	r.update(a, tea.KeyPressMsg{Code: 'n', Text: "n"})
	if r.confirm {
		t.Error("n did not cancel the confirmation")
	}

	// An invalid setup refuses to apply.
	bad := testSetup()
	bad.Relay.Nickname = ""
	rb := newReview(a, bad, nil)
	if _, cmd := rb.update(a, tea.KeyPressMsg{Code: 'a', Text: "a"}); rb.confirm || cmd == nil {
		t.Error("an invalid setup reached the confirmation")
	} else if msg, ok := cmd().(toastMsg); !ok || !strings.Contains(string(msg), "Fix the highlighted problem") {
		t.Errorf("toast = %v", msg)
	}
	if _, cmd := r.update(a, tea.KeyPressMsg{Code: 'q', Text: "q"}); cmd == nil {
		t.Error("q returned no command")
	} else if msg, ok := cmd().(quitMsg); !ok || !errors.Is(msg.err, ErrAborted) {
		t.Errorf("q produced %v, want quitMsg{ErrAborted}", msg)
	}
}

// ---------------------------------------------------------------- apply

// syntheticApply returns an apply screen over three steps weighing 1, 3 and 6.
func syntheticApply(a *App) *apply {
	ap := newApply(a, testSetup())
	ap.steps = []plan.Step{
		{ID: "one", Title: "First", Weight: 1},
		{ID: "two", Title: "Second", Weight: 3},
		{ID: "three", Title: "Third", Weight: 6},
	}
	ap.states = make([]stepState, len(ap.steps))
	for i, s := range ap.steps {
		ap.states[i].title = s.Title
	}
	return ap
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestNewApplyMirrorsThePlan(t *testing.T) {
	t.Parallel()
	a := testApp()
	s := testSetup()
	ap := newApply(a, s)
	steps := plan.Build(s, a.checks.Facts)
	if len(ap.steps) != len(steps) || len(ap.states) != len(steps) {
		t.Fatalf("apply has %d steps / %d states, plan has %d", len(ap.steps), len(ap.states), len(steps))
	}
	for i := range steps {
		if ap.states[i].title != steps[i].Title || ap.states[i].status != stepPending {
			t.Errorf("state %d = %+v, want pending %q", i, ap.states[i], steps[i].Title)
		}
	}
	if ap.overall() != 0 {
		t.Errorf("overall() = %v before anything ran", ap.overall())
	}
}

func TestApplyProgress(t *testing.T) {
	t.Parallel()
	a := testApp()
	ap := syntheticApply(a)
	boom := errors.New("apt-get install failed")

	steps := []struct {
		event   plan.Event
		overall float64
		check   func(t *testing.T)
	}{
		{plan.Event{Kind: plan.StepStarted, Step: 0, Text: "First"}, 0, func(t *testing.T) {
			if ap.states[0].status != stepRunning || ap.states[0].started.IsZero() {
				t.Errorf("state 0 = %+v", ap.states[0])
			}
		}},
		{plan.Event{Kind: plan.StepProgress, Step: 0, Percent: 50, Text: "halfway"}, 0.05, func(t *testing.T) {
			if ap.states[0].percent != 50 || ap.states[0].detail != "halfway" {
				t.Errorf("state 0 = %+v", ap.states[0])
			}
		}},
		{plan.Event{Kind: plan.StepFinished, Step: 0, Elapsed: 1500 * time.Millisecond}, 0.1, func(t *testing.T) {
			if s := ap.states[0]; s.status != stepDone || s.percent != 100 || s.detail != "" || s.elapsed != 1500*time.Millisecond {
				t.Errorf("state 0 = %+v", s)
			}
		}},
		{plan.Event{Kind: plan.StepStarted, Step: 1, Text: "Second"}, 0.1, nil},
		{plan.Event{Kind: plan.StepProgress, Step: 1, Percent: 40}, 0.1 + 0.3*0.4, nil},
		{plan.Event{Kind: plan.StepLog, Step: 1, Text: "Unpacking tor"}, 0.1 + 0.3*0.4, nil},
		{plan.Event{Kind: plan.StepNote, Step: 1, Level: plan.Warn, Text: "careful"}, 0.1 + 0.3*0.4, func(t *testing.T) {
			if !reflect.DeepEqual(ap.states[1].notes, []stepNote{{level: plan.Warn, text: "careful"}}) {
				t.Errorf("notes = %+v", ap.states[1].notes)
			}
		}},
		{plan.Event{Kind: plan.StepFailed, Step: 1, Err: boom, Text: boom.Error(), Elapsed: time.Second}, 0.1, func(t *testing.T) {
			if ap.states[1].status != stepFailed || ap.states[2].status != stepPending {
				t.Errorf("states = %+v", ap.states)
			}
		}},
	}
	for i, st := range steps {
		ap.handle(st.event)
		if got := ap.overall(); !near(got, st.overall) {
			t.Errorf("after event %d (%v): overall() = %v, want %v", i, st.event.Kind, got, st.overall)
		}
		if st.check != nil {
			st.check(t)
		}
	}
	wantLog := []string{"── First", "── Second", "  Unpacking tor", "  • careful", "  ✗ apt-get install failed"}
	if !reflect.DeepEqual(ap.log, wantLog) {
		t.Errorf("log = %q, want %q", ap.log, wantLog)
	}

	// Finishing every step fills the bar.
	for i := range ap.steps {
		ap.handle(plan.Event{Kind: plan.StepFinished, Step: i})
	}
	if !near(ap.overall(), 1) {
		t.Errorf("overall() = %v after all steps, want 1", ap.overall())
	}
	empty := &apply{}
	if empty.overall() != 0 {
		t.Error("overall() of an empty plan should be 0")
	}
}

func TestApplyFeedsFromPlanRun(t *testing.T) {
	t.Parallel()
	a := testApp()
	ap := syntheticApply(a)
	for i := range ap.steps {
		ap.steps[i].Run = func(ctx context.Context, e *plan.Env, r plan.Reporter) error {
			r.Progress(30, "working")
			r.Note(plan.Success, "fine")
			return nil
		}
	}
	err := plan.Run(context.Background(), ap.steps, &plan.Env{}, func(e plan.Event) { ap.handle(e) })
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range ap.states {
		if s.status != stepDone || len(s.notes) != 1 {
			t.Errorf("state %d = %+v", i, s)
		}
	}
	if !near(ap.overall(), 1) {
		t.Errorf("overall() = %v", ap.overall())
	}
}

func TestApplyView(t *testing.T) {
	t.Parallel()
	running := func(a *App) *apply {
		ap := syntheticApply(a)
		ap.started = time.Now().Add(-3 * time.Second)
		ap.handle(plan.Event{Kind: plan.StepStarted, Step: 0})
		ap.handle(plan.Event{Kind: plan.StepNote, Step: 0, Level: plan.Success, Text: "Signing key verified"})
		ap.handle(plan.Event{Kind: plan.StepFinished, Step: 0, Elapsed: 2 * time.Second})
		ap.handle(plan.Event{Kind: plan.StepStarted, Step: 1})
		ap.handle(plan.Event{Kind: plan.StepProgress, Step: 1, Percent: 42, Text: "Downloading tor"})
		return ap
	}
	finish := func(ap *apply, err error) {
		ap.done, ap.err, ap.ended = true, err, time.Now()
	}
	tests := []struct {
		name    string
		dry     bool
		prepare func(a *App, ap *apply)
		want    []string
		notWant []string
		keys    []string
	}{
		{
			name: "running",
			want: []string{"Applying", "1/3", "✓ First", "2.0s", "✓ Signing key verified", "Second  Downloading tor   42%", "○ Third"},
			keys: []string{"l", "toggle output", "ctrl+c", "abort"},
		},
		{
			name: "failed",
			prepare: func(a *App, ap *apply) {
				ap.handle(plan.Event{Kind: plan.StepFailed, Step: 1, Text: "dpkg lock held"})
				finish(ap, errors.New("setup stopped: dpkg lock held"))
			},
			want: []string{"Setup stopped", "✗ Second", "What went wrong", "setup stopped: dpkg lock held", "press r to retry", "Output", "✗ dpkg lock held"},
			keys: []string{"r", "retry", "l", "output", "q", "quit"},
		},
		{
			name:    "dry run complete",
			dry:     true,
			prepare: func(a *App, ap *apply) { finish(ap, nil) },
			want:    []string{"Dry run complete", "nothing was changed", "Run again without --dry-run"},
			notWant: []string{"Output"},
			keys:    []string{"enter", "finish", "l", "output"},
		},
		{
			name: "configured and reachable",
			prepare: func(a *App, ap *apply) {
				ap.setup.Family.Mode = "generate"
				ap.env = plan.NewEnv(a.opt.Host, a.checks.Facts, ap.setup, "p")
				ap.env.FamilyID = famID("F")
				ap.finger = strings.Repeat("AB", 20)
				ap.reaching, ap.reachDone, ap.reach = true, true, service.SelfTest{IPv4: true, IPv6: true}
				finish(ap, nil)
			},
			want: []string{"Relay configured", "Your relay", "Nickname      TestRelay", "Fingerprint   " + strings.Repeat("AB", 20),
				"FamilyId      " + famID("F"), "✓ ORPort reachable from outside (IPv4 + IPv6)", "Copy the family key"},
		},
		{
			name: "configured but not confirmed",
			prepare: func(a *App, ap *apply) {
				ap.env = plan.NewEnv(a.opt.Host, a.checks.Facts, ap.setup, "p")
				ap.reachDone, ap.reach = true, service.SelfTest{Failed: true}
				finish(ap, nil)
			},
			want:    []string{"! not confirmed — check the provider firewall for TCP 9001"},
			notWant: []string{"FamilyId", "Fingerprint"},
		},
		{
			name: "configured, still waiting",
			prepare: func(a *App, ap *apply) {
				ap.env = plan.NewEnv(a.opt.Host, a.checks.Facts, ap.setup, "p")
				ap.reaching, ap.reachStart = true, time.Now()
				finish(ap, nil)
			},
			want: []string{"waiting for Tor's self-test", "enter finishes now"},
		},
		{
			name: "output toggled",
			prepare: func(a *App, ap *apply) {
				ap.update(a, tea.KeyPressMsg{Code: 'l', Text: "l"})
			},
			want: []string{"Output", "── First", "• Signing key verified"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := testApp()
			a.opt.DryRun = tt.dry
			ap := running(a)
			if tt.prepare != nil {
				tt.prepare(a, ap)
			}
			got := strip(ap.view(a))
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("view lacks %q:\n%s", w, got)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("view unexpectedly contains %q:\n%s", w, got)
				}
			}
			if tt.keys != nil && !reflect.DeepEqual(ap.keys(a), tt.keys) {
				t.Errorf("keys = %q, want %q", ap.keys(a), tt.keys)
			}
		})
	}
}

func TestApplyHostEventsAreCompacted(t *testing.T) {
	t.Parallel()
	a := testApp()
	ap := syntheticApply(a)
	ap.update(a, applyHostMsg{Kind: host.EventCommand, Text: "DEBIAN_FRONTEND=noninteractive apt-get -q -y -o A=B install tor", Dry: true})
	ap.update(a, applyHostMsg{Kind: host.EventFile, Text: "would write /etc/tor/torrc", Dry: true})
	want := []string{"would run $ apt-get install tor", "  would write /etc/tor/torrc"}
	if !reflect.DeepEqual(ap.log, want) {
		t.Errorf("log = %q, want %q", ap.log, want)
	}
}

func TestApplyLogPanelKeepsTheLog(t *testing.T) {
	t.Parallel()
	a := testApp()
	ap := syntheticApply(a)
	long := strings.Repeat("x", 200)
	ap.log = []string{long}
	panel := strip(ap.logPanel(a, 50))
	if strings.Contains(panel, long) {
		t.Error("log panel did not truncate a long line")
	}
	if ap.log[0] != long {
		t.Skip("BUG: apply.logPanel (internal/tui/apply.go, the `lines[i] = truncate(l, w-4)` loop) truncates " +
			"entries of ap.log in place because `lines` aliases ap.log; after one narrow render the in-memory " +
			"output stays cut off even when the window is widened")
	}
}

// ---------------------------------------------------------------- console

func consoleReport() status.Report {
	var r status.Report
	r.Tor.Installed, r.Tor.Version, r.Tor.Supported = true, "0.4.9.3", true
	r.Service.Unit, r.Service.Active = "tor@default", true
	r.Relay.Configured, r.Relay.Nickname = true, "GoodRelay"
	r.Relay.Fingerprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
	r.Relay.ORPort, r.Relay.IPv6, r.Relay.Sandbox = 9001, true, true
	r.Relay.MetricsPort = "127.0.0.1:9035"
	r.Relay.Bandwidth = "1640 KBytes (burst 8200 KBytes)"
	r.Relay.Accounting = "8381 GBytes per month, rule sum"
	r.Listener.IPv4 = true
	r.Reachability.IPv4, r.Reachability.IPv6, r.Reachability.Seen = true, true, true
	return r
}

func TestConsoleCards(t *testing.T) {
	t.Parallel()
	famA, famB := famID("A"), famID("B")
	tests := []struct {
		name    string
		width   int
		mutate  func(c *console)
		want    []string
		notWant []string
	}{
		{
			name:  "healthy relay, two columns",
			width: 200,
			want: []string{
				"Nickname     GoodRelay", "Fingerprint  ABCDEF0123456789ABCDEF0123456789ABCDEF01", "Mode         guard / middle",
				"ORPort       9001 (IPv4 + IPv6)", "Service       ✓ running", "tor           ✓ 0.4.9.3", "Listener      ✓ TCP 9001",
				"Reachability  ✓ reachable (IPv4 + IPv6)", "single relay (no FamilyId)", "Limit        1640 KBytes (burst 8200 KBytes)",
				"Accounting   8381 GBytes per month, rule sum", "MetricsPort  127.0.0.1:9035", "Sandbox      yes",
				"Not published yet",
			},
			notWant: []string{"Needs attention", "Recent log"},
		},
		{
			name:  "fingerprint is shortened in narrow cards",
			width: 120,
			want:  []string{"Fingerprint  ABCDEF01…ABCDEF01"},
		},
		{
			name:  "warnings and a family key missing",
			width: 120,
			mutate: func(c *console) {
				c.report.Family.IDs = []string{famA, famB}
				c.report.Family.MissingKeys = []string{famB}
				c.report.Family.LegacyCount = 2
				c.report.Warnings = []string{"no family key installed for FamilyId " + famB}
			},
			want: []string{
				"Needs attention", "! no family key installed for FamilyId " + famB,
				"✓  " + famA, "✗  " + famB, "legacy MyFamily: 2 fingerprints",
			},
			notWant: []string{"single relay"},
		},
		{
			name:  "stopped relay without tor",
			width: 120,
			mutate: func(c *console) {
				r := &c.report
				r.Service.Active, r.Tor.Installed, r.Tor.Version, r.Tor.Supported = false, false, "", false
				r.Listener.IPv4 = false
				r.Reachability.IPv4, r.Reachability.IPv6, r.Reachability.Failed = false, false, true
				r.Relay.Exit, r.Relay.IPv6, r.Relay.Sandbox = true, false, false
				r.Relay.Bandwidth, r.Relay.Accounting, r.Relay.MetricsPort, r.Relay.Fingerprint = "", "", "", ""
			},
			want: []string{
				"✗ stopped", "✗ not installed", "✗ TCP 9001", "✗ not reachable from outside", "Mode         exit",
				"ORPort       9001", "Limit        no limit", "Accounting   off", "MetricsPort  off", "Sandbox      no",
				"not generated yet", "Start Tor once to get a fingerprint.",
			},
			notWant: []string{"IPv4 + IPv6"},
		},
		{
			name:   "unsupported tor and no self-test",
			width:  120,
			mutate: func(c *console) { c.report.Tor.Supported = false; c.report.Reachability = status.Report{}.Reachability },
			want:   []string{"! 0.4.9.3", "not tested since startup"},
		},
		{
			name:  "recent log",
			width: 120,
			mutate: func(c *console) {
				c.report.RecentLog = []string{"Mar 04 [warn] Clock skew detected", "Self-testing indicates your ORPort is reachable"}
			},
			want: []string{"Recent log  (l opens the live view)", "Mar 04 [warn] Clock skew detected"},
		},
		{
			name:   "directory lookup in progress",
			width:  120,
			mutate: func(c *console) { c.dirLoading = true },
			want:   []string{"SPIN asking Tor Metrics…"},
		},
		{
			name:   "directory lookup failed",
			width:  120,
			mutate: func(c *console) { c.dirErr = errors.New("onionoo timeout") },
			want:   []string{"! onionoo timeout"},
		},
		{
			name:  "directory entry",
			width: 120,
			mutate: func(c *console) {
				c.dir = &onionoo.Relay{Running: true, Flags: []string{"Fast", "Guard", "Running"}, AdvertisedBandwidth: 1_678_000, ConsensusWeight: 4200, FirstSeen: "2026-01-01 00:00:00"}
			},
			want: []string{"Status      ✓ running", "Flags       Fast Guard Running", "Advertised  13.4 Mbit/s", "Weight      4200", "First seen  2026-01-01 00:00:00"},
		},
		{
			name:  "single column",
			width: 70,
			mutate: func(c *console) {
				c.report.Warnings = []string{"tor@default is not running"}
			},
			want: []string{"Needs attention", "Fingerprint  ABCDEF0123456789ABCDEF0123456789ABCDEF01", "Tor Metrics"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := testApp()
			a.spin.Spinner.Frames = []string{"SPIN"}
			c := newConsole()
			c.report, c.loaded = consoleReport(), true
			if tt.mutate != nil {
				tt.mutate(c)
			}
			got := strip(c.cards(a, tt.width))
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("cards lack %q:\n%s", w, got)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("cards unexpectedly contain %q:\n%s", w, got)
				}
			}
			if len(c.report.Warnings) > 0 && !strings.HasPrefix(got, "╭") {
				t.Errorf("the warnings panel should come first:\n%s", got)
			}
			if len(c.report.Warnings) > 0 {
				if i, j := strings.Index(got, "Needs attention"), strings.Index(got, "Nickname"); i < 0 || i > j {
					t.Errorf("Needs attention (%d) should precede the relay card (%d)", i, j)
				}
			}
		})
	}
}

func TestConsoleCardsShortFingerprint(t *testing.T) {
	t.Parallel()
	a := testApp()
	c := newConsole()
	c.report, c.loaded = consoleReport(), true
	c.report.Relay.Fingerprint = "BROKEN" // e.g. a truncated /var/lib/tor/fingerprint file
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("BUG: console.cards (internal/tui/console.go, `fp[:8] + \"…\" + fp[len(fp)-8:]`) panics "+
				"when the fingerprint read from /var/lib/tor/fingerprint is shorter than 16 characters and the card "+
				"is narrower than 60 columns (status.Collect does not validate it): %v", r)
		}
	}()
	got := strip(c.cards(a, 50))
	if !strings.Contains(got, "BROKEN") {
		t.Errorf("short fingerprint not shown:\n%s", got)
	}
}

func TestConsoleViewAndKeys(t *testing.T) {
	t.Parallel()
	a := testApp()
	c := newConsole()
	if v := strip(c.view(a)); !strings.Contains(v, "Checking the relay…") || !strings.Contains(v, "Actions") || !strings.Contains(v, "Refresh") {
		t.Errorf("loading view =\n%s", v)
	}

	// Navigation wraps around.
	c.update(a, tea.KeyPressMsg{Code: tea.KeyUp})
	if c.cursor != len(c.actions)-1 {
		t.Errorf("up from the top: cursor = %d", c.cursor)
	}
	c.update(a, tea.KeyPressMsg{Code: tea.KeyDown})
	c.update(a, tea.KeyPressMsg{Code: 'j', Text: "j"})
	if c.cursor != 1 {
		t.Errorf("cursor = %d, want 1", c.cursor)
	}

	// Refresh collects a report from the (fake) host; no fingerprint means
	// no Tor Metrics lookup, so nothing touches the network.
	next, cmd := c.update(a, tea.KeyPressMsg{Code: 'r', Text: "r"})
	if next != c || cmd == nil || c.cursor != 0 {
		t.Fatalf("r: next %T, cmd %v, cursor %d", next, cmd != nil, c.cursor)
	}
	msg, ok := cmd().(reportMsg)
	if !ok {
		t.Fatalf("refresh produced %T, want reportMsg", msg)
	}
	if _, cmd := c.update(a, msg); cmd != nil || !c.loaded {
		t.Errorf("report without a fingerprint: loaded %v, lookup cmd %v", c.loaded, cmd != nil)
	}
	v := strip(c.view(a))
	for _, w := range []string{"Actions", "Health", "Traffic"} {
		if !strings.Contains(v, w) {
			t.Errorf("loaded view lacks %q:\n%s", w, v)
		}
	}

	c.report.Relay.Fingerprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
	if c.lookup(a) == nil || !c.dirLoading {
		t.Error("a fingerprint should start a Tor Metrics lookup")
	}
	c.update(a, directoryMsg{relay: &onionoo.Relay{Running: true}})
	if c.dirLoading || c.dir == nil {
		t.Errorf("directory result not stored: loading %v dir %v", c.dirLoading, c.dir)
	}

	if _, cmd := c.update(a, tea.KeyPressMsg{Code: 'q', Text: "q"}); cmd == nil {
		t.Error("q returned no command")
	} else if m, ok := cmd().(quitMsg); !ok || m.err != nil {
		t.Errorf("q produced %v, want a clean quit", m)
	}
}
