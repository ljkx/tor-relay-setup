package tui

import (
	"context"
	"errors"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
	"github.com/ljkx/tor-relay-setup/internal/update"
)

// Options configures a TUI session.
type Options struct {
	Host    host.Host
	Version string // e.g. "v3.0.0"
	DryRun  bool
	// Prefill seeds the wizard (from --config or the current torrc).
	Prefill *config.Setup
	// ConfigPath is where "save config" writes; default ./relay.toml.
	ConfigPath string
	// Onionoo is the Tor Metrics client; the zero value uses the public API.
	Onionoo onionoo.Client
	// UpdateCheck shows a header hint when a newer release exists.
	UpdateCheck bool
}

// stateDir holds the cached update check (and the setup state).
const stateDir = "/var/lib/tor-relay-setup"

type updateMsg string

// checkUpdate looks up the newest release in the background, at most once
// a day; failures are silent.
func checkUpdate() tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	latest, _ := update.CheckCached(ctx, stateDir, 24*time.Hour)
	return updateMsg(latest)
}

// newerRelease returns latest when it is newer than this build. Builds
// without a release version (dev, snapshots) never show the hint.
func newerRelease(current, latest string) string {
	if cmp, ok := update.Compare(current, latest); ok && cmp < 0 {
		return latest
	}
	return ""
}

// ErrAborted is returned when the operator quits before finishing.
var ErrAborted = errors.New("aborted")

// screen is one full-window view of the app.
type screen interface {
	update(a *App, msg tea.Msg) (screen, tea.Cmd)
	view(a *App) string
	// keys returns the footer key hints.
	keys(a *App) []string
}

// App is the root Bubble Tea model.
type App struct {
	opt    Options
	theme  Theme
	width  int
	height int
	checks Checks
	spin   spinner.Model
	screen screen
	err    error
	done   bool
	toast  string
	latest string // a newer release, when the update check found one
	// console, once started, keeps receiving its background updates while
	// another view is on screen.
	console *console
}

func newApp(opt Options, first screen) *App {
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	a := &App{opt: opt, theme: NewTheme(true), width: 100, height: 30, spin: sp, screen: first}
	a.spin.Style = lipgloss.NewStyle().Foreground(a.theme.Accent)
	return a
}

// Init starts background work: terminal colours, the spinner, and probes.
func (a *App) Init() tea.Cmd {
	cmds := []tea.Cmd{tea.RequestBackgroundColor, a.spin.Tick, detectFacts(a.opt.Host)}
	if a.opt.UpdateCheck {
		cmds = append(cmds, checkUpdate)
	}
	if s, ok := a.screen.(interface{ init(*App) tea.Cmd }); ok {
		cmds = append(cmds, s.init(a))
	}
	return tea.Batch(cmds...)
}

// Update routes messages to the shared state and the active screen.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
	case tea.BackgroundColorMsg:
		a.theme = NewTheme(msg.IsDark())
		a.spin.Style = lipgloss.NewStyle().Foreground(a.theme.Accent)
	case spinner.TickMsg:
		var cmd tea.Cmd
		a.spin, cmd = a.spin.Update(msg)
		cmds = append(cmds, cmd)
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			a.err = ErrAborted
			return a, tea.Quit
		}
		a.toast = ""
	case quitMsg:
		a.err, a.done = msg.err, true
		return a, tea.Quit
	case updateMsg:
		a.latest = newerRelease(a.opt.Version, string(msg))
		return a, nil
	case toastMsg:
		a.toast = string(msg)
	}
	if changed, cmd := a.checks.update(msg); changed {
		cmds = append(cmds, cmd)
	}
	if c := a.console; c != nil && a.screen != screen(c) {
		if cmd, ok := c.background(a, msg); ok {
			return a, tea.Batch(append(cmds, cmd)...)
		}
	}
	next, cmd := a.screen.update(a, msg)
	a.screen = next
	cmds = append(cmds, cmd)
	return a, tea.Batch(cmds...)
}

// View draws header, screen, and footer.
func (a *App) View() tea.View {
	t := a.theme
	right := a.checks.Facts.Hostname
	if a.opt.DryRun {
		right = t.Badge.Render("DRY RUN") + "  " + right
	}
	if a.latest != "" {
		right = t.WarnText.Render("↑ "+a.latest+" available · tor-relay-setup self-update") + "  " + right
	}
	top := header(t, a.width, a.opt.Version, right)
	body := a.screen.view(a)
	footer := keyHelp(t, a.screen.keys(a)...)
	if a.toast != "" {
		footer = " " + t.InfoText.Render(a.toast)
	}
	bodyHeight := a.height - 3
	if bodyHeight < 5 {
		bodyHeight = 5
	}
	body = lipgloss.NewStyle().Height(bodyHeight).MaxHeight(bodyHeight).Render(body)
	v := tea.NewView(strings.Join([]string{top, rule(t, a.width), body, footer}, "\n"))
	v.AltScreen = true
	v.WindowTitle = "tor-relay-setup"
	return v
}

// contentWidth is the usable width inside the window margins.
func (a *App) contentWidth() int { return clamp(a.width-2, 40, 160) }

type quitMsg struct{ err error }

type toastMsg string

func quit(err error) tea.Cmd { return func() tea.Msg { return quitMsg{err: err} } }

func toast(s string) tea.Cmd { return func() tea.Msg { return toastMsg(s) } }

// run starts the program and returns the screen-level error.
func run(a *App) error {
	final, err := tea.NewProgram(a).Run()
	if err != nil {
		return err
	}
	if fa, ok := final.(*App); ok {
		return fa.err
	}
	return nil
}
