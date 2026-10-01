package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/ljkx/tor-relay-setup/internal/config"
	"github.com/ljkx/tor-relay-setup/internal/family"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/plan"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/service"
)

// ---------------------------------------------------------------- logs

type logLineMsg string

// logView shows the Tor journal and follows it live.
type logView struct {
	back   *console
	vp     viewport.Model
	lines  []string
	follow bool
	events chan tea.Msg
	cancel context.CancelFunc
}

func newLogView(back *console) *logView {
	return &logView{back: back, vp: viewport.New(), follow: true, events: make(chan tea.Msg, 512)}
}

func (l *logView) start(a *App) tea.Cmd {
	l.resize(a)
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	events := l.events
	tor := service.Tor{Host: a.opt.Host, Unit: service.DefaultUnit}
	go func() {
		_ = tor.Follow(ctx, func(s string) {
			select {
			case events <- logLineMsg(s):
			case <-ctx.Done():
			}
		})
	}()
	return l.listen()
}

func (l *logView) listen() tea.Cmd {
	ch := l.events
	return func() tea.Msg { return <-ch }
}

func (l *logView) resize(a *App) {
	l.vp.SetWidth(a.contentWidth())
	l.vp.SetHeight(clamp(a.height-6, 3, 500))
}

func (l *logView) render(a *App) {
	t := a.theme
	out := make([]string, len(l.lines))
	for i, line := range l.lines {
		switch {
		case strings.Contains(line, "[warn]"), strings.Contains(line, "[err]"):
			out[i] = t.WarnText.Render(line)
		case strings.Contains(line, "Self-testing indicates"):
			out[i] = t.GoodText.Render(line)
		default:
			out[i] = t.Subtle.Render(line)
		}
	}
	l.vp.SetContentLines(out)
	if l.follow {
		l.vp.GotoBottom()
	}
}

func (l *logView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		l.resize(a)
		l.render(a)
	case logLineMsg:
		l.lines = append(l.lines, string(msg))
		if len(l.lines) > 3000 {
			l.lines = l.lines[len(l.lines)-3000:]
		}
		l.render(a)
		return l, l.listen()
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc", "q", "backspace":
			l.cancel()
			return l.back, l.back.refresh(a)
		case "f", "end", "G":
			l.follow = true
			l.vp.GotoBottom()
			return l, nil
		case "up", "k", "pgup", "home", "g":
			l.follow = false
		}
	}
	var cmd tea.Cmd
	l.vp, cmd = l.vp.Update(msg)
	return l, cmd
}

func (l *logView) view(a *App) string {
	t := a.theme
	state := t.GoodText.Render("● following")
	if !l.follow {
		state = t.Subtle.Render("○ paused (f resumes)")
	}
	return t.Title.Render(" Tor log") + "  " + state + t.Subtle.Render("  · "+service.DefaultUnit) + "\n" + l.vp.View()
}

func (l *logView) keys(a *App) []string {
	return []string{"↑/↓", "scroll", "f", "follow", "esc", "back"}
}

// ---------------------------------------------------------------- family

// familyView manages FamilyId keys on this relay.
type familyView struct {
	back   *console
	cursor int
	form   *huh.Form
	mode   string // "", create, import, remove, share
	name   string
	path   string
	id     string
	remove string
}

func newFamilyView(a *App, back *console) *familyView { return &familyView{back: back} }

var familyActions = []struct{ key, label, desc string }{
	{"c", "Create a family key", "Start a family (or rotate: old IDs can be kept)"},
	{"i", "Import a family key", "Join the family of another relay you run"},
	{"s", "Share with another relay", "How to copy this family's key safely"},
	{"x", "Remove a FamilyId", "Leave a family; key files stay on disk"},
	{"m", "Remove legacy MyFamily", "Drop pre-0.4.9 fingerprint lists once FamilyId is set"},
}

func (f *familyView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	if f.form != nil {
		m, cmd := f.form.Update(msg)
		if ff, ok := m.(*huh.Form); ok {
			f.form = ff
		}
		switch f.form.State {
		case huh.StateCompleted:
			f.form = nil
			return f.run(a)
		case huh.StateAborted:
			f.form, f.mode = nil, ""
		}
		return f, cmd
	}
	if k, ok := msg.(tea.KeyPressMsg); ok {
		switch k.String() {
		case "esc", "q", "backspace":
			return f.back, f.back.refresh(a)
		case "up", "k":
			f.cursor = (f.cursor - 1 + len(familyActions)) % len(familyActions)
		case "down", "j", "tab":
			f.cursor = (f.cursor + 1) % len(familyActions)
		case "enter":
			return f.start(a, familyActions[f.cursor].key)
		default:
			for _, act := range familyActions {
				if k.String() == act.key {
					return f.start(a, act.key)
				}
			}
		}
	}
	return f, nil
}

func (f *familyView) start(a *App, key string) (screen, tea.Cmd) {
	r := f.back.report
	switch key {
	case "c":
		f.mode, f.name = "create", "relay-family"
		f.form = huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("Family key name").Value(&f.name).Validate(func(s string) error {
				if !relay.ValidFamilyKeyName(s) {
					return errors.New("letters, digits, '.', '_' or '-'")
				}
				return nil
			}),
		)).WithTheme(a.theme.Form()).WithShowHelp(false).WithKeyMap(escKeyMap())
	case "i":
		f.mode = "import"
		f.form = huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("Path to NAME.secret_family_key").Placeholder("/root/relay-family.secret_family_key").
				Value(&f.path).Validate(func(s string) error {
				data, err := os.ReadFile(strings.TrimSpace(s))
				if err != nil || !family.ValidKey(data) {
					return errors.New("not a readable Tor family key file")
				}
				return nil
			}),
			huh.NewInput().Title("FamilyId (empty when NAME.public_family_id is next to the key)").Value(&f.id),
		)).WithTheme(a.theme.Form()).WithShowHelp(false).WithKeyMap(escKeyMap())
	case "x":
		if len(r.Family.IDs) == 0 {
			return f, toast("No FamilyId is configured.")
		}
		f.mode = "remove"
		opts := make([]huh.Option[string], len(r.Family.IDs))
		for i, id := range r.Family.IDs {
			opts[i] = huh.NewOption(id, id)
		}
		f.form = huh.NewForm(huh.NewGroup(
			huh.NewSelect[string]().Title("Remove which FamilyId?").Options(opts...).Value(&f.remove),
		)).WithTheme(a.theme.Form()).WithShowHelp(false).WithKeyMap(escKeyMap())
	case "s":
		f.mode = "share"
		return f, nil
	case "m":
		if r.Family.LegacyCount == 0 {
			return f, toast("No legacy MyFamily lines are configured.")
		}
		back := f.back
		question := fmt.Sprintf("Remove the MyFamily list (%d fingerprints)?", r.Family.LegacyCount)
		if len(r.Family.IDs) == 0 {
			question += " No FamilyId is set yet: create or import one first, or this relay loses its family."
		}
		return newConfirmView(f, question, func() (screen, tea.Cmd) {
			return newTask(a, back, "Remove legacy MyFamily", func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
				data, err := h.ReadFile(torrcPath)
				if err != nil {
					return "", err
				}
				doc := relay.ParseDocument(data)
				doc.SetMyFamily(nil)
				if err := writeTorrc(ctx, h, doc.Bytes(), false, out); err != nil {
					return "", err
				}
				return "MyFamily removed; FamilyId keeps the family together.", nil
			})
		}), nil
	}
	if f.form != nil {
		return f, f.form.Init()
	}
	return f, nil
}

func (f *familyView) run(a *App) (screen, tea.Cmd) {
	back := f.back
	keyDir := back.report.Family.KeyDirectory
	current := append([]string(nil), back.report.Family.IDs...)
	switch f.mode {
	case "create":
		name := f.name
		return newTask(a, back, "Create family key "+name, func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
			work, err := os.MkdirTemp("", "tor-family-")
			if err != nil {
				return "", err
			}
			defer os.RemoveAll(work)
			progress(20, "tor --keygen-family "+name)
			secret, id, err := family.Generate(ctx, h, work, name)
			if err != nil {
				return "", err
			}
			if err := family.Install(h, keyDir, name, secret, id, plan.TorUser); err != nil {
				return "", err
			}
			if id == "" {
				return "Dry run: a key would be generated and added as a FamilyId.", nil
			}
			progress(60, "updating torrc")
			if err := updateFamilyIDs(ctx, h, append(current, id), out); err != nil {
				return "", err
			}
			return "FamilyId " + id + "\nCopy the key to your other relays: Relay family → Share.", nil
		})
	case "import":
		path, id := strings.TrimSpace(f.path), strings.TrimSpace(f.id)
		return newTask(a, back, "Import family key", func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
			data, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			if pub, err := os.ReadFile(strings.TrimSuffix(path, ".secret_family_key") + ".public_family_id"); err == nil {
				id = strings.TrimSpace(string(pub))
			}
			if !relay.ValidFamilyID(id) {
				return "", errors.New("no valid FamilyId: put NAME.public_family_id next to the key or enter the ID")
			}
			name := strings.TrimSuffix(filepath.Base(path), ".secret_family_key")
			if err := family.Install(h, keyDir, name, data, id, plan.TorUser); err != nil {
				return "", err
			}
			if err := updateFamilyIDs(ctx, h, append(current, id), out); err != nil {
				return "", err
			}
			return "Joined family " + id + ". Delete the copied key files from where you uploaded them.", nil
		})
	case "remove":
		drop := f.remove
		var keep []string
		for _, id := range current {
			if id != drop {
				keep = append(keep, id)
			}
		}
		return newTask(a, back, "Remove FamilyId", func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
			if err := updateFamilyIDs(ctx, h, keep, out); err != nil {
				return "", err
			}
			return "Removed " + drop + ". Key files were left in place.", nil
		})
	}
	return f, nil
}

func updateFamilyIDs(ctx context.Context, h host.Host, ids []string, out func(string)) error {
	data, err := h.ReadFile(torrcPath)
	if err != nil {
		return err
	}
	doc := relay.ParseDocument(data)
	doc.SetFamilyIDs(ids)
	// Sandbox 1 cannot open new key files after start-up: restart, not reload.
	return writeTorrc(ctx, h, doc.Bytes(), true, out)
}

func (f *familyView) view(a *App) string {
	t := a.theme
	w := a.contentWidth()
	r := f.back.report
	if f.form != nil {
		return t.Title.Render(" Relay family") + "\n\n" + panel(t, "", f.form.View(), clamp(w, 40, 90), true)
	}

	var status strings.Builder
	if len(r.Family.IDs) == 0 {
		status.WriteString(t.Subtle.Render("No FamilyId configured — this relay is not in a family."))
	}
	for _, id := range r.Family.IDs {
		missing := false
		for _, m := range r.Family.MissingKeys {
			missing = missing || m == id
		}
		status.WriteString(statusIcon(t, !missing, false) + " " + id)
		if missing {
			status.WriteString(t.BadText.Render("  key missing"))
		}
		status.WriteString("\n")
	}
	status.WriteString("\n" + t.Subtle.Render("Key directory: "+r.Family.KeyDirectory))
	for _, k := range r.Family.Keys {
		status.WriteString("\n" + t.Subtle.Render("  "+filepath.Base(k.Path)))
	}
	if r.Family.LegacyCount > 0 {
		status.WriteString("\n\n" + t.WarnText.Render(iconWarn+" legacy MyFamily lists "+itoa(r.Family.LegacyCount)+" fingerprints; current clients use FamilyId only"))
	}

	var menu strings.Builder
	for i, act := range familyActions {
		line := " " + t.Key.Render(act.key) + "  " + act.label
		if i == f.cursor {
			line = t.Selected.Render(" "+act.key+"  "+act.label) + "\n" + t.Subtle.Render("    "+act.desc)
		}
		menu.WriteString(line + "\n")
	}
	body := panel(t, "Status", strings.TrimRight(status.String(), "\n"), w, false) + "\n" +
		panel(t, "Actions", strings.TrimRight(menu.String(), "\n"), w, true)
	if f.mode == "share" {
		body += "\n" + panel(t, "Share this family", family.ShareInstructions(r.Family.Keys, "NEW-RELAY"), w, true)
	}
	return t.Title.Render(" Relay family") + t.Subtle.Render(" · Tor 0.4.9 FamilyId") + "\n\n" + body
}

func (f *familyView) keys(a *App) []string {
	if f.form != nil {
		return []string{"enter", "next", "esc", "cancel"}
	}
	return []string{"↑/↓", "select", "enter", "run", "esc", "back"}
}

// ---------------------------------------------------------------- edit

// editView changes common settings in the live torrc.
type editView struct {
	back *console
	form *huh.Form
	ans  *answers
	doc  *relay.Document
	was  config.Setup
}

func newEditView(a *App, back *console) (screen, tea.Cmd) {
	data, err := a.opt.Host.ReadFile(torrcPath)
	if err != nil {
		return back, toast("Cannot read " + torrcPath + ": " + err.Error())
	}
	doc := relay.ParseDocument(data)
	s := config.FromDocument(doc)
	e := &editView{back: back, ans: answersFrom(s), doc: doc, was: s}
	e.ans.ContactFormat = "free"
	ans := e.ans
	e.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Nickname").Value(&ans.Nickname).Validate(func(s string) error {
				if !relay.ValidNickname(strings.TrimSpace(s)) {
					return errors.New("1–19 letters or digits")
				}
				return nil
			}),
			huh.NewInput().Title("ContactInfo").Value(&ans.ContactFree).Validate(func(s string) error {
				if !relay.ValidContactInfo(strings.TrimSpace(s)) {
					return errors.New("required, max 250 characters, no '#'")
				}
				return nil
			}),
			newConfirm().Title("MetricsPort on 127.0.0.1:9035?").Value(&ans.Metrics),
			newConfirm().Title("Sandbox 1?").Description("Changing this restarts Tor.").Value(&ans.Sandbox),
		).Title("Relay"),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Bandwidth").Options(bandwidthOptions(ans.BandwidthMode)...).Value(&ans.BandwidthMode),
		).Title("Bandwidth"),
		huh.NewGroup(
			huh.NewInput().Title("Monthly quota").Description("e.g. 10TB (decimal) or 9313GiB").Value(&ans.Quota).
				Validate(func(s string) error {
					if _, err := relay.ParseQuota(s); err != nil {
						return errors.New("a quota such as 10TB")
					}
					return nil
				}),
			huh.NewInput().Title("Headroom (%)").Value(&ans.Headroom),
			huh.NewSelect[string]().Title("Traffic counted as").Options(
				huh.NewOption("in + out combined", string(relay.RuleSum)),
				huh.NewOption("outbound only", string(relay.RuleOut)),
				huh.NewOption("each direction separately", string(relay.RuleMax)),
			).Value(&ans.Billing),
			huh.NewNote().Title("Result").DescriptionFunc(ans.budgetSummary, ans),
		).WithHideFunc(func() bool {
			return ans.BandwidthMode != string(relay.BandwidthSteady) && ans.BandwidthMode != string(relay.BandwidthAccounting)
		}),
		huh.NewGroup(
			huh.NewInput().Title("Rate (Mbit/s)").Value(&ans.RateMbit),
			huh.NewInput().Title("Burst (Mbit/s)").Value(&ans.BurstMbit),
		).WithHideFunc(func() bool { return ans.BandwidthMode != string(relay.BandwidthManual) }),
	).WithTheme(a.theme.Form()).WithShowHelp(false).WithKeyMap(escKeyMap())
	return e, e.form.Init()
}

func (e *editView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	m, cmd := e.form.Update(msg)
	if f, ok := m.(*huh.Form); ok {
		e.form = f
	}
	switch e.form.State {
	case huh.StateAborted:
		return e.back, nil
	case huh.StateCompleted:
		s := e.ans.setup()
		bw, err := s.Bandwidth.Resolve()
		if err != nil {
			return e.back, toast("Bandwidth: " + err.Error())
		}
		doc := e.doc
		doc.Set("Nickname", s.Relay.Nickname)
		doc.Set("ContactInfo", relay.Quote(s.Relay.Contact))
		doc.SetBandwidth(bw)
		if s.Relay.MetricsPort {
			doc.SetMetricsPort(config.DefaultMetricsPort)
		} else {
			doc.SetMetricsPort("")
		}
		restart := s.Relay.Sandbox != e.was.Relay.Sandbox
		if s.Relay.Sandbox {
			doc.Set("Sandbox", "1")
		} else {
			doc.Set("Sandbox", "0")
		}
		data := doc.Bytes()
		return newTask(a, e.back, "Apply settings", func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
			if err := writeTorrc(ctx, h, data, restart, out); err != nil {
				return "", err
			}
			return "Settings applied.", nil
		})
	}
	return e, cmd
}

func (e *editView) view(a *App) string {
	return a.theme.Title.Render(" Edit settings") + a.theme.Subtle.Render(" · verified with tor before anything is written") +
		"\n\n" + panel(a.theme, "", e.form.View(), clamp(a.contentWidth(), 40, 100), true)
}

func (e *editView) keys(a *App) []string {
	return []string{"enter", "next", "shift+tab", "back", "esc", "cancel"}
}

// escKeyMap lets Esc cancel a console form (ctrl+c still quits the app).
func escKeyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Quit = key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "cancel"))
	return km
}
