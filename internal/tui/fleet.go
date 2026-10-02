package tui

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/onionoo"
)

// FleetOptions configures the fleet dashboard.
type FleetOptions struct {
	Version   string
	DryRun    bool
	Inventory fleet.Inventory
	// Probe runs fleet-probe on one server (remote.Fleet.Probe).
	Probe func(ctx context.Context, address string) fleet.HostProbe
	// Onionoo is the Tor Metrics client; the zero value uses the public API.
	Onionoo onionoo.Client
	// Rollout performs a rolling action ("restart", "reload" or
	// "update-tor") on the entries, one relay at a time, reporting output
	// lines (remote.Fleet.Rollout).
	Rollout func(ctx context.Context, action string, entries []fleet.Entry, out func(string)) error
	// Cache reads and writes the flag cache at CachePath; an empty path
	// keeps no cache.
	Cache     host.Host
	CachePath string
}

// RunFleet opens the fleet dashboard.
func RunFleet(opt FleetOptions) error {
	if opt.Cache == nil {
		opt.Cache = host.NewLocal()
	}
	a := newApp(Options{Host: opt.Cache, Version: opt.Version, DryRun: opt.DryRun, NoChecks: true}, nil)
	a.screen = newFleetView(opt)
	return run(a)
}

// How often the dashboard refreshes on its own.
const (
	fleetProbeEvery    = 10 * time.Second
	fleetDirEvery      = 30 * time.Minute // Onionoo publishes hourly
	fleetProbeParallel = 16
	fleetDirTimeout    = time.Minute
)

type (
	fleetProbeMsg fleet.HostProbe
	fleetTickMsg  time.Time
	fleetDirMsg   struct {
		details map[string]*onionoo.Relay
		history map[string]*onionoo.Bandwidth
		err     error
		at      time.Time
	}
)

// fleetSort is one way to order the table. desc makes the natural order
// largest first (rates, weights, warnings).
type fleetSort struct {
	name string
	desc bool
	cmp  func(v *fleetView, a, b *fleet.Relay) int
}

var fleetSorts = []fleetSort{
	{"inventory", false, nil},
	{"host", false, func(_ *fleetView, a, b *fleet.Relay) int {
		return cmp.Or(cmp.Compare(fleet.HostOf(a.Address), fleet.HostOf(b.Address)), cmp.Compare(a.Instance, b.Instance))
	}},
	{"nickname", false, func(_ *fleetView, a, b *fleet.Relay) int {
		return cmp.Compare(strings.ToLower(a.Nickname()), strings.ToLower(b.Nickname()))
	}},
	{"status", false, func(v *fleetView, a, b *fleet.Relay) int { return cmp.Compare(v.rank(a), v.rank(b)) }},
	{"live", true, func(_ *fleetView, a, b *fleet.Relay) int { return cmp.Compare(liveTotal(a), liveTotal(b)) }},
	{"weight", true, func(v *fleetView, a, b *fleet.Relay) int { return cmp.Compare(v.weight(a), v.weight(b)) }},
	{"warnings", true, func(_ *fleetView, a, b *fleet.Relay) int { return cmp.Compare(len(a.Warnings()), len(b.Warnings())) }},
	{"tor", false, func(_ *fleetView, a, b *fleet.Relay) int { return cmp.Compare(a.TorVersion(), b.TorVersion()) }},
}

// fleetView is the dashboard: totals, checks, and one row per relay.
type fleetView struct {
	opt      FleetOptions
	model    *fleet.Model
	inflight map[string]bool // addresses being probed
	sem      chan struct{}   // bounds concurrent probes
	ticking  bool
	updated  time.Time
	now      func() time.Time

	dirLoading bool

	sortBy    int
	reverse   bool
	filter    string
	filtering bool
	cursor    int
	offset    int
	detail    bool
}

func newFleetView(opt FleetOptions) *fleetView {
	v := &fleetView{
		opt: opt, model: fleet.NewModel(opt.Inventory), inflight: map[string]bool{},
		sem: make(chan struct{}, fleetProbeParallel), now: time.Now,
	}
	if opt.Cache != nil && opt.CachePath != "" {
		v.model.PrevFlags = fleet.LoadFlagCache(opt.Cache, opt.CachePath)
	}
	return v
}

// init registers the dashboard for background updates and probes every
// host right away.
func (v *fleetView) init(a *App) tea.Cmd {
	a.fleet = v
	cmds := []tea.Cmd{v.probeAll()}
	if !v.ticking {
		v.ticking = true
		cmds = append(cmds, fleetTick())
	}
	return tea.Batch(cmds...)
}

func fleetTick() tea.Cmd {
	return tea.Tick(fleetProbeEvery, func(t time.Time) tea.Msg { return fleetTickMsg(t) })
}

func (v *fleetView) headerRight() string {
	name := "fleet"
	if v.opt.Inventory.Path != "" {
		name = v.opt.Inventory.Path
	}
	return fmt.Sprintf("%s · %d relays", name, len(v.model.Relays()))
}

// probeAll probes every host that is not already being probed.
func (v *fleetView) probeAll() tea.Cmd {
	var cmds []tea.Cmd
	for _, h := range v.model.Hosts() {
		if v.inflight[h.Address] || v.opt.Probe == nil {
			continue
		}
		v.inflight[h.Address] = true
		probe, sem, addr := v.opt.Probe, v.sem, h.Address
		cmds = append(cmds, func() tea.Msg {
			sem <- struct{}{}
			defer func() { <-sem }()
			return fleetProbeMsg(probe(context.Background(), addr))
		})
	}
	return tea.Batch(cmds...)
}

// lookup asks Tor Metrics for every known fingerprint at once: details and
// traffic history, in bulk requests.
func (v *fleetView) lookup() tea.Cmd {
	fps := v.model.Fingerprints()
	if len(fps) == 0 || v.dirLoading {
		return nil
	}
	v.dirLoading = true
	client := v.opt.Onionoo
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), fleetDirTimeout)
		defer cancel()
		details, err := client.DetailsBulk(ctx, fps)
		var history map[string]*onionoo.Bandwidth
		if err == nil {
			history, _ = client.BandwidthBulk(ctx, fps)
		}
		return fleetDirMsg{details: details, history: history, err: err, at: time.Now()}
	}
}

// saveFlags stores the flags Tor Metrics reported, for the next run.
func (v *fleetView) saveFlags(details map[string]*onionoo.Relay, at time.Time) tea.Cmd {
	if v.opt.Cache == nil || v.opt.CachePath == "" || details == nil {
		return nil
	}
	h, path, prev := v.opt.Cache, v.opt.CachePath, v.model.PrevFlags
	return func() tea.Msg {
		_ = fleet.SaveFlagCache(h, path, prev, details, at)
		return nil
	}
}

// background handles probes, Tor Metrics results and timers, whether or
// not the dashboard is on screen; ok is false for other messages.
func (v *fleetView) background(a *App, msg tea.Msg) (tea.Cmd, bool) {
	switch msg := msg.(type) {
	case fleetProbeMsg:
		delete(v.inflight, msg.Address)
		v.model.Apply(fleet.HostProbe(msg))
		v.updated = v.now()
		if v.dirDue() {
			return v.lookup(), true
		}
		return nil, true
	case fleetDirMsg:
		v.dirLoading = false
		v.model.SetDirectory(msg.details, msg.err, msg.at)
		v.model.SetHistory(msg.history)
		if msg.err == nil {
			return v.saveFlags(msg.details, msg.at), true
		}
		return nil, true
	case fleetTickMsg:
		return tea.Batch(v.probeAll(), fleetTick()), true
	}
	return nil, false
}

// dirDue reports whether Tor Metrics should be asked: once every host
// answered for the first time, then every 30 minutes.
func (v *fleetView) dirDue() bool {
	if v.dirLoading {
		return false
	}
	if !v.model.DirAt.IsZero() {
		return v.now().Sub(v.model.DirAt) > fleetDirEvery
	}
	for _, h := range v.model.Hosts() {
		if h.State == fleet.HostPending {
			return false
		}
	}
	return true
}

// rows are the relays after filtering and sorting.
func (v *fleetView) rows() []*fleet.Relay {
	all := v.model.Relays()
	order := map[*fleet.Relay]int{}
	var out []*fleet.Relay
	for i, r := range all {
		order[r] = i
		if v.matches(r) {
			out = append(out, r)
		}
	}
	s := fleetSorts[v.sortBy]
	desc := s.desc != v.reverse
	// Ties keep inventory order, whichever way the column sorts.
	slices.SortStableFunc(out, func(a, b *fleet.Relay) int {
		c := cmp.Compare(order[a], order[b])
		if s.cmp != nil {
			c = s.cmp(v, a, b)
		}
		if desc {
			c = -c
		}
		return cmp.Or(c, cmp.Compare(order[a], order[b]))
	})
	return out
}

// matches applies the filter: a case-insensitive substring of the host,
// nickname, instance, fingerprint, state, flags or tor version.
func (v *fleetView) matches(r *fleet.Relay) bool {
	if v.filter == "" {
		return true
	}
	f := strings.ToLower(v.filter)
	fields := []string{r.Address, r.Nickname(), r.Instance, r.Fingerprint(), v.model.RelayState(r), r.TorVersion()}
	if d := v.model.DirectoryOf(r); d != nil {
		fields = append(fields, strings.Join(d.Flags, " "))
	}
	for _, s := range fields {
		if strings.Contains(strings.ToLower(s), f) {
			return true
		}
	}
	return false
}

// rank orders relays worst first for the status sort.
func (v *fleetView) rank(r *fleet.Relay) int {
	switch v.model.RelayState(r) {
	case string(fleet.HostUnreachable), string(fleet.HostFailed):
		return 0
	case "missing", "unconfigured":
		return 1
	case "stopped":
		return 2
	case string(fleet.HostTooOld), string(fleet.HostMissing):
		return 3
	case string(fleet.HostPending):
		return 4
	}
	if len(r.Warnings()) > 0 {
		return 5
	}
	return 6
}

func liveTotal(r *fleet.Relay) float64 {
	if !r.HasRate {
		return -1
	}
	return r.Rate.Total()
}

func (v *fleetView) weight(r *fleet.Relay) int64 {
	if d := v.model.DirectoryOf(r); d != nil {
		return d.ConsensusWeight
	}
	return -1
}

func (v *fleetView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	if cmd, ok := v.background(a, msg); ok {
		return v, cmd
	}
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return v, nil
	}
	if v.filtering {
		return v.filterKey(key)
	}
	rows := v.rows()
	if v.detail {
		switch key.String() {
		case "esc", "enter", "backspace", "q":
			v.detail = false
		case "up", "k":
			v.move(-1, len(rows))
		case "down", "j":
			v.move(1, len(rows))
		}
		return v, nil
	}
	switch key.String() {
	case "q":
		return v, quit(nil)
	case "up", "k":
		v.move(-1, len(rows))
	case "down", "j":
		v.move(1, len(rows))
	case "pgup":
		v.move(-v.pageSize(a), len(rows))
	case "pgdown", "space":
		v.move(v.pageSize(a), len(rows))
	case "home", "g":
		v.cursor = 0
	case "end", "G":
		v.cursor = max(len(rows)-1, 0)
	case "enter":
		if len(rows) > 0 {
			v.detail = true
		}
	case "s":
		v.sortBy = (v.sortBy + 1) % len(fleetSorts)
		v.reverse = false
	case "S":
		v.reverse = !v.reverse
	case "/":
		v.filtering = true
	case "esc":
		v.filter = ""
	case "r":
		v.model.DirAt = time.Time{} // ask Tor Metrics again too
		return v, v.probeAll()
	case "R":
		return v.confirmRollout(a, "restart", "Restart tor")
	case "O":
		return v.confirmRollout(a, "reload", "Reload tor")
	case "U":
		return v.confirmRollout(a, "update-tor", "Update tor")
	}
	return v, nil
}

// filterKey edits the filter while "/" is active.
func (v *fleetView) filterKey(key tea.KeyPressMsg) (screen, tea.Cmd) {
	switch key.String() {
	case "enter":
		v.filtering = false
	case "esc":
		v.filtering, v.filter = false, ""
	case "backspace":
		if r := []rune(v.filter); len(r) > 0 {
			v.filter = string(r[:len(r)-1])
		}
	default:
		if t := key.Text; t != "" && !strings.ContainsAny(t, "\n\t") {
			v.filter += t
		}
	}
	v.cursor, v.offset = 0, 0
	return v, nil
}

func (v *fleetView) move(delta, n int) {
	if n == 0 {
		v.cursor = 0
		return
	}
	v.cursor = clamp(v.cursor+delta, 0, n-1)
}

// confirmRollout asks before a rolling action on the relays in view.
func (v *fleetView) confirmRollout(a *App, action, title string) (screen, tea.Cmd) {
	var entries []fleet.Entry
	for _, r := range v.rows() {
		if r.Entry != nil {
			entries = append(entries, *r.Entry)
		}
	}
	if len(entries) == 0 || v.opt.Rollout == nil {
		return v, toast("No inventory relays in view.")
	}
	var b strings.Builder
	scope := "every relay"
	if v.filter != "" {
		scope = "the relays matching \"" + v.filter + "\""
	}
	fmt.Fprintf(&b, "%s on %s (%d), one relay at a time?\nEach must be running and listening again before the next starts; a failure stops the rollout.\n", title, scope, len(entries))
	for i, e := range entries {
		if i == 8 {
			fmt.Fprintf(&b, "\n  … and %d more", len(entries)-i)
			break
		}
		fmt.Fprintf(&b, "\n  %d. %s (%s)", i+1, e.Nickname(), e.Address)
	}
	if v.opt.DryRun {
		b.WriteString("\n\nDry run: each host only shows what it would do.")
	}
	rollout := v.opt.Rollout
	return newConfirmView(v, b.String(), func() (screen, tea.Cmd) {
		return runTask(a, v, func(*App) tea.Cmd { return v.probeAll() }, title+" across the fleet",
			func(ctx context.Context, _ host.Host, out func(string), _ func(float64, string)) (string, error) {
				if err := rollout(ctx, action, entries, out); err != nil {
					return "", err
				}
				return fmt.Sprintf("%s done on %d relays.", title, len(entries)), nil
			})
	}), nil
}

// pageSize is how many table rows fit on screen.
func (v *fleetView) pageSize(a *App) int { return max(a.height-3-v.chromeHeight(a), 3) }

// chromeHeight is the room the totals and attention panels take, plus the
// table's border, title and header.
func (v *fleetView) chromeHeight(a *App) int {
	h := lipgloss.Height(v.totalsPanel(a, a.contentWidth())) + 4
	if att := v.attentionPanel(a, a.contentWidth()); att != "" {
		h += lipgloss.Height(att)
	}
	return h
}

func (v *fleetView) view(a *App) string {
	w := a.contentWidth()
	rows := v.rows()
	v.cursor = clamp(v.cursor, 0, max(len(rows)-1, 0))
	parts := []string{v.totalsPanel(a, w)}
	if v.detail && len(rows) > 0 {
		return strings.Join(append(parts, v.detailView(a, rows[v.cursor], w)), "\n")
	}
	if att := v.attentionPanel(a, w); att != "" {
		parts = append(parts, att)
	}
	parts = append(parts, v.table(a, rows, w, v.pageSize(a)))
	return strings.Join(parts, "\n")
}

// totalsPanel is the fleet summary.
func (v *fleetView) totalsPanel(a *App, w int) string {
	t := a.theme
	tot := v.model.Totals()
	hosts := strconv.Itoa(tot.Hosts)
	if tot.Unreachable > 0 {
		hosts += t.Subtle.Render(" · ") + t.BadText.Render(fmt.Sprintf("%d unreachable", tot.Unreachable))
	}
	if tot.TooOld > 0 {
		hosts += t.Subtle.Render(" · ") + t.WarnText.Render(fmt.Sprintf("%d need self-update", tot.TooOld))
	}
	running := fmt.Sprintf("%d / %d running", tot.Running, tot.Relays)
	running = statusIcon(t, tot.Running == tot.Relays && tot.Relays > 0, tot.Running > 0) + " " + running
	left := [][2]string{{"Relays", running}, {"Hosts", hosts}}
	var right [][2]string

	switch {
	case v.dirLoading && v.model.DirAt.IsZero():
		left = append(left, [2]string{"Tor Metrics", a.spin.View() + " " + t.Subtle.Render("asking for "+strconv.Itoa(len(v.model.Fingerprints()))+" relays…")})
	case v.model.DirErr != nil:
		left = append(left, [2]string{"Tor Metrics", statusIcon(t, false, true) + " " + t.Subtle.Render(truncate(v.model.DirErr.Error(), w/2))})
	case v.model.DirAt.IsZero():
		left = append(left, [2]string{"Tor Metrics", t.Subtle.Render("waiting for the first probes")})
	default:
		left = append(left,
			[2]string{"Weight", fmt.Sprintf("%d", tot.ConsensusWeight) + t.Subtle.Render(" · "+fleet.Percent(tot.WeightFraction)+" of the network")},
			[2]string{"Selection", fmt.Sprintf("guard %s · middle %s · exit %s", fleet.Percent(tot.Guard), fleet.Percent(tot.Middle), fleet.Percent(tot.Exit))},
		)
		right = append(right, [2]string{"Advertised", humanRate(float64(tot.Advertised))})
	}
	live := t.Subtle.Render("measuring…")
	if tot.Read+tot.Written > 0 {
		live = t.InfoText.Render("↓ "+humanRate(tot.Read)) + "  " + t.Directive.Render("↑ "+humanRate(tot.Written))
	}
	right = append([][2]string{{"Live", live}}, right...)
	if len(tot.History) > 0 {
		label := fmt.Sprintf("%d days", len(tot.History))
		right = append(right,
			[2]string{label, t.Directive.Render(sparkline(tot.History, clamp(w/2-20, 8, 60)))},
			[2]string{"", t.Subtle.Render("in " + humanBytes(tot.HistoryIn) + " · out " + humanBytes(tot.HistoryOut))})
	}
	var body string
	if w >= 110 {
		lw := (w - 4) * 11 / 20
		body = lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(lw).Render(kv(t, left)), kv(t, right))
	} else {
		body = kv(t, append(left, right...))
	}
	return panel(t, "Fleet", body, w, false)
}

// maxAttention caps the attention panel (fewer on short terminals); the
// rest is summarized.
const maxAttention = 10

// attentionPanel lists the fleet checks, or is empty when all is well.
func (v *fleetView) attentionPanel(a *App, w int) string {
	t := a.theme
	items := v.model.Attention()
	if len(items) == 0 {
		return ""
	}
	limit := clamp(a.height/4, 3, maxAttention)
	var b strings.Builder
	for i, it := range items {
		if i == limit {
			fmt.Fprintf(&b, "\n%s", t.Subtle.Render(fmt.Sprintf("  … %d more (fleet status lists all)", len(items)-limit)))
			break
		}
		if i > 0 {
			b.WriteString("\n")
		}
		style := t.WarnText
		if it.Level == fleet.Bad {
			style = t.BadText
		}
		b.WriteString(style.Render(truncate(iconWarn+" "+it.Text, w-4)))
	}
	return panel(t, fmt.Sprintf("Needs attention (%d)", len(items)), b.String(), w, true)
}

// fleetCol is one table column.
type fleetCol struct {
	title string
	width int
	right bool
	cell  func(v *fleetView, r *fleet.Relay) string
}

// fleetColumns returns the columns that fit: lower-priority ones (instance,
// tor version, flags, weight) are dropped on narrow terminals, and the host
// column takes what is left.
func (v *fleetView) fleetColumns(inner int) (cols []fleetCol, hostW int) {
	all := []struct {
		col  fleetCol
		drop int // 0 never; higher drops first
	}{
		{fleetCol{"", 1, false, nil}, 0},
		{fleetCol{"HOST", 0, false, func(_ *fleetView, r *fleet.Relay) string { return fleet.HostOf(r.Address) }}, 0},
		{fleetCol{"NICKNAME", 19, false, func(_ *fleetView, r *fleet.Relay) string { return r.Nickname() }}, 0},
		{fleetCol{"INSTANCE", 9, false, func(_ *fleetView, r *fleet.Relay) string { return r.Instance }}, 4},
		{fleetCol{"FLAGS", 7, false, func(v *fleetView, r *fleet.Relay) string {
			if d := v.model.DirectoryOf(r); d != nil {
				return fleet.AbbrevFlags(d.Flags)
			}
			return ""
		}}, 2},
		{fleetCol{"TOR", 9, false, func(_ *fleetView, r *fleet.Relay) string { return r.TorVersion() }}, 3},
		{fleetCol{"LIVE", 12, true, func(_ *fleetView, r *fleet.Relay) string {
			if !r.HasRate {
				return ""
			}
			return humanRate(r.Rate.Total())
		}}, 0},
		{fleetCol{"WEIGHT", 8, true, func(v *fleetView, r *fleet.Relay) string {
			if w := v.weight(r); w >= 0 {
				return strconv.FormatInt(w, 10)
			}
			return ""
		}}, 1},
		{fleetCol{"WARN", 4, true, func(_ *fleetView, r *fleet.Relay) string {
			if r.Probe == nil {
				return ""
			}
			return strconv.Itoa(len(r.Warnings()))
		}}, 0},
	}
	const gap, minHost, maxHost, minNick = 2, 12, 28, 10
	for dropped := 0; ; dropped++ {
		cols = cols[:0]
		fixed := 0
		for _, c := range all {
			if c.drop > 0 && c.drop > 4-dropped {
				continue
			}
			cols = append(cols, c.col)
			fixed += c.col.width + gap
		}
		hostW = inner - (fixed - gap)
		if hostW >= minHost+2 || dropped == 4 {
			break
		}
	}
	// Still too narrow: shorten the nickname column before the host's.
	if short := minHost - hostW; short > 0 {
		for i := range cols {
			if cols[i].title == "NICKNAME" {
				cut := min(short, cols[i].width-minNick)
				cols[i].width -= cut
				hostW += cut
			}
		}
	}
	return cols, clamp(hostW, minHost, maxHost)
}

// table renders the relay rows with the cursor kept in view.
func (v *fleetView) table(a *App, rows []*fleet.Relay, w, height int) string {
	t := a.theme
	inner := w - 4
	cols, hostW := v.fleetColumns(inner)
	pad := func(s string, width int, right bool) string {
		s = truncate(s, width)
		if gap := width - lipgloss.Width(s); gap > 0 {
			if right {
				return strings.Repeat(" ", gap) + s
			}
			return s + strings.Repeat(" ", gap)
		}
		return s
	}
	width := func(c fleetCol) int {
		if c.title == "HOST" {
			return hostW
		}
		return c.width
	}
	var head []string
	for _, c := range cols {
		title := c.title
		if s := fleetSorts[v.sortBy]; strings.EqualFold(c.title, s.name) || (c.title == "WARN" && s.name == "warnings") || (c.title == "" && s.name == "status") {
			arrow := "↑"
			if s.desc != v.reverse {
				arrow = "↓"
			}
			title = strings.TrimSpace(title + arrow)
		}
		head = append(head, pad(title, width(c), c.right))
	}
	lines := []string{t.Subtle.Render(strings.Join(head, "  "))}

	height = max(height, 1)
	if v.cursor < v.offset {
		v.offset = v.cursor
	}
	if v.cursor >= v.offset+height {
		v.offset = v.cursor - height + 1
	}
	v.offset = clamp(v.offset, 0, max(len(rows)-height, 0))
	end := min(v.offset+height, len(rows))
	for i := v.offset; i < end; i++ {
		r := rows[i]
		cells := make([]string, len(cols))
		for j, c := range cols {
			if c.cell == nil {
				cells[j] = " "
				continue
			}
			cells[j] = pad(c.cell(v, r), width(c), c.right)
		}
		line := strings.Join(cells, "  ")
		icon := v.icon(a, r)
		if i == v.cursor {
			lines = append(lines, icon+t.Selected.Render(pad(line[1:], inner-1, false)))
			continue
		}
		lines = append(lines, icon+line[1:])
	}
	if len(rows) == 0 {
		msg := "No relays."
		if v.filter != "" {
			msg = "No relay matches \"" + v.filter + "\" (esc clears the filter)."
		}
		lines = append(lines, t.Subtle.Render(msg))
	}
	title := fmt.Sprintf("Relays · sorted by %s", fleetSorts[v.sortBy].name)
	if v.reverse {
		title += " (reversed)"
	}
	switch {
	case v.filtering:
		title += " · filter: " + v.filter + "▌"
	case v.filter != "":
		title += fmt.Sprintf(" · filter %q: %d of %d", v.filter, len(rows), len(v.model.Relays()))
	}
	if len(rows) > height {
		title += fmt.Sprintf(" · %d–%d of %d", v.offset+1, end, len(rows))
	}
	return panel(t, title, strings.Join(lines, "\n"), w, false)
}

// icon is a relay's status mark.
func (v *fleetView) icon(a *App, r *fleet.Relay) string {
	t := a.theme
	switch v.rank(r) {
	case 0, 1, 2:
		return t.BadText.Render(iconFail)
	case 3, 5:
		return t.WarnText.Render(iconWarn)
	case 4:
		return t.Faintly.Render(iconPending)
	}
	return t.GoodText.Render(iconDone)
}

// detailView shows one relay: its report, host, and Tor Metrics data.
func (v *fleetView) detailView(a *App, r *fleet.Relay, w int) string {
	t := a.theme
	state := v.model.RelayState(r)
	hostDetail := ""
	relayRows := [][2]string{
		{"Nickname", r.Nickname()},
		{"Host", r.Address},
		{"Instance", r.Instance},
		{"State", v.icon(a, r) + " " + state},
	}
	if r.Entry == nil {
		relayRows = append(relayRows, [2]string{"Inventory", t.WarnText.Render("not listed in the inventory")})
	}
	if h := v.model.Host(r.Address); h != nil {
		probed := "not yet"
		if !h.At.IsZero() {
			probed = ago(v.now().Sub(h.At)) + " ago"
		}
		ver := h.Version
		if ver == "" {
			ver = "unknown"
		}
		relayRows = append(relayRows, [2]string{"Probed", probed + t.Subtle.Render(" · tor-relay-setup "+ver)})
		hostDetail = h.Detail
	}
	cols := 1
	if w >= 100 {
		cols = 2
	}
	cw := (w - (cols - 1)) / cols
	cwRight := w - (cols-1)*(cw+1)

	var healthRows [][2]string
	famBody := t.Subtle.Render("no report")
	if p := r.Probe; p != nil {
		rep := p.Report
		fp := rep.Relay.Fingerprint
		if fp == "" {
			fp = t.Subtle.Render("not generated yet")
		} else if cw < 64 {
			fp = fp[:8] + "…" + fp[len(fp)-8:]
		}
		relayRows = append(relayRows, [2]string{"Fingerprint", fp})
		reach := t.Subtle.Render("no self-test in the last 24 h")
		switch {
		case rep.Reachability.IPv4 && rep.Reachability.IPv6:
			reach = statusIcon(t, true, false) + " reachable (IPv4 + IPv6)"
		case rep.Reachability.IPv4:
			reach = statusIcon(t, true, false) + " reachable"
		case rep.Reachability.Failed:
			reach = statusIcon(t, false, false) + " not reachable from outside"
		}
		version := rep.Tor.Version
		if version == "" {
			version = "not installed"
		}
		healthRows = [][2]string{
			{"Service", statusIcon(t, rep.Service.Active, false) + " " + rep.Service.Unit},
			{"tor", statusIcon(t, rep.Tor.Supported, rep.Tor.Installed) + " " + version},
			{"Listener", statusIcon(t, rep.Listener.IPv4 || rep.Listener.IPv6, false) + " TCP " + itoa(rep.Relay.ORPort)},
			{"Reachability", reach},
		}
		switch {
		case r.HasRate:
			healthRows = append(healthRows, [2]string{"Live", t.InfoText.Render("↓ "+humanRate(r.Rate.Read)) + "  " + t.Directive.Render("↑ "+humanRate(r.Rate.Written))})
		case rep.Relay.MetricsPort == "":
			healthRows = append(healthRows, [2]string{"Live", t.Subtle.Render("no MetricsPort")})
		case p.Traffic == nil:
			healthRows = append(healthRows, [2]string{"Live", t.Subtle.Render("MetricsPort not answering")})
		default:
			healthRows = append(healthRows, [2]string{"Live", t.Subtle.Render("measuring…")})
		}
		if p.Traffic != nil {
			healthRows = append(healthRows, [2]string{"Connections", fmt.Sprintf("%d OR", p.Traffic.Connections)})
		}
		famBody = t.Subtle.Render("single relay (no FamilyId)")
		if len(rep.Family.IDs) > 0 {
			var rows [][2]string
			for _, id := range rep.Family.IDs {
				rows = append(rows, [2]string{statusIcon(t, !slices.Contains(rep.Family.MissingKeys, id), false), truncate(id, cw-8)})
			}
			famBody = kv(t, rows)
		}
		if rep.Family.LegacyCount > 0 {
			famBody += "\n" + t.Subtle.Render(fmt.Sprintf("legacy MyFamily: %d fingerprints", rep.Family.LegacyCount))
		}
	}

	dirBody := t.Subtle.Render("not looked up yet")
	switch d := v.model.DirectoryOf(r); {
	case d != nil:
		rows := [][2]string{
			{"Status", statusIcon(t, d.Running, false) + " " + map[bool]string{true: "running", false: "not running"}[d.Running]},
			{"Flags", truncate(strings.Join(d.Flags, " "), cwRight-16)},
			{"Weight", fmt.Sprintf("%d", d.ConsensusWeight) + t.Subtle.Render(" · "+fleet.Percent(d.ConsensusWeightFraction))},
			{"Selection", fmt.Sprintf("guard %s · middle %s · exit %s", fleet.Percent(d.GuardProbability), fleet.Percent(d.MiddleProbability), fleet.Percent(d.ExitProbability))},
			{"Advertised", humanBandwidth(d.AdvertisedBandwidth)},
		}
		if d.FirstSeen != "" {
			rows = append(rows, [2]string{"First seen", d.FirstSeen})
		}
		if lost := v.model.LostFlags(r); len(lost) > 0 {
			rows = append(rows, [2]string{"Lost", t.WarnText.Render(strings.Join(lost, ", ") + " since the last run")})
		}
		if bw := v.model.History[r.Fingerprint()]; bw != nil {
			daily, _, in, out := fleet.SumHistory([]*onionoo.Bandwidth{bw})
			if len(daily) > 0 {
				rows = append(rows,
					[2]string{fmt.Sprintf("%d days", len(daily)), t.Directive.Render(sparkline(daily, clamp(cwRight-20, 8, 60)))},
					[2]string{"", t.Subtle.Render("in " + humanBytes(in) + " · out " + humanBytes(out))})
			}
		}
		dirBody = kv(t, rows)
	case v.model.DirErr != nil:
		dirBody = statusIcon(t, false, true) + " " + t.Subtle.Render(truncate(v.model.DirErr.Error(), cwRight-6))
	case !v.model.DirAt.IsZero() && r.Fingerprint() != "":
		dirBody = t.Subtle.Render("Not published yet — new relays appear after about 3 hours.")
	}

	var warnBody string
	for i, warn := range r.Warnings() {
		if i > 0 {
			warnBody += "\n"
		}
		warnBody += t.WarnText.Render(truncate(iconWarn+" "+warn, w-4))
	}

	relayCard := panel(t, "Relay", kv(t, relayRows), cw, true)
	healthCard := panel(t, "Health", kv(t, healthRows), cwRight, false)
	if healthRows == nil {
		body := t.Subtle.Render("no report from this relay")
		if hostDetail != "" {
			body += "\n" + t.WarnText.Render(hostDetail)
		}
		healthCard = panel(t, "Health", body, cwRight, false)
	}
	famCard := panel(t, "Family", famBody, cw, false)
	dirCard := panel(t, "Tor Metrics", dirBody, cwRight, false)
	var out []string
	if cols == 2 {
		out = []string{sideBySide(relayCard, healthCard), sideBySide(famCard, dirCard)}
	} else {
		out = []string{relayCard, healthCard, famCard, dirCard}
	}
	if warnBody != "" {
		out = append(out, panel(t, "Warnings", warnBody, w, false))
	}
	return strings.Join(out, "\n")
}

func (v *fleetView) keys(a *App) []string {
	switch {
	case v.filtering:
		return []string{"type", "filter", "enter", "keep", "esc", "clear"}
	case v.detail:
		return []string{"↑/↓", "next relay", "esc", "back"}
	}
	refresh := "refresh"
	if !v.updated.IsZero() {
		refresh = "refresh · " + ago(v.now().Sub(v.updated)) + " ago"
	}
	k := []string{"↑/↓", "select", "enter", "details", "s/S", "sort", "/", "filter", "r", refresh}
	if a.width >= 110 {
		k = append(k, "R/O/U", "restart/reload/update", "q", "quit")
	} else {
		k = append(k, "R/O/U", "roll", "q", "quit")
	}
	return k
}
