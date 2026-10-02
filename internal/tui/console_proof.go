package tui

import (
	"context"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/ljkx/tor-relay-setup/internal/proof"
	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// proofView shows the CIISS proof files to publish on the operator's
// website for every relay on this server, and checks the published copies.
type proofView struct {
	back     *console
	sites    []proof.Site
	checking bool
	results  map[string]proof.Result // by URL
}

type proofCheckMsg []proof.Result

func newProofView(a *App, back *console) *proofView {
	configs, _ := relay.DiscoverConfigs(a.opt.Host)
	return &proofView{back: back, sites: proof.Sites(proof.Local(a.opt.Host, configs))}
}

func (p *proofView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	switch msg := msg.(type) {
	case proofCheckMsg:
		p.checking = false
		p.results = map[string]proof.Result{}
		for _, r := range msg {
			p.results[r.URL] = r
		}
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc", "q", "backspace":
			return p.back, p.back.refresh(a)
		case "c":
			if p.checking {
				return p, nil
			}
			p.checking = true
			sites := p.sites
			return p, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				client := proof.Client(nil)
				var out []proof.Result
				for _, s := range sites {
					out = append(out, proof.CheckSite(ctx, client, s)...)
				}
				return proofCheckMsg(out)
			}
		}
	}
	return p, nil
}

func (p *proofView) view(a *App) string {
	t := a.theme
	w := a.contentWidth()
	var parts []string
	if len(p.sites) == 0 {
		parts = append(parts, t.Subtle.Render("No relay on this server can be proven (bridges are never listed)."))
	}
	for _, s := range p.sites {
		title := "Relays " + strings.Join(s.Relays, ", ")
		if s.Domain != "" {
			title += " · " + s.Domain
		}
		var b strings.Builder
		for _, line := range proof.Advice(s) {
			b.WriteString(t.WarnText.Render(iconWarn+" "+line) + "\n")
		}
		for i, f := range s.Files {
			if i > 0 || b.Len() > 0 {
				b.WriteString("\n")
			}
			label := "CIISS v3, proof:uri-familyid-ed25519"
			if f.Kind == proof.Fingerprints {
				label = "legacy CIISS v2, proof:uri-rsa"
			}
			where := f.URL
			if where == "" {
				where = "https://YOUR-DOMAIN" + f.Kind.Path()
			}
			b.WriteString(t.Bold.Render(f.Kind.FileName()) + t.Subtle.Render("  ("+label+")") + "\n")
			b.WriteString(t.Subtle.Render("Publish at ") + where + "\n")
			if r, ok := p.results[f.URL]; ok {
				b.WriteString(checkLine(t, r) + "\n")
			}
			b.WriteString(indentLines(strings.TrimRight(string(f.Content), "\n"), "  ") + "\n")
		}
		parts = append(parts, panel(t, title, strings.TrimRight(b.String(), "\n"), w, false))
	}
	head := t.Title.Render(" ContactInfo proof") + t.Subtle.Render(" · files for your website (HTTPS, text/plain, no redirect to another domain)")
	if p.checking {
		head += "  " + a.spin.View() + t.Subtle.Render(" checking…")
	}
	return head + "\n\n" + strings.Join(parts, "\n")
}

// checkLine renders the result of fetching one published proof file.
func checkLine(t Theme, r proof.Result) string {
	switch {
	case r.Error != "":
		return statusIcon(t, false, false) + " " + r.Error
	case r.OK:
		line := statusIcon(t, true, false) + " published and lists every entry"
		for _, n := range r.Notes {
			line += "\n" + t.WarnText.Render(iconWarn+" "+n)
		}
		return line
	default:
		return statusIcon(t, false, true) + " published, but missing " + strings.Join(r.Missing, ", ")
	}
}

func (p *proofView) keys(a *App) []string {
	return []string{"c", "check the published files", "esc", "back"}
}
