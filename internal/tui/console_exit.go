package tui

import (
	"context"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/relay"
	"github.com/ljkx/tor-relay-setup/internal/system"
)

// exitPolicyView edits an exit relay's policy in the live torrc: tor's
// ReducedExitPolicy, web only, tor's default, or custom rules, plus IPv6
// exiting and the exit notice. Like the other edits it is verified with
// tor --verify-config before anything is written.
type exitPolicyView struct {
	back *console
	form *huh.Form
	ans  *answers
	doc  *relay.Document
	// was is the notice page before the edit; DirPort changes need a restart.
	wasNotice string
}

func newExitPolicyView(a *App, back *console) (screen, tea.Cmd) {
	inst := back.selected()
	data, err := a.opt.Host.ReadFile(inst.TorrcPath)
	if err != nil {
		return back, toast("Cannot read " + inst.TorrcPath + ": " + err.Error())
	}
	doc := relay.ParseDocument(data)
	policy, custom := doc.ExitPolicySettings()
	ans := &answers{ExitPolicy: string(policy), ExitCustom: strings.Join(custom, "\n"), ExitNotice: doc.ExitNotice() != ""}
	if v, _ := doc.Get("IPv6Exit"); strings.TrimSpace(v) == "1" {
		ans.IPv6Exit = true
	}
	if ans.ExitCustom == "" {
		ans.ExitCustom = strings.Join(relay.WebExitPolicy, "\n")
	}
	e := &exitPolicyView{back: back, ans: ans, doc: doc, wasNotice: doc.ExitNotice()}
	e.form = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("Exit policy").Options(exitPolicyOptions()...).Value(&ans.ExitPolicy),
		),
		huh.NewGroup(
			huh.NewText().Title("Rules").
				Description("One per line, first match wins: accept|reject ADDR:PORT. ADDR is *, *4, *6, private, 10.0.0.0/8 or [2001:db8::]/32; PORT is 443, 6660-6669 or *. End with reject *:*.").
				Value(&ans.ExitCustom).Lines(10).Validate(validExitPolicyText),
			huh.NewNote().Title("torrc").DescriptionFunc(func() string { return exitPolicyPreview(ans) }, ans),
		).WithHideFunc(func() bool { return ans.ExitPolicy != string(relay.PolicyCustom) }),
		huh.NewGroup(
			newConfirm().Title("Allow IPv6 exit traffic (IPv6Exit 1)?").
				Description("Needs an IPv6 ORPort; without it tor rejects all IPv6 exits anyway.").Value(&ans.IPv6Exit),
			newConfirm().Title("Serve the exit notice on port 80?").
				Description("tor serves "+inst.ExitNoticePath()+" with DirPort 80 and DirPortFrontPage. Turning it on or off restarts Tor.").
				Value(&ans.ExitNotice),
		),
	).WithTheme(a.theme.Form()).WithShowHelp(false).WithKeyMap(escKeyMap())
	return e, e.form.Init()
}

func (e *exitPolicyView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	m, cmd := e.form.Update(msg)
	if f, ok := m.(*huh.Form); ok {
		e.form = f
	}
	switch e.form.State {
	case huh.StateAborted:
		return e.back, nil
	case huh.StateCompleted:
		ans := e.ans
		policy := relay.ExitPolicy(ans.ExitPolicy)
		var entries []string
		if policy == relay.PolicyCustom {
			var err error
			if entries, err = relay.NormalizePolicy(relay.SplitPolicy(ans.ExitCustom)); err != nil {
				return e.back, toast("Exit policy: " + err.Error())
			}
		}
		inst := e.back.selected()
		notice := ""
		if ans.ExitNotice {
			notice = inst.ExitNoticePath()
			if e.wasNotice != "" {
				notice = e.wasNotice // keep a page the operator moved elsewhere
			}
		}
		doc := e.doc
		doc.SetExitPolicy(policy, entries, ans.IPv6Exit)
		doc.SetExitNotice(notice)
		data := doc.Bytes()
		// A new or removed DirPort listener needs a restart: tor cannot bind
		// port 80 again after dropping root.
		restart := (notice == "") != (e.wasNotice == "")
		nickname, _ := doc.Get("Nickname")
		contact, _ := doc.Get("ContactInfo")
		var firewall []host.Command
		if fw := a.checks.Facts.Firewall; notice != "" && e.wasNotice == "" && a.checks.FactsReady && fw.Active {
			firewall = system.FirewallCommandsFor(fw, []system.Port{{Number: relay.ExitNoticePort, Label: "Tor exit notice"}}, a.checks.Facts.SSHPorts, false, false)
		}
		return newTask(a, e.back, "Apply exit policy", func(ctx context.Context, h host.Host, out func(string), progress func(float64, string)) (string, error) {
			if notice != "" {
				if _, err := h.Stat(notice); err != nil {
					out("writing " + notice)
					if _, err := h.WriteFile(notice, relay.RenderExitNotice(nickname, relay.Unquote(contact)), host.FileOptions{Mode: 0o644}); err != nil {
						return "", err
					}
				}
			}
			if err := writeTorrc(ctx, h, inst, data, restart, out); err != nil {
				return "", err
			}
			for _, c := range firewall {
				out(c.String())
				if _, err := h.Run(ctx, c); err != nil {
					return "", err
				}
			}
			summary := "Exit policy applied (" + string(policy) + ")."
			if notice != "" {
				summary += "\nThe exit notice is " + notice + "; edit it to describe your organisation. Open TCP 80 in your provider's firewall too."
			}
			return summary, nil
		})
	}
	return e, cmd
}

func (e *exitPolicyView) view(a *App) string {
	return a.theme.Title.Render(" Exit policy") + a.theme.Subtle.Render(instanceTitle(e.back.selected())+" · verified with tor before anything is written") +
		"\n\n" + panel(a.theme, "", e.form.View(), clamp(a.contentWidth(), 40, 110), true)
}

func (e *exitPolicyView) keys(a *App) []string {
	return []string{"enter", "next", "shift+tab", "back", "esc", "cancel"}
}
