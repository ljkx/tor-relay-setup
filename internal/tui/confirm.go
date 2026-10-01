package tui

import (
	tea "charm.land/bubbletea/v2"
)

// confirmView asks a yes/no question before a disruptive action.
type confirmView struct {
	back     screen
	question string
	yes      func() (screen, tea.Cmd)
}

func newConfirmView(back screen, question string, yes func() (screen, tea.Cmd)) *confirmView {
	return &confirmView{back: back, question: question, yes: yes}
}

func (c *confirmView) update(a *App, msg tea.Msg) (screen, tea.Cmd) {
	if k, ok := msg.(tea.KeyPressMsg); ok {
		switch k.String() {
		case "y":
			return c.yes()
		case "n", "esc", "q", "enter":
			return c.back, nil
		}
	}
	return c, nil
}

func (c *confirmView) view(a *App) string {
	t := a.theme
	body := t.Bold.Render(c.question) + "\n\n" +
		t.Key.Render("y") + t.KeyDesc.Render(" yes    ") + t.Key.Render("n") + t.KeyDesc.Render(" no (default)")
	return "\n" + panel(t, "Confirm", body, clamp(a.contentWidth(), 40, 90), true)
}

func (c *confirmView) keys(a *App) []string {
	return []string{"y", "yes", "n / esc", "no"}
}
