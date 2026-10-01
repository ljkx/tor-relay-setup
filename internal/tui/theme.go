// Package tui is the interactive interface: the setup wizard, the review
// and apply screens, and the operator console, built on Bubble Tea v2,
// Huh forms, and Lip Gloss.
package tui

import (
	"image/color"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// Theme holds every style, resolved for a light or dark terminal.
type Theme struct {
	Dark bool

	Accent, AccentSoft, Fg, Muted, Faint, Border color.Color
	Good, Warn, Bad, Info                        color.Color

	Title, Subtle, Faintly, Bold lipgloss.Style
	Brand, BrandTag              lipgloss.Style
	Panel, PanelFocused          lipgloss.Style
	PanelTitle                   lipgloss.Style
	Key, KeyDesc                 lipgloss.Style
	GoodText, WarnText, BadText  lipgloss.Style
	InfoText                     lipgloss.Style
	Directive, Value, Comment    lipgloss.Style
	Selected, Unselected         lipgloss.Style
	Badge                        lipgloss.Style
}

// NewTheme builds the palette. Tor purple is the accent in both modes.
func NewTheme(dark bool) Theme {
	ld := lipgloss.LightDark(dark)
	t := Theme{
		Dark:       dark,
		Accent:     ld(lipgloss.Color("#7D4698"), lipgloss.Color("#B98EDB")),
		AccentSoft: ld(lipgloss.Color("#EFE4F6"), lipgloss.Color("#3B2552")),
		Fg:         ld(lipgloss.Color("#1F1B24"), lipgloss.Color("#ECE8F0")),
		Muted:      ld(lipgloss.Color("#6B6275"), lipgloss.Color("#A59CB0")),
		Faint:      ld(lipgloss.Color("#A39AAD"), lipgloss.Color("#645B6E")),
		Border:     ld(lipgloss.Color("#D6CCE0"), lipgloss.Color("#4A3F57")),
		Good:       ld(lipgloss.Color("#1A7F4E"), lipgloss.Color("#5FD39A")),
		Warn:       ld(lipgloss.Color("#9A6700"), lipgloss.Color("#F2C14E")),
		Bad:        ld(lipgloss.Color("#C0362C"), lipgloss.Color("#FF7A70")),
		Info:       ld(lipgloss.Color("#2B6CB0"), lipgloss.Color("#7FB8F0")),
	}
	s := lipgloss.NewStyle
	t.Title = s().Foreground(t.Fg).Bold(true)
	t.Subtle = s().Foreground(t.Muted)
	t.Faintly = s().Foreground(t.Faint)
	t.Bold = s().Bold(true).Foreground(t.Fg)
	t.Brand = s().Foreground(t.Accent).Bold(true)
	t.BrandTag = s().Foreground(t.Muted)
	t.Panel = s().Border(lipgloss.RoundedBorder()).BorderForeground(t.Border).Padding(0, 1)
	t.PanelFocused = t.Panel.BorderForeground(t.Accent)
	t.PanelTitle = s().Foreground(t.Accent).Bold(true)
	t.Key = s().Foreground(t.Accent).Bold(true)
	t.KeyDesc = s().Foreground(t.Muted)
	t.GoodText = s().Foreground(t.Good)
	t.WarnText = s().Foreground(t.Warn)
	t.BadText = s().Foreground(t.Bad)
	t.InfoText = s().Foreground(t.Info)
	t.Directive = s().Foreground(t.Accent)
	t.Value = s().Foreground(t.Fg)
	t.Comment = s().Foreground(t.Faint).Italic(true)
	t.Selected = s().Foreground(t.Fg).Background(t.AccentSoft).Bold(true)
	t.Unselected = s().Foreground(t.Fg)
	t.Badge = s().Foreground(ld(lipgloss.Color("#FFFFFF"), lipgloss.Color("#1F1B24"))).Background(t.Accent).Padding(0, 1).Bold(true)
	return t
}

// Form returns a Huh theme that matches this palette. It is pinned to the
// light/dark mode the app detected, because forms built after the terminal
// answered the background-colour query never see that answer themselves.
func (t Theme) Form() huh.Theme {
	dark := t.Dark
	return huh.ThemeFunc(func(bool) *huh.Styles {
		th := NewTheme(dark)
		st := huh.ThemeBase(dark)
		s := lipgloss.NewStyle

		st.Focused.Base = st.Focused.Base.BorderForeground(th.Accent)
		st.Focused.Card = st.Focused.Base
		st.Focused.Title = s().Foreground(th.Accent).Bold(true)
		st.Focused.NoteTitle = s().Foreground(th.Accent).Bold(true).MarginBottom(1)
		st.Focused.Description = s().Foreground(th.Muted)
		st.Focused.ErrorIndicator = s().Foreground(th.Bad).SetString(" ✗")
		st.Focused.ErrorMessage = s().Foreground(th.Bad)
		st.Focused.SelectSelector = s().Foreground(th.Accent).SetString("› ")
		st.Focused.NextIndicator = s().Foreground(th.Accent).MarginLeft(1).SetString("→")
		st.Focused.PrevIndicator = s().Foreground(th.Accent).MarginRight(1).SetString("←")
		st.Focused.Option = s().Foreground(th.Fg)
		st.Focused.SelectedOption = s().Foreground(th.Good)
		st.Focused.SelectedPrefix = s().Foreground(th.Good).SetString("✓ ")
		st.Focused.UnselectedPrefix = s().Foreground(th.Faint).SetString("• ")
		st.Focused.UnselectedOption = s().Foreground(th.Fg)
		st.Focused.FocusedButton = s().Foreground(lipgloss.LightDark(dark)(lipgloss.Color("#FFFFFF"), lipgloss.Color("#1F1B24"))).Background(th.Accent).Padding(0, 2).MarginRight(1).Bold(true)
		st.Focused.BlurredButton = s().Foreground(th.Muted).Background(th.AccentSoft).Padding(0, 2).MarginRight(1)
		st.Focused.Next = st.Focused.FocusedButton
		st.Focused.TextInput.Cursor = s().Foreground(th.Accent)
		st.Focused.TextInput.Placeholder = s().Foreground(th.Faint)
		st.Focused.TextInput.Prompt = s().Foreground(th.Accent).SetString("▌ ")
		st.Focused.TextInput.Text = s().Foreground(th.Fg)

		st.Blurred = st.Focused
		st.Blurred.Base = st.Focused.Base.BorderStyle(lipgloss.HiddenBorder())
		st.Blurred.Card = st.Blurred.Base
		st.Blurred.Title = s().Foreground(th.Muted).Bold(true)
		st.Blurred.TextInput.Prompt = s().Foreground(th.Faint).SetString("▌ ")
		st.Blurred.NextIndicator = s()
		st.Blurred.PrevIndicator = s()

		st.Group.Title = s().Foreground(th.Fg).Bold(true).MarginBottom(1)
		st.Group.Description = s().Foreground(th.Muted)
		st.Help.ShortKey = s().Foreground(th.Accent)
		st.Help.ShortDesc = s().Foreground(th.Muted)
		st.Help.ShortSeparator = s().Foreground(th.Faint)
		st.Help.FullKey = st.Help.ShortKey
		st.Help.FullDesc = st.Help.ShortDesc
		return st
	})
}
