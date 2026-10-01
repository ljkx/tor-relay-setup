package tui

import (
	"fmt"
	"math"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// Icons used across screens. They are plain Unicode so they survive any
// terminal font; spinners are handled by the bubbles spinner.
const (
	iconDone    = "✓"
	iconFail    = "✗"
	iconWarn    = "!"
	iconPending = "○"
	iconCurrent = "●"
	iconInfo    = "·"
)

// header renders the top bar: brand, version, context on the right.
func header(t Theme, width int, version, right string) string {
	left := t.Brand.Render("◆ tor-relay-setup") + " " + t.BrandTag.Render(version)
	gap := width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		return " " + left
	}
	return " " + left + strings.Repeat(" ", gap) + t.Subtle.Render(right) + " "
}

// rule renders a thin horizontal separator.
func rule(t Theme, width int) string {
	if width < 1 {
		return ""
	}
	return t.Faintly.Render(strings.Repeat("─", width))
}

// stepper renders "● Mode ─ ● Identity ─ ◉ Network ─ ○ Family …" and
// collapses to "Step 3/7 · Network" when there is not enough room.
func stepper(t Theme, width int, steps []string, current int) string {
	var parts []string
	for i, s := range steps {
		switch {
		case i < current:
			parts = append(parts, t.GoodText.Render(iconDone)+" "+t.Subtle.Render(s))
		case i == current:
			parts = append(parts, t.Brand.Render(iconCurrent+" "+s))
		default:
			parts = append(parts, t.Faintly.Render(iconPending+" "+s))
		}
	}
	line := " " + strings.Join(parts, t.Faintly.Render(" ─ "))
	if lipgloss.Width(line) <= width {
		return line
	}
	return " " + t.Brand.Render(fmt.Sprintf("Step %d/%d", current+1, len(steps))) + t.Subtle.Render(" · "+steps[current])
}

// panel draws a rounded box with a title on its first line.
func panel(t Theme, title, body string, width int, focused bool) string {
	st := t.Panel
	if focused {
		st = t.PanelFocused
	}
	inner := width - st.GetHorizontalFrameSize()
	if inner < 10 {
		inner = 10
	}
	content := body
	if title != "" {
		content = t.PanelTitle.Render(title) + "\n" + body
	}
	return st.Width(width).Render(lipgloss.NewStyle().Width(inner).Render(content))
}

// keyHelp renders "tab next · shift+tab back · q quit".
func keyHelp(t Theme, pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, t.Key.Render(pairs[i])+" "+t.KeyDesc.Render(pairs[i+1]))
	}
	return " " + strings.Join(parts, t.Faintly.Render("  ·  "))
}

// highlightTorrc colours directives, values, and comments.
func highlightTorrc(t Theme, torrc string, maxWidth int) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(torrc, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			b.WriteString("\n")
			continue
		case strings.HasPrefix(trimmed, "#"):
			b.WriteString(t.Comment.Render(truncate(line, maxWidth)))
		default:
			key, val, _ := strings.Cut(trimmed, " ")
			b.WriteString(t.Directive.Render(key))
			if val != "" {
				b.WriteString(" " + t.Value.Render(truncate(val, maxWidth-len(key)-1)))
			}
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// kv renders aligned "label  value" rows.
func kv(t Theme, rows [][2]string) string {
	w := 0
	for _, r := range rows {
		if l := lipgloss.Width(r[0]); l > w {
			w = l
		}
	}
	var b strings.Builder
	for i, r := range rows {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(t.Subtle.Render(r[0] + strings.Repeat(" ", w-lipgloss.Width(r[0]))))
		b.WriteString("  ")
		b.WriteString(r[1])
	}
	return b.String()
}

// statusIcon renders a coloured icon for a check result.
func statusIcon(t Theme, ok bool, warn bool) string {
	switch {
	case ok:
		return t.GoodText.Render(iconDone)
	case warn:
		return t.WarnText.Render(iconWarn)
	default:
		return t.BadText.Render(iconFail)
	}
}

// sparkBlocks are the eight bar heights of a sparkline.
var sparkBlocks = []rune("▁▂▃▄▅▆▇█")

// sparkline draws values as a one-line bar chart at most width cells wide,
// averaging neighbours when there are more values than cells. NaN values
// (gaps in the data) draw as spaces; the scale starts at zero.
func sparkline(values []float64, width int) string {
	if width < 1 || len(values) == 0 {
		return ""
	}
	cells := values
	if len(values) > width {
		cells = make([]float64, width)
		for i := range cells {
			lo, hi := i*len(values)/width, (i+1)*len(values)/width
			sum, n := 0.0, 0
			for _, v := range values[lo:hi] {
				if !math.IsNaN(v) {
					sum += v
					n++
				}
			}
			cells[i] = math.NaN()
			if n > 0 {
				cells[i] = sum / float64(n)
			}
		}
	}
	peak := 0.0
	for _, v := range cells {
		if v > peak {
			peak = v
		}
	}
	var b strings.Builder
	for _, v := range cells {
		switch {
		case math.IsNaN(v):
			b.WriteRune(' ')
		case peak <= 0:
			b.WriteRune(sparkBlocks[0])
		default:
			i := int(math.Round(v / peak * float64(len(sparkBlocks)-1)))
			b.WriteRune(sparkBlocks[clamp(i, 0, len(sparkBlocks)-1)])
		}
	}
	return b.String()
}

// humanRate formats bytes per second as bits per second.
func humanRate(bytesPerSecond float64) string {
	bits := bytesPerSecond * 8
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.1f Mbit/s", bits/1e6)
	case bits >= 1e3:
		return fmt.Sprintf("%.0f kbit/s", bits/1e3)
	default:
		return fmt.Sprintf("%.0f bit/s", bits)
	}
}

// humanBytes formats a byte count with decimal units, as providers bill.
func humanBytes(n float64) string {
	for _, u := range []struct {
		div  float64
		unit string
	}{{1e12, "TB"}, {1e9, "GB"}, {1e6, "MB"}, {1e3, "kB"}} {
		if n >= u.div {
			return fmt.Sprintf("%.1f %s", n/u.div, u.unit)
		}
	}
	return fmt.Sprintf("%.0f B", n)
}

func truncate(s string, max int) string {
	if max < 4 || lipgloss.Width(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) > max-1 {
		r = r[:max-1]
	}
	return string(r) + "…"
}

func formatDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
