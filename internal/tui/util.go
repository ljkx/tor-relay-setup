package tui

import (
	"strconv"
	"strings"
)

func itoa(i int) string { return strconv.Itoa(i) }

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

func joinOr(parts []string, fallback string) string {
	if len(parts) == 0 {
		return fallback
	}
	return strings.Join(parts, ", ")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// compactCommand shortens a command line for display: environment
// assignments and apt's "-o Key=Value" options are dropped (the log file
// keeps the full line).
func compactCommand(line string) string {
	fields := strings.Fields(line)
	out := fields[:0:0]
	skipNext := false
	for i, f := range fields {
		switch {
		case skipNext:
			skipNext = false
		case len(out) == 0 && isEnvAssignment(f):
			// leading KEY=value
		case f == "-o" && i+1 < len(fields):
			skipNext = true
		case f == "-q" || f == "-y":
		default:
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

// program names this tool in generated files, e.g. "tor-relay-setup v3.0.0".
func program(version string) string { return "tor-relay-setup " + version }

func isEnvAssignment(f string) bool {
	key, _, ok := strings.Cut(f, "=")
	return ok && key != "" && key == strings.ToUpper(key)
}
