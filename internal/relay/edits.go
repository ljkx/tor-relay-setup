package relay

import (
	"slices"
	"strings"
)

// Edits behind the console's exit policy editor and offline key flow. Each
// rewrites one managed block in place, like SetMetricsPort, so repeating an
// edit changes nothing.

// ExitPolicySettings reads the exit policy choice back from a torrc:
// ReducedExitPolicy 1 is PolicyReduced, ExitPolicy lines equal to
// WebExitPolicy are PolicyWeb, any other ExitPolicy lines PolicyCustom (each
// line may hold several comma-separated entries), and none PolicyDefault.
func (d *Document) ExitPolicySettings() (ExitPolicy, []string) {
	if v, _ := d.Get("ReducedExitPolicy"); strings.TrimSpace(v) == "1" {
		return PolicyReduced, nil
	}
	var entries []string
	for _, v := range d.GetAll("ExitPolicy") {
		entries = append(entries, SplitPolicy(v)...)
	}
	if len(entries) == 0 {
		return PolicyDefault, nil
	}
	if norm, err := NormalizePolicy(entries); err == nil && slices.Equal(norm, WebExitPolicy) {
		return PolicyWeb, nil
	}
	return PolicyCustom, entries
}

// ActsAsExit reports whether this torrc makes tor an exit relay. ExitRelay
// 1 always counts and ExitRelay 0 never does. With ExitRelay unset or auto,
// tor exits when ReducedExitPolicy 1 is set or an ExitPolicy accepts
// anything; a policy that only rejects (reject *:*) is not an exit. It errs
// on the side of "exit": an accept entry counts even if tor would reject
// its addresses anyway (private ranges).
func (d *Document) ActsAsExit() bool {
	first := func(key string) string {
		v, _ := d.Get(key)
		if f := strings.Fields(v); len(f) > 0 {
			return strings.ToLower(f[0])
		}
		return ""
	}
	switch first("ExitRelay") {
	case "1":
		return true
	case "0":
		return false
	}
	if first("ReducedExitPolicy") == "1" {
		return true
	}
	for _, v := range d.GetAll("ExitPolicy") {
		for _, e := range SplitPolicy(v) {
			if strings.HasPrefix(strings.ToLower(e), "accept") {
				return true
			}
		}
	}
	return false
}

// SetExitPolicy replaces ReducedExitPolicy, every ExitPolicy line and
// IPv6Exit with the lines for p (entries are used by PolicyCustom). The new
// lines go where the old ones were, else right after ExitRelay, else at the
// end.
func (d *Document) SetExitPolicy(p ExitPolicy, entries []string, ipv6Exit bool) {
	if p == PolicyWeb {
		entries = WebExitPolicy
	} else if p != PolicyCustom {
		entries = nil
	}
	lines := policyLines(p, entries, ipv6Exit)
	at := d.removeManaged(nil, "ReducedExitPolicy", "ExitPolicy", "IPv6Exit")
	if at < 0 {
		at = d.indexAfter("ExitRelay")
	}
	if at < 0 || at > len(d.lines) {
		if len(lines) > 0 {
			d.appendBlock(lines)
		}
		return
	}
	d.lines = slices.Insert(d.lines, at, lines...)
}

// ExitNotice returns the DirPortFrontPage file, if one is configured.
func (d *Document) ExitNotice() string {
	v, _ := d.Get("DirPortFrontPage")
	if strings.HasPrefix(v, `"`) {
		return Unquote(v)
	}
	return strings.TrimSpace(v)
}

// SetExitNotice rewrites the managed exit notice block (DirPort 80 and
// DirPortFrontPage page); an empty page removes it, DirPort included.
func (d *Document) SetExitNotice(page string) {
	at := d.removeManaged([]string{exitNoticeComment}, "DirPort", "DirPortFrontPage")
	if page == "" {
		return
	}
	d.replaceBlock(at, append([]string{exitNoticeComment}, exitNoticeLines(page)...))
}

// DirPortNumbers returns the port numbers of every DirPort line.
func (d *Document) DirPortNumbers() []int {
	var out []int
	for _, v := range d.GetAll("DirPort") {
		if n := PortNumber(v); n > 0 && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// OfflineMasterKey reports whether torrc sets OfflineMasterKey 1.
func (d *Document) OfflineMasterKey() bool {
	v, _ := d.Get("OfflineMasterKey")
	return strings.TrimSpace(v) == "1"
}

// SetOfflineMasterKey writes the managed "OfflineMasterKey 1" block after
// ContactInfo (and the family block), or removes it.
func (d *Document) SetOfflineMasterKey(on bool) {
	d.removeManaged([]string{offlineKeyComment}, "OfflineMasterKey")
	if !on {
		return
	}
	block := []string{offlineKeyComment, "OfflineMasterKey 1"}
	if i := d.indexAfter("FamilyId"); i >= 0 {
		d.lines = slices.Insert(d.lines, i, append([]string{""}, block...)...)
		return
	}
	d.insertAfterContactInfo(block)
}

// indexAfter returns the index just past the last active line of key, or -1.
func (d *Document) indexAfter(key string) int {
	at := -1
	for i, line := range d.lines {
		if k, _, ok := splitDirective(line); ok && strings.EqualFold(k, key) {
			at = i + 1
		}
	}
	return at
}
