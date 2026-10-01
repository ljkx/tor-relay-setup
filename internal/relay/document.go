package relay

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Document is an editable torrc. It keeps every line verbatim, so comments,
// blank lines, unknown options and ordering survive edits exactly; only the
// lines an edit touches change. Keys match case-insensitively, as in Tor.
// A comment line is optional whitespace followed by '#'.
type Document struct {
	lines           []string
	trailingNewline bool
}

// ParseDocument splits data into lines. It never fails: anything that is
// not a comment or blank is treated as a "Key value" directive.
func ParseDocument(data []byte) *Document {
	d := &Document{trailingNewline: len(data) == 0 || data[len(data)-1] == '\n'}
	if len(data) > 0 {
		d.lines = strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	}
	return d
}

// Bytes renders the document. An unedited document round-trips byte for
// byte, including a missing final newline.
func (d *Document) Bytes() []byte {
	if len(d.lines) == 0 {
		return []byte{}
	}
	s := strings.Join(d.lines, "\n")
	if d.trailingNewline {
		s += "\n"
	}
	return []byte(s)
}

// Get returns the value of the first active occurrence of key: the rest of
// the line after the key, trimmed. Quoted values stay quoted (see Unquote)
// and trailing comments are not stripped.
func (d *Document) Get(key string) (string, bool) {
	for _, line := range d.lines {
		if k, v, ok := splitDirective(line); ok && strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// GetAll returns the values of every active occurrence of key, in order.
func (d *Document) GetAll(key string) []string {
	var out []string
	for _, line := range d.lines {
		if k, v, ok := splitDirective(line); ok && strings.EqualFold(k, key) {
			out = append(out, v)
		}
	}
	return out
}

// Set replaces every active line of key with one "key value" line per value,
// placed where the first old line was, or appended at the end when key is
// absent. Set with no values removes key.
func (d *Document) Set(key string, values ...string) {
	var repl []string
	for _, v := range values {
		repl = append(repl, strings.TrimSpace(key+" "+v))
	}
	at := -1
	out := make([]string, 0, len(d.lines)+len(repl))
	for _, line := range d.lines {
		if k, _, ok := splitDirective(line); ok && strings.EqualFold(k, key) {
			if at < 0 {
				at = len(out)
			}
			continue
		}
		out = append(out, line)
	}
	if at < 0 {
		out = append(out, repl...)
	} else {
		out = slices.Insert(out, at, repl...)
	}
	d.lines = out
}

// Remove deletes every active line of the given keys. Comments stay.
func (d *Document) Remove(keys ...string) {
	d.lines = slices.DeleteFunc(d.lines, func(line string) bool {
		k, _, ok := splitDirective(line)
		return ok && matchesKey(k, keys)
	})
}

// FamilyIDs returns the FamilyId values in order.
func (d *Document) FamilyIDs() []string {
	var out []string
	for _, v := range d.GetAll("FamilyId") {
		if f := strings.Fields(v); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

// SetFamilyIDs rewrites the managed FamilyId block: the old managed comment
// (and the FamilyId placeholder Render writes) and every FamilyId line are
// removed, then the comment and one line per id are inserted after the
// first ContactInfo line, or appended when there is none. Empty ids leave
// no family block. Repeated calls with the same ids change nothing.
func (d *Document) SetFamilyIDs(ids []string) {
	d.removeManaged([]string{familyComment, familyPendingComment}, "FamilyId")
	ids = uniqueNonEmpty(ids)
	if len(ids) == 0 {
		return
	}
	block := []string{familyComment}
	for _, id := range ids {
		block = append(block, "FamilyId "+id)
	}
	d.insertAfterContactInfo(block)
}

// MyFamily returns the normalized fingerprints (upper-case, no '$') listed
// on all MyFamily lines, which may separate entries by commas or spaces.
// Duplicates and malformed entries are dropped.
func (d *Document) MyFamily() []string {
	var out []string
	for _, v := range d.GetAll("MyFamily") {
		v, _, _ = strings.Cut(v, "#")
		for _, f := range strings.Fields(strings.ReplaceAll(v, ",", " ")) {
			if ValidFingerprint(f) {
				out = append(out, NormalizeFingerprint(f))
			}
		}
	}
	return uniqueNonEmpty(out)
}

// SetMyFamily rewrites the managed legacy MyFamily block after the first
// ContactInfo line as a single "MyFamily $A,$B" line. Fingerprints are
// normalized and de-duplicated; malformed ones are skipped. An empty list
// removes MyFamily entirely.
func (d *Document) SetMyFamily(fps []string) {
	d.removeManaged([]string{myFamilyComment}, "MyFamily")
	var norm []string
	for _, fp := range fps {
		if ValidFingerprint(fp) {
			norm = append(norm, "$"+NormalizeFingerprint(fp))
		}
	}
	norm = uniqueNonEmpty(norm)
	if len(norm) == 0 {
		return
	}
	d.insertAfterContactInfo([]string{myFamilyComment, "MyFamily " + strings.Join(norm, ",")})
}

// SetMetricsPort removes MetricsPort, MetricsPortPolicy and the managed
// comment, then, unless addr is empty, writes the local-only metrics block
// where the old one was, or at the end. MetricsPortPolicy admits only the
// listener's own loopback host.
func (d *Document) SetMetricsPort(addr string) {
	at := d.removeManaged([]string{metricsComment}, "MetricsPort", "MetricsPortPolicy")
	if addr == "" {
		return
	}
	d.replaceBlock(at, append([]string{metricsComment}, metricsLines(addr)...))
}

// SetBandwidth removes RelayBandwidthRate/Burst, every Accounting* setting
// and their managed comments (including the ones Render writes), then
// writes a "# Managed bandwidth and traffic settings." block for whatever b
// configures, where the old settings were or at the end. BandwidthNone
// leaves no limits.
func (d *Document) SetBandwidth(b Bandwidth) {
	at := d.removeManaged([]string{bandwidthComment, rateComment, accountingComment},
		"RelayBandwidthRate", "RelayBandwidthBurst", "AccountingStart", "AccountingRule", "AccountingMax")
	lines := append(b.rateLines(), b.accountingLines()...)
	if len(lines) == 0 {
		return
	}
	d.replaceBlock(at, append([]string{bandwidthComment}, lines...))
}

// ORPorts returns every ORPort value in order.
func (d *Document) ORPorts() []string { return d.GetAll("ORPort") }

// FirstORPort returns the port number of the first ORPort that names one
// ("9001", "0.0.0.0:9001", "[::]:443 NoListen"), or 0 if none does.
func (d *Document) FirstORPort() int {
	for _, v := range d.ORPorts() {
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		p := f[0]
		if i := strings.LastIndex(p, "]:"); i >= 0 {
			p = p[i+2:]
		} else if i := strings.LastIndexByte(p, ':'); i >= 0 {
			p = p[i+1:]
		}
		if n, err := strconv.Atoi(p); err == nil && ValidPort(n) {
			return n
		}
	}
	return 0
}

// DataDirectory returns the configured DataDirectory, or Tor's Debian
// default /var/lib/tor.
func (d *Document) DataDirectory() string {
	v, _ := d.Get("DataDirectory")
	if strings.HasPrefix(v, `"`) {
		v = Unquote(v)
	} else if f := strings.Fields(v); len(f) > 0 {
		v = f[0]
	}
	if v == "" {
		return "/var/lib/tor"
	}
	return v
}

// Quote returns v as a torrc quoted string, escaping '\' and '"'.
func Quote(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return `"` + v + `"`
}

// Unquote reverses Quote. Values that are not a quoted string are returned
// unchanged. Besides \\ and \" it understands Tor's \n, \t and \r escapes.
func Unquote(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}
	inner := v[1 : len(v)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c != '\\' || i+1 == len(inner) {
			b.WriteByte(c)
			continue
		}
		i++
		switch inner[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\', '"', '\'':
			b.WriteByte(inner[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(inner[i])
		}
	}
	return b.String()
}

// splitDirective parses an active line into key and trimmed value. ok is
// false for blank and comment lines.
func splitDirective(line string) (key, value string, ok bool) {
	t := strings.TrimSpace(line)
	if t == "" || t[0] == '#' {
		return "", "", false
	}
	i := strings.IndexFunc(t, unicode.IsSpace)
	if i < 0 {
		return t, "", true
	}
	return t[:i], strings.TrimSpace(t[i:]), true
}

func matchesKey(k string, keys []string) bool {
	return slices.ContainsFunc(keys, func(want string) bool { return strings.EqualFold(k, want) })
}

func isBlank(line string) bool { return strings.TrimSpace(line) == "" }

// isManagedComment reports whether line is one of the given managed
// comments. Matching uses the comment's leading words (up to the first
// punctuation), so older wordings written by the Bash installer match too.
func isManagedComment(line string, comments []string) bool {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "#") {
		return false
	}
	t = strings.TrimSpace(strings.TrimPrefix(t, "#"))
	for _, c := range comments {
		if strings.HasPrefix(t, commentStem(c)) {
			return true
		}
	}
	return false
}

// commentStem is the identifying start of a managed comment: the text after
// '#' up to the first '(', ':' or '.', e.g. "Managed MyFamily".
func commentStem(c string) string {
	c = strings.TrimSpace(strings.TrimPrefix(c, "#"))
	if i := strings.IndexAny(c, "(:."); i > 0 {
		c = c[:i]
	}
	return strings.TrimSpace(c)
}

// removeManaged drops the managed comments and every active line of keys.
// The blank line separating a removed managed comment from what precedes
// it goes too, so replacing a block repeatedly never piles up blank lines.
// It returns the index where the first removed line was, or -1.
func (d *Document) removeManaged(comments []string, keys ...string) int {
	at := -1
	out := make([]string, 0, len(d.lines))
	for _, line := range d.lines {
		if isManagedComment(line, comments) {
			if n := len(out); n > 0 && isBlank(out[n-1]) {
				out = out[:n-1]
			}
			if at < 0 || at > len(out) {
				at = len(out)
			}
			continue
		}
		if k, _, ok := splitDirective(line); ok && matchesKey(k, keys) {
			if at < 0 {
				at = len(out)
			}
			continue
		}
		out = append(out, line)
	}
	d.lines = out
	return at
}

// replaceBlock puts block where the removed block was (at, from
// removeManaged), keeping a blank line on either side, or appends it when
// nothing was removed.
func (d *Document) replaceBlock(at int, block []string) {
	if at < 0 || at >= len(d.lines) {
		d.appendBlock(block)
		return
	}
	if at > 0 && !isBlank(d.lines[at-1]) {
		block = append([]string{""}, block...)
	}
	if !isBlank(d.lines[at]) {
		block = append(block, "")
	}
	d.lines = slices.Insert(d.lines, at, block...)
}

// insertAfterContactInfo inserts a blank line and block after the first
// active ContactInfo line, or appends the block when there is none.
func (d *Document) insertAfterContactInfo(block []string) {
	for i, line := range d.lines {
		if k, _, ok := splitDirective(line); ok && strings.EqualFold(k, "ContactInfo") {
			d.lines = slices.Insert(d.lines, i+1, append([]string{""}, block...)...)
			return
		}
	}
	d.appendBlock(block)
}

// appendBlock appends block at the end, separated from existing content by
// one blank line.
func (d *Document) appendBlock(block []string) {
	if n := len(d.lines); n > 0 && !isBlank(d.lines[n-1]) {
		d.lines = append(d.lines, "")
	}
	d.lines = append(d.lines, block...)
}

// uniqueNonEmpty returns s without empty strings and later duplicates.
func uniqueNonEmpty(s []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range s {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
