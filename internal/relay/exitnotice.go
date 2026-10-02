package relay

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"
)

// exitNoticeTemplate is the exit notice page; docs/examples/tor-exit-notice.html
// is the same file for operators who serve it themselves.
//
//go:embed exitnotice.html
var exitNoticeTemplate string

var exitNotice = template.Must(template.New("exit-notice").Parse(exitNoticeTemplate))

// ExitNoticeTemplate returns the unrendered exit notice page.
func ExitNoticeTemplate() string { return exitNoticeTemplate }

// RenderExitNotice fills the exit notice page in for a relay. The email
// comes from a CIISS "email:" field (with "[]" turned back into "@") or a
// plain address ContactInfo; html/template escapes everything.
func RenderExitNotice(nickname, contact string) []byte {
	var b bytes.Buffer
	_ = exitNotice.Execute(&b, struct{ Nickname, Contact, Email string }{nickname, contact, ContactEmail(contact)})
	return b.Bytes()
}

// ContactEmail extracts an email address from ContactInfo: the CIISS
// "email:" field, or the first word that looks like an address.
func ContactEmail(contact string) string {
	for _, f := range strings.Fields(contact) {
		if v, ok := strings.CutPrefix(f, "email:"); ok {
			f = strings.ReplaceAll(v, "[]", "@")
		}
		f = strings.Trim(f, "<>()[],;\"'")
		if ValidEmail(f) {
			return f
		}
	}
	return ""
}
