package relay

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// WebExitPolicy allows HTTP and HTTPS only: the narrowest useful exit.
var WebExitPolicy = []string{"accept *:80", "accept *:443", "reject *:*"}

// PolicyRule is one ExitPolicy entry: "accept[6]|reject[6] ADDR[/MASK][:PORT]"
// as tor(1) describes it. Addr is "*", "*4", "*6", "private", an IPv4
// address or an IPv6 address in brackets.
type PolicyRule struct {
	Accept bool
	// Only6 marks accept6/reject6, which only produce IPv6 entries.
	Only6  bool
	Addr   string
	Bits   int // prefix length; -1 when no /MASK was given
	PortLo int // 1-65535; PortLo 1 and PortHi 65535 mean "*"
	PortHi int
}

// ParsePolicyRule parses one exit policy entry. It accepts what tor accepts
// for a single entry except dotted netmasks, and refuses entries tor would
// only warn about and ignore (an IPv4 address with accept6/reject6).
func ParsePolicyRule(s string) (PolicyRule, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return PolicyRule{}, fmt.Errorf("%q: want \"accept ADDR:PORT\" or \"reject ADDR:PORT\"", s)
	}
	var r PolicyRule
	switch strings.ToLower(f[0]) {
	case "accept":
		r.Accept = true
	case "accept6":
		r.Accept, r.Only6 = true, true
	case "reject":
	case "reject6":
		r.Only6 = true
	default:
		return PolicyRule{}, fmt.Errorf("%q: start with accept, reject, accept6 or reject6", s)
	}
	target := f[1]
	addr, port := target, "*"
	if strings.HasPrefix(target, "[") {
		end := strings.Index(target, "]")
		if end < 0 {
			return PolicyRule{}, fmt.Errorf("%q: unclosed [ in the IPv6 address", s)
		}
		addr, port = target[:end+1], "*"
		rest := target[end+1:]
		if mask, after, ok := strings.Cut(rest, ":"); ok {
			addr += mask
			port = after
		} else {
			addr += rest
		}
	} else if strings.Count(target, ":") > 1 {
		return PolicyRule{}, fmt.Errorf("%q: write IPv6 addresses in brackets, e.g. [2001:db8::1]:443", s)
	} else if a, p, ok := strings.Cut(target, ":"); ok {
		addr, port = a, p
	}
	if err := r.setAddr(addr); err != nil {
		return PolicyRule{}, fmt.Errorf("%q: %w", s, err)
	}
	if err := r.setPorts(port); err != nil {
		return PolicyRule{}, fmt.Errorf("%q: %w", s, err)
	}
	if r.Only6 && r.isIPv4() {
		return PolicyRule{}, fmt.Errorf("%q: accept6/reject6 need an IPv6 address or *6 (tor ignores IPv4 here)", s)
	}
	return r, nil
}

func (r *PolicyRule) setAddr(addr string) error {
	r.Bits = -1
	host, mask, hasMask := strings.Cut(addr, "/")
	switch strings.ToLower(host) {
	case "*", "*4", "*6", "private":
		if hasMask {
			return errors.New("a wildcard or \"private\" takes no /MASK")
		}
		r.Addr = strings.ToLower(host)
		return nil
	}
	v6 := strings.HasPrefix(host, "[")
	if v6 {
		if !strings.HasSuffix(host, "]") {
			return errors.New("write IPv6 addresses in brackets, e.g. [2001:db8::]/32")
		}
		host = host[1 : len(host)-1]
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return fmt.Errorf("%q is not an address, *, *4, *6 or private", host)
	}
	if a.Is6() && !a.Is4In6() && !v6 {
		return errors.New("write IPv6 addresses in brackets, e.g. [2001:db8::1]")
	}
	if v6 && !a.Is6() {
		return errors.New("only IPv6 addresses go in brackets")
	}
	r.Addr = a.String()
	if v6 {
		r.Addr = "[" + a.String() + "]"
	}
	if hasMask {
		n, err := strconv.Atoi(mask)
		limit := 32
		if v6 {
			limit = 128
		}
		if err != nil || n < 0 || n > limit {
			return fmt.Errorf("/%s: use a prefix length from 0 to %d", mask, limit)
		}
		r.Bits = n
	}
	return nil
}

func (r *PolicyRule) setPorts(p string) error {
	if p == "*" || p == "" {
		r.PortLo, r.PortHi = 1, 65535
		return nil
	}
	lo, hi, isRange := strings.Cut(p, "-")
	a, err1 := strconv.Atoi(lo)
	b := a
	var err2 error
	if isRange {
		b, err2 = strconv.Atoi(hi)
	}
	switch {
	case err1 != nil || err2 != nil:
		return fmt.Errorf("port %q: use a number, a range such as 6660-6669, or *", p)
	case !ValidPort(a) || !ValidPort(b):
		return fmt.Errorf("port %q: ports are 1-65535", p)
	case a > b:
		return fmt.Errorf("port range %q runs backwards", p)
	}
	r.PortLo, r.PortHi = a, b
	return nil
}

func (r PolicyRule) isIPv4() bool {
	if r.Addr == "*4" {
		return true
	}
	a, err := netip.ParseAddr(r.Addr)
	return err == nil && a.Is4()
}

// CatchAll reports whether the rule matches every address and port of its
// family: "accept *:*", "reject *:*" (and the *4/*6 forms).
func (r PolicyRule) CatchAll() bool {
	return (r.Addr == "*" || r.Addr == "*4" || r.Addr == "*6") && r.Bits < 0 && r.PortLo == 1 && r.PortHi == 65535
}

// String renders the rule the way tor(1) writes it.
func (r PolicyRule) String() string {
	verb := "reject"
	if r.Accept {
		verb = "accept"
	}
	if r.Only6 {
		verb += "6"
	}
	addr := r.Addr
	if r.Bits >= 0 {
		addr += "/" + strconv.Itoa(r.Bits)
	}
	port := "*"
	switch {
	case r.PortLo == 1 && r.PortHi == 65535:
	case r.PortLo == r.PortHi:
		port = strconv.Itoa(r.PortLo)
	default:
		port = strconv.Itoa(r.PortLo) + "-" + strconv.Itoa(r.PortHi)
	}
	return verb + " " + addr + ":" + port
}

// SplitPolicy turns editor text into policy entries: one per line, commas
// also separate entries (as on an ExitPolicy line), and blank lines and
// '#' comments are skipped.
func SplitPolicy(text string) []string {
	var out []string
	for line := range strings.Lines(text) {
		line, _, _ = strings.Cut(line, "#")
		for _, part := range strings.Split(line, ",") {
			if part = strings.Join(strings.Fields(part), " "); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// NormalizePolicy parses and validates entries and returns them in tor's
// canonical form. A custom policy must end with "reject *:*" (or
// "accept *:*"): without a final catch-all tor would prepend the entries
// to its default exit policy instead of replacing it, which is rarely what
// an operator means. Entries after a catch-all of the same family could
// never match and are refused, as is an empty policy.
func NormalizePolicy(entries []string) ([]string, error) {
	if len(entries) == 0 {
		return nil, errors.New("the exit policy is empty; end it with reject *:*")
	}
	var errs []error
	out := make([]string, 0, len(entries))
	closed4, closed6 := false, false
	for i, e := range entries {
		r, err := ParsePolicyRule(e)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
			continue
		}
		v4 := !r.Only6 && r.Addr != "*6" && !strings.HasPrefix(r.Addr, "[")
		v6 := r.Addr != "*4" && !r.isIPv4()
		if (closed4 || !v4) && (closed6 || !v6) {
			errs = append(errs, fmt.Errorf("line %d: %q comes after a catch-all rule and never matches", i+1, e))
			continue
		}
		if r.CatchAll() {
			closed4 = closed4 || v4
			closed6 = closed6 || v6
		}
		out = append(out, r.String())
	}
	if len(errs) == 0 && (!closed4 || !closed6) {
		errs = append(errs, errors.New("end the policy with reject *:* (or accept *:*) so it replaces tor's default policy"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}
