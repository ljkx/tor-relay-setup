// Package relay models a Tor relay configuration: validating operator input,
// rendering a fresh torrc, editing an existing torrc in place without losing
// comments, sizing bandwidth limits from a monthly traffic quota, building
// CIISS v3 ContactInfo strings, reading Tor's ORPort self-test notices, and
// asking tor itself to verify a candidate torrc.
//
// Everything except Verify is pure: it neither reads nor writes the machine.
package relay

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Mode selects the relay role.
type Mode string

// Relay roles.
const (
	ModeGuard Mode = "guard" // guard / middle relay, never exits traffic
	ModeExit  Mode = "exit"  // exit relay
)

// ExitPolicy selects the exit policy written for exit relays.
type ExitPolicy string

// Exit policies.
const (
	PolicyReduced ExitPolicy = "reduced" // ReducedExitPolicy 1
	PolicyDefault ExitPolicy = "default" // Tor's built-in default exit policy
)

// BandwidthMode selects how relay bandwidth is limited.
type BandwidthMode string

// Bandwidth modes.
const (
	// BandwidthSteady paces the relay (KBytes rate/burst) so a monthly quota
	// lasts the whole month, with AccountingMax as a safety cap.
	BandwidthSteady BandwidthMode = "steady"
	// BandwidthManual writes an operator-chosen rate and burst in MBits.
	BandwidthManual BandwidthMode = "manual"
	// BandwidthAccounting writes only a hard monthly AccountingMax cap.
	BandwidthAccounting BandwidthMode = "accounting"
	// BandwidthNone writes no relay-specific limits.
	BandwidthNone BandwidthMode = "none"
)

// BillingRule describes how a provider counts monthly traffic. The values
// double as Tor AccountingRule values.
type BillingRule string

// Billing rules.
const (
	RuleSum BillingRule = "sum" // inbound + outbound combined
	RuleOut BillingRule = "out" // outbound only
	RuleMax BillingRule = "max" // max(in, out); Tor's default AccountingRule
)

// Bandwidth holds the relay bandwidth and accounting settings.
type Bandwidth struct {
	Mode BandwidthMode

	RateKBytes  int // RelayBandwidthRate in KBytes (steady mode); 0 = unset
	BurstKBytes int // RelayBandwidthBurst in KBytes (steady mode)

	RateMbit  int // RelayBandwidthRate in MBits (manual mode)
	BurstMbit int // RelayBandwidthBurst in MBits (manual mode)

	AccountingMaxGBytes int         // 0 = no accounting
	AccountingRule      BillingRule // written only when set and != RuleMax
}

// Validate checks the settings used by the selected Mode.
func (b Bandwidth) Validate() error {
	var errs []error
	switch b.Mode {
	case "", BandwidthNone:
		return nil
	case BandwidthSteady:
		if b.RateKBytes < 1 {
			errs = append(errs, fmt.Errorf("invalid bandwidth RateKBytes %d: must be at least 1", b.RateKBytes))
		} else if b.BurstKBytes < b.RateKBytes {
			errs = append(errs, fmt.Errorf("invalid bandwidth BurstKBytes %d: must be at least RateKBytes %d", b.BurstKBytes, b.RateKBytes))
		}
	case BandwidthManual:
		if b.RateMbit < 1 {
			errs = append(errs, fmt.Errorf("invalid bandwidth RateMbit %d: must be at least 1", b.RateMbit))
		} else if b.BurstMbit < b.RateMbit {
			errs = append(errs, fmt.Errorf("invalid bandwidth BurstMbit %d: must be at least RateMbit %d", b.BurstMbit, b.RateMbit))
		}
	case BandwidthAccounting:
		if b.AccountingMaxGBytes < 1 {
			errs = append(errs, fmt.Errorf("invalid bandwidth AccountingMaxGBytes %d: accounting mode needs at least 1", b.AccountingMaxGBytes))
		}
	default:
		return fmt.Errorf("invalid bandwidth Mode %q: want steady, manual, accounting or none", b.Mode)
	}
	if b.AccountingMaxGBytes < 0 {
		errs = append(errs, fmt.Errorf("invalid bandwidth AccountingMaxGBytes %d: must not be negative", b.AccountingMaxGBytes))
	}
	switch b.AccountingRule {
	case "", RuleSum, RuleOut, RuleMax:
	default:
		errs = append(errs, fmt.Errorf("invalid bandwidth AccountingRule %q: want sum, out or max", b.AccountingRule))
	}
	return errors.Join(errs...)
}

// rateLines returns the RelayBandwidthRate/Burst directives, if any.
func (b Bandwidth) rateLines() []string {
	switch b.Mode {
	case BandwidthSteady:
		if b.RateKBytes > 0 {
			return []string{
				fmt.Sprintf("RelayBandwidthRate %d KBytes", b.RateKBytes),
				fmt.Sprintf("RelayBandwidthBurst %d KBytes", max(b.BurstKBytes, b.RateKBytes)),
			}
		}
	case BandwidthManual:
		if b.RateMbit > 0 {
			return []string{
				fmt.Sprintf("RelayBandwidthRate %d MBits", b.RateMbit),
				fmt.Sprintf("RelayBandwidthBurst %d MBits", max(b.BurstMbit, b.RateMbit)),
			}
		}
	}
	return nil
}

// accountingLines returns the Accounting* directives, if any.
func (b Bandwidth) accountingLines() []string {
	switch b.Mode {
	case BandwidthSteady, BandwidthManual, BandwidthAccounting:
	default:
		return nil
	}
	if b.AccountingMaxGBytes <= 0 {
		return nil
	}
	lines := []string{"AccountingStart month 1 00:00"}
	if b.AccountingRule != "" && b.AccountingRule != RuleMax {
		lines = append(lines, "AccountingRule "+string(b.AccountingRule))
	}
	return append(lines, fmt.Sprintf("AccountingMax %d GBytes", b.AccountingMaxGBytes))
}

// Config is everything needed to render a fresh relay torrc.
type Config struct {
	Nickname    string
	ContactInfo string
	ORPort      int
	IPv6Address string // "" = no IPv6 ORPort
	Mode        Mode
	ExitPolicy  ExitPolicy // exit mode only
	IPv6Exit    bool       // exit mode only
	FamilyIDs   []string
	// FamilyPending renders a placeholder comment when FamilyIDs is empty,
	// for a family key that is generated with tor --keygen-family later.
	FamilyPending bool
	Sandbox       bool
	MetricsPort   string // "" = disabled, else e.g. "127.0.0.1:9035"
	Bandwidth     Bandwidth
}

// Validate checks every field and reports all problems at once, each
// naming the offending field.
func (c Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !ValidNickname(c.Nickname) {
		add("invalid Nickname %q: use 1-19 letters and digits", c.Nickname)
	}
	if !ValidContactInfo(c.ContactInfo) {
		add("invalid ContactInfo: must be non-empty, at most 250 characters, one line, and without '#'")
	}
	if !ValidPort(c.ORPort) {
		add("invalid ORPort %d: must be 1-65535", c.ORPort)
	}
	if c.IPv6Address != "" && !ValidIPv6(c.IPv6Address) {
		add("invalid IPv6Address %q: need a global IPv6 address without brackets or prefix length", c.IPv6Address)
	}
	switch c.Mode {
	case ModeGuard:
	case ModeExit:
		if c.ExitPolicy != PolicyReduced && c.ExitPolicy != PolicyDefault {
			add("invalid ExitPolicy %q: want reduced or default", c.ExitPolicy)
		}
	default:
		add("invalid Mode %q: want guard or exit", c.Mode)
	}
	for _, id := range c.FamilyIDs {
		if !ValidFamilyID(id) {
			add("invalid FamilyIDs entry %q: need 43 base64 characters", id)
		}
	}
	if c.MetricsPort != "" && !validMetricsAddr(c.MetricsPort) {
		add("invalid MetricsPort %q: need a loopback address and port such as 127.0.0.1:9035", c.MetricsPort)
	}
	if err := c.Bandwidth.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Comments that mark managed blocks. Document edits recognise them (by
// prefix) so a block is replaced rather than duplicated.
const (
	familyComment        = "# Managed relay family (Tor 0.4.9 FamilyId). Every relay in the family shares the key."
	familyPendingComment = "# FamilyId <generated with tor --keygen-family during apply>"
	myFamilyComment      = "# Managed MyFamily (legacy, before Tor 0.4.9 FamilyId): relays controlled by this operator. Keep synced on every family member."
	metricsComment       = "# Local-only Prometheus metrics. Never expose this port publicly."
	bandwidthComment     = "# Managed bandwidth and traffic settings."
	rateComment          = "# Relay-specific bandwidth limits. Tor applies these per second."
	accountingComment    = "# Monthly accounting safety cap. Tor hibernates if this is exhausted."
)

// Render returns a complete torrc for c, laid out like the Bash installer's
// build_torrc. generatedBy and now (printed in UTC) go into the header.
// Render does not validate; call Validate first.
func (c Config) Render(generatedBy string, now time.Time) []byte {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	p("# Generated by %s on %s UTC.\n", generatedBy, now.UTC().Format("2006-01-02 15:04:05"))
	p("# Tor relay configuration.\n")
	p("# Review Tor Project relay documentation before making manual changes.\n")
	p("\n")
	p("Nickname %s\n", c.Nickname)
	p("ContactInfo %s\n", Quote(c.ContactInfo))
	if len(c.FamilyIDs) > 0 {
		p("\n%s\n", familyComment)
		for _, id := range c.FamilyIDs {
			p("FamilyId %s\n", id)
		}
	} else if c.FamilyPending {
		p("\n%s\n", familyPendingComment)
	}

	p("\nORPort %d\n", c.ORPort)
	if c.IPv6Address != "" {
		p("ORPort [%s]:%d\n", strings.Trim(c.IPv6Address, "[]"), c.ORPort)
	}

	p("\n# Disable local SOCKS listener on this relay-only server.\n")
	p("SocksPort 0\n")
	p("\n")
	if c.Mode == ModeExit {
		p("# Exit relay mode.\n")
		p("ExitRelay 1\n")
		if c.ExitPolicy == PolicyReduced {
			p("ReducedExitPolicy 1\n")
		}
		if c.IPv6Exit {
			p("IPv6Exit 1\n")
		}
	} else {
		p("# Guard / middle relay mode.\n")
		p("ExitRelay 0\n")
	}

	p("\n# Keep potentially sensitive log details scrubbed.\n")
	p("SafeLogging 1\n")
	if c.Sandbox {
		p("Sandbox 1\n")
	}

	if c.MetricsPort != "" {
		p("\n%s\n", metricsComment)
		for _, line := range metricsLines(c.MetricsPort) {
			p("%s\n", line)
		}
	}
	if lines := c.Bandwidth.rateLines(); len(lines) > 0 {
		p("\n%s\n", rateComment)
		for _, line := range lines {
			p("%s\n", line)
		}
	}
	if lines := c.Bandwidth.accountingLines(); len(lines) > 0 {
		p("\n%s\n", accountingComment)
		for _, line := range lines {
			p("%s\n", line)
		}
	}
	return []byte(b.String())
}

// validMetricsAddr accepts a loopback ip:port, the only safe place for
// Tor's unauthenticated metrics listener.
func validMetricsAddr(addr string) bool {
	ap, err := netip.ParseAddrPort(addr)
	return err == nil && ap.Port() != 0 && ap.Addr().Zone() == "" && ap.Addr().IsLoopback()
}

// metricsLines returns the MetricsPort directives. The policy admits only
// the host the port listens on (127.0.0.1, or [::1] for an IPv6 listener).
func metricsLines(addr string) []string {
	policy := "127.0.0.1"
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		a := ap.Addr()
		if a.Is4() || a.Is4In6() {
			policy = a.Unmap().String()
		} else {
			policy = "[" + a.String() + "]"
		}
	}
	return []string{"MetricsPort " + addr, "MetricsPortPolicy accept " + policy}
}
