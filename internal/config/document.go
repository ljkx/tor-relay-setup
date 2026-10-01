package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/relay"
)

// FromDocument derives setup answers from an existing torrc so that
// reconfiguring a relay starts from what it runs today. Existing FamilyIds
// are kept and bandwidth limits are reproduced exactly.
func FromDocument(doc *relay.Document) Setup {
	s := Default()
	s.Relay.Nickname, _ = doc.Get("Nickname")
	if c, ok := doc.Get("ContactInfo"); ok {
		s.Relay.Contact = relay.Unquote(c)
	}
	if p := doc.FirstORPort(); p > 0 {
		s.Relay.ORPort = p
	}
	for _, p := range doc.ORPorts() {
		if open := strings.Index(p, "["); open >= 0 {
			if end := strings.Index(p, "]"); end > open {
				s.Relay.IPv6 = p[open+1 : end]
			}
		}
	}
	if flag(doc, "ExitRelay") {
		s.Relay.Mode = string(relay.ModeExit)
		s.Exit.ProviderPermission = true // an exit is already running
		s.Exit.Policy = string(relay.PolicyDefault)
		if flag(doc, "ReducedExitPolicy") {
			s.Exit.Policy = string(relay.PolicyReduced)
		}
		s.Exit.IPv6Exit = flag(doc, "IPv6Exit")
	}
	// Tor's default is Sandbox 0, and Render omits the line when it is off.
	s.Relay.Sandbox = flag(doc, "Sandbox")
	_, s.Relay.MetricsPort = doc.Get("MetricsPort")
	s.Family.Keep = doc.FamilyIDs()

	s.Bandwidth = bandwidthFrom(doc)
	return s
}

func flag(doc *relay.Document, key string) bool {
	v, ok := doc.Get(key)
	return ok && strings.TrimSpace(v) == "1"
}

// bandwidthFrom maps the torrc limits onto the friendliest mode that
// renders them byte for byte, falling back to custom (kept verbatim).
func bandwidthFrom(doc *relay.Document) BandwidthPlan {
	b := BandwidthPlan{Mode: string(relay.BandwidthNone), HeadroomPercent: 10, Billing: string(relay.RuleSum)}
	rate, hasRate := doc.Get("RelayBandwidthRate")
	burst, hasBurst := doc.Get("RelayBandwidthBurst")
	maxV, hasMax := doc.Get("AccountingMax")
	if rule, ok := doc.Get("AccountingRule"); ok {
		b.Billing = strings.ToLower(strings.TrimSpace(rule))
	} else {
		b.Billing = string(relay.RuleMax) // Tor's default
	}
	accounting := 0
	if hasMax {
		if gb, ok := gbytes(maxV); ok {
			accounting = gb
		}
	}

	if !hasRate {
		if accounting > 0 {
			b.Mode = string(relay.BandwidthAccounting)
			b.MonthlyQuota = fmt.Sprintf("%dGiB", accounting)
			b.HeadroomPercent = 0
		}
		return b
	}

	// Rate and burst both in MBits: manual mode reproduces them exactly.
	if r, ok := mbits(rate); ok {
		if br, ok := mbits(burst); ok || !hasBurst {
			b.Mode = string(relay.BandwidthManual)
			b.RateMbit, b.BurstMbit = r, br
			if !hasBurst {
				b.BurstMbit = r
			}
			b.AccountingGBytes = accounting
			return b
		}
	}

	rk, rateOK := kbytes(rate)
	bk, burstOK := kbytes(burst)
	if !hasBurst {
		bk, burstOK = rk, true
	}
	if !rateOK || !burstOK {
		return b // a unit this tool cannot reproduce: leave limits out
	}
	// A steady budget with 0% headroom over AccountingMax gives back the same
	// numbers when the relay was set up with this tool; use it if it does.
	if accounting > 0 {
		if p, err := relay.Steady(accounting, 0, relay.BillingRule(b.Billing)); err == nil &&
			p.Bandwidth.RateKBytes == rk && p.Bandwidth.BurstKBytes == bk {
			b.Mode = string(relay.BandwidthSteady)
			b.MonthlyQuota = fmt.Sprintf("%dGiB", accounting)
			b.HeadroomPercent = 0
			return b
		}
	}
	b.Mode = BandwidthCustom
	b.RateKBytes, b.BurstKBytes, b.AccountingGBytes = rk, bk, accounting
	return b
}

// amount splits "1640 KBytes" into its number and unit.
func amount(v string) (int, string, bool) {
	f := strings.Fields(v)
	if len(f) == 0 {
		return 0, "", false
	}
	n, err := strconv.Atoi(f[0])
	if err != nil || n < 0 {
		return 0, "", false
	}
	unit := ""
	if len(f) > 1 {
		unit = strings.ToLower(f[1])
	}
	return n, unit, true
}

// kbytes converts a torrc byte-rate value to whole KBytes. Bit units are
// not converted (they do not map onto KBytes exactly).
func kbytes(v string) (int, bool) {
	n, unit, ok := amount(v)
	if !ok {
		return 0, false
	}
	switch unit {
	case "", "byte", "bytes", "b":
		if n%1024 != 0 {
			return 0, false
		}
		return n / 1024, true
	case "kbyte", "kbytes", "kb":
		return n, true
	case "mbyte", "mbytes", "mb":
		return n * 1024, true
	case "gbyte", "gbytes", "gb":
		return n * 1024 * 1024, true
	}
	return 0, false
}

func mbits(v string) (int, bool) {
	n, unit, ok := amount(v)
	if !ok || (unit != "mbits" && unit != "mbit") {
		return 0, false
	}
	return n, true
}

func gbytes(v string) (int, bool) {
	n, unit, ok := amount(v)
	if !ok {
		return 0, false
	}
	switch unit {
	case "gbytes", "gbyte", "gb":
		return n, true
	case "tbytes", "tbyte", "tb":
		return n * 1024, true
	case "mbytes", "mbyte", "mb":
		return n / 1024, n >= 1024 && n%1024 == 0
	}
	return 0, false
}
