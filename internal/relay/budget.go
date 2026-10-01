package relay

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

var (
	// ErrQuotaFormat reports a traffic quota ParseQuota cannot read.
	ErrQuotaFormat = errors.New("traffic amount needs a number and unit, for example 10TB, 2.5TB or 5000GB")
	// ErrBelowMinimum reports a quota or bandwidth too small for a useful
	// relay: under 1 GByte for ParseQuota, or a steady rate under 10 Mbit/s
	// for Steady.
	ErrBelowMinimum = errors.New("below the relay minimum")
)

const (
	// MinRateKBytes is Tor's practical relay minimum, 10 Mbit/s.
	MinRateKBytes = 1221
	// RecommendedRateKBytes is Tor's recommended minimum, 16 Mbit/s.
	RecommendedRateKBytes = 1954
	// maxQuotaGBytes bounds quotas (1 EiB) so later arithmetic cannot overflow.
	maxQuotaGBytes = 1 << 30
	// pacingSeconds is the longest month (31 days): pacing over it means a
	// long month can never exhaust the quota early and trigger hibernation.
	pacingSeconds = 31 * 86400
)

var quotaRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(K|KB|KIB|KBYTES?|M|MB|MIB|MBYTES?|G|GB|GIB|GBYTES?|T|TB|TIB|TBYTES?)$`)

// ParseQuota converts a provider traffic amount into whole binary GBytes
// (2^30 bytes, Tor's AccountingMax unit), rounding down.
//
// Providers bill in decimal units, so K/M/G/T and KB/MB/GB/TB mean 10^3n
// bytes. KiB/MiB/GiB/TiB and Tor's own KBytes/MBytes/GBytes/TBytes spelling
// are binary (2^10n). Matching is case-insensitive, whitespace is ignored
// and decimals are allowed: "10TB" is 9313, "10 TiB" is 10240.
//
// Unreadable input wraps ErrQuotaFormat; amounts under 1 GByte wrap
// ErrBelowMinimum.
func ParseQuota(s string) (gbytes int, err error) {
	compact := strings.ToUpper(strings.Join(strings.Fields(s), ""))
	m := quotaRe.FindStringSubmatch(compact)
	if m == nil || len(m[1]) > 32 {
		return 0, fmt.Errorf("%w (got %q)", ErrQuotaFormat, s)
	}
	number, ok := new(big.Rat).SetString(m[1])
	if !ok {
		return 0, fmt.Errorf("%w (got %q)", ErrQuotaFormat, s)
	}
	unit := m[2]
	power := int64(strings.IndexByte("KMGT", unit[0]) + 1)
	base := int64(1000)
	if strings.HasSuffix(unit, "IB") || strings.Contains(unit, "BYTE") {
		base = 1024
	}
	scale := new(big.Int).Exp(big.NewInt(base), big.NewInt(power), nil)
	bytes := number.Mul(number, new(big.Rat).SetInt(scale))
	gib := bytes.Quo(bytes, new(big.Rat).SetInt64(1<<30))
	whole := new(big.Int).Quo(gib.Num(), gib.Denom()) // positive, so this floors

	if whole.Sign() == 0 {
		return 0, fmt.Errorf("%w: %q is less than 1 GByte", ErrBelowMinimum, s)
	}
	if whole.Cmp(big.NewInt(maxQuotaGBytes)) > 0 {
		return 0, fmt.Errorf("%w: %q is implausibly large", ErrQuotaFormat, s)
	}
	return int(whole.Int64()), nil
}

// SteadyPlan is the result of sizing steady bandwidth from a monthly quota.
type SteadyPlan struct {
	Bandwidth          Bandwidth // ready to use: Mode steady, rate, burst, accounting
	UsableGBytes       int       // quota after headroom; also AccountingMax
	PerDirectionGBytes int       // traffic budget per direction
	Mbit               float64   // RelayBandwidthRate in Mbit/s
	BelowRecommended   bool      // rate under 16 Mbit/s
}

// Steady spreads a monthly quota evenly over the longest month.
//
// usable = quota*(100-headroom)/100; the per-direction budget is half of that
// for RuleSum and all of it for RuleOut and RuleMax; the rate in KBytes/s is
// per-direction/31 days, and the burst is five times the rate. AccountingMax
// is set to the usable budget as a safety cap.
//
// headroomPercent must be 0-50. A rate under 10 Mbit/s returns an error
// wrapping ErrBelowMinimum together with the fully computed plan, so the
// caller can show the operator what the quota would have allowed.
func Steady(quotaGBytes, headroomPercent int, rule BillingRule) (SteadyPlan, error) {
	if headroomPercent < 0 || headroomPercent > 50 {
		return SteadyPlan{}, fmt.Errorf("headroom %d%% out of range: must be 0-50", headroomPercent)
	}
	if quotaGBytes < 1 || quotaGBytes > maxQuotaGBytes {
		return SteadyPlan{}, fmt.Errorf("quota %d GBytes out of range: must be 1-%d", quotaGBytes, maxQuotaGBytes)
	}
	usable := quotaGBytes * (100 - headroomPercent) / 100
	var perDir int
	switch rule {
	case RuleSum:
		perDir = usable / 2
	case RuleOut, RuleMax:
		perDir = usable
	default:
		return SteadyPlan{}, fmt.Errorf("unknown billing rule %q: want sum, out or max", rule)
	}

	rate := perDir * 1024 * 1024 / pacingSeconds
	plan := SteadyPlan{
		Bandwidth: Bandwidth{
			Mode:                BandwidthSteady,
			RateKBytes:          rate,
			BurstKBytes:         rate * 5,
			AccountingMaxGBytes: usable,
			AccountingRule:      rule,
		},
		UsableGBytes:       usable,
		PerDirectionGBytes: perDir,
		Mbit:               MbitFromKBytes(rate),
		BelowRecommended:   rate < RecommendedRateKBytes,
	}
	if rate < MinRateKBytes {
		return plan, fmt.Errorf("%w: the budget allows only %.1f Mbit/s, under Tor's practical 10 Mbit/s relay guidance",
			ErrBelowMinimum, plan.Mbit)
	}
	return plan, nil
}

// MbitFromKBytes converts Tor KBytes/s (1024 bytes) to Mbit/s (10^6 bits).
func MbitFromKBytes(k int) float64 { return float64(k) * 8192 / 1e6 }
