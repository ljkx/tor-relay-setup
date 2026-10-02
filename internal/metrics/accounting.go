package metrics

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Tor's MetricsPort (0.4.9) has no accounting series, so accounting usage
// comes from the state file in the DataDirectory (/var/lib/tor/state),
// which tor rewrites about once a minute while accounting is enabled:
//
//	AccountingBytesReadInInterval 40329216
//	AccountingBytesWrittenInInterval 2846720
//	AccountingIntervalStart 2026-09-29 22:00:00
//	AccountingSecondsActive 73
//	LastWritten 2026-10-02 11:25:50
//
// Times in the state file are UTC. The limits come from torrc
// (AccountingMax, AccountingRule, AccountingStart).

// Accounting rules (torrc AccountingRule).
const (
	RuleMax = "max" // the larger of bytes read and written (tor's default)
	RuleSum = "sum" // read plus written
	RuleIn  = "in"  // read only
	RuleOut = "out" // written only
)

// AccountingConfig is a relay's torrc accounting setup.
type AccountingConfig struct {
	Max   uint64 // AccountingMax in bytes; 0 means accounting is off
	Rule  string // one of the Rule constants
	Start AccountingStart
}

// AccountingStart is a parsed AccountingStart: the period unit and when
// each period begins, in the relay's local time.
type AccountingStart struct {
	Unit   string // "day", "week" or "month"
	Day    int    // week: 1 (Monday) to 7 (Sunday); month: 1 to 28; day: 0
	Hour   int
	Minute int
}

// ParseAccountingConfig reads the three torrc values (as relay.Document.Get
// returns them; empty when unset). Defaults follow tor: rule "max" and
// "month 1 0:00". An empty max means accounting is off.
func ParseAccountingConfig(maxValue, rule, start string) (AccountingConfig, error) {
	var c AccountingConfig
	var err error
	if strings.TrimSpace(maxValue) != "" {
		if c.Max, err = ParseBytes(maxValue); err != nil {
			return c, fmt.Errorf("AccountingMax: %w", err)
		}
	}
	switch r := strings.ToLower(strings.TrimSpace(rule)); r {
	case "":
		c.Rule = RuleMax
	case RuleMax, RuleSum, RuleIn, RuleOut:
		c.Rule = r
	default:
		return c, fmt.Errorf("AccountingRule %q: want max, sum, in or out", rule)
	}
	if c.Start, err = ParseAccountingStart(start); err != nil {
		return c, err
	}
	return c, nil
}

// memoryUnits is tor's memory_units table (src/lib/confmgt/unitparse.c):
// byte units are binary, and the bit units are an eighth of them.
var memoryUnits = map[string]uint64{
	"": 1, "b": 1, "byte": 1, "bytes": 1,
	"kb": 1 << 10, "kbyte": 1 << 10, "kbytes": 1 << 10, "kilobyte": 1 << 10, "kilobytes": 1 << 10,
	"kilobits": 1 << 7, "kilobit": 1 << 7, "kbits": 1 << 7, "kbit": 1 << 7,
	"m": 1 << 20, "mb": 1 << 20, "mbyte": 1 << 20, "mbytes": 1 << 20, "megabyte": 1 << 20, "megabytes": 1 << 20,
	"megabits": 1 << 17, "megabit": 1 << 17, "mbits": 1 << 17, "mbit": 1 << 17,
	"gb": 1 << 30, "gbyte": 1 << 30, "gbytes": 1 << 30, "gigabyte": 1 << 30, "gigabytes": 1 << 30,
	"gigabits": 1 << 27, "gigabit": 1 << 27, "gbits": 1 << 27, "gbit": 1 << 27,
	"tb": 1 << 40, "tbyte": 1 << 40, "tbytes": 1 << 40, "terabyte": 1 << 40, "terabytes": 1 << 40,
	"terabits": 1 << 37, "terabit": 1 << 37, "tbits": 1 << 37, "tbit": 1 << 37,
}

// ParseBytes parses a torrc memory value such as "10 GBytes", "1.5 TB" or
// "500 MBits" the way tor does: units are case-insensitive, KB/MB/GB/TB are
// binary (2^10n), and a trailing comment is ignored.
func ParseBytes(s string) (uint64, error) {
	v, _, _ := strings.Cut(s, "#")
	v = strings.TrimSpace(v)
	i := strings.IndexFunc(v, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	num, unit := v, ""
	if i >= 0 {
		num, unit = v[:i], strings.ToLower(strings.TrimSpace(v[i:]))
	}
	mult, ok := memoryUnits[unit]
	if !ok || num == "" {
		return 0, fmt.Errorf("cannot read %q as an amount of bytes", s)
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot read %q as an amount of bytes", s)
	}
	total := f * float64(mult)
	if total >= math.MaxInt64 {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return uint64(total), nil
}

// ParseAccountingStart parses "day HH:MM", "week D HH:MM" or
// "month D HH:MM" like tor's accounting_parse_options; empty is tor's
// default "month 1 0:00".
func ParseAccountingStart(s string) (AccountingStart, error) {
	v, _, _ := strings.Cut(s, "#")
	f := strings.Fields(v)
	if len(f) == 0 {
		return AccountingStart{Unit: "month", Day: 1}, nil
	}
	bad := func(why string) (AccountingStart, error) {
		return AccountingStart{}, fmt.Errorf("AccountingStart %q: %s", strings.TrimSpace(v), why)
	}
	st := AccountingStart{Unit: strings.ToLower(f[0])}
	want, lo, hi := 3, 1, 0
	switch st.Unit {
	case "day":
		want = 2
	case "week":
		hi = 7
	case "month":
		hi = 28
	default:
		return bad("unit must be day, week or month")
	}
	if len(f) != want {
		return bad(fmt.Sprintf("%s needs %d argument(s)", st.Unit, want-1))
	}
	if want == 3 {
		d, err := strconv.Atoi(f[1])
		if err != nil || d < lo || d > hi {
			return bad(fmt.Sprintf("day must be %d-%d", lo, hi))
		}
		st.Day = d
	}
	hh, mm, ok := strings.Cut(f[want-1], ":")
	h, herr := strconv.Atoi(hh)
	m, merr := strconv.Atoi(mm)
	if !ok || herr != nil || merr != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return bad("time must be HH:MM")
	}
	st.Hour, st.Minute = h, m
	return st, nil
}

// Period returns the accounting period containing now, in now's location
// (tor uses the relay's local time), mirroring tor's
// edge_of_accounting_period_containing.
func (s AccountingStart) Period(now time.Time) (start, end time.Time) {
	loc := now.Location()
	y, mo, d := now.Date()
	before := now.Hour() < s.Hour || (now.Hour() == s.Hour && now.Minute() < s.Minute)
	at := func(y int, mo time.Month, d int) time.Time {
		return time.Date(y, mo, d, s.Hour, s.Minute, 0, 0, loc)
	}
	switch s.Unit {
	case "week":
		wday := s.Day % 7 // tor: 7 is Sunday; time.Weekday: 0 is Sunday
		back := (7 + int(now.Weekday()) - wday) % 7
		if back == 0 && before {
			back = 7
		}
		start = at(y, mo, d-back)
		return start, at(y, mo, d-back+7)
	case "day":
		if before {
			d--
		}
		return at(y, mo, d), at(y, mo, d+1)
	default: // month
		if d < s.Day || (d == s.Day && before) {
			mo--
		}
		return at(y, mo, s.Day), at(y, mo+1, s.Day)
	}
}

// AccountingUsage is the accounting part of tor's state file.
type AccountingUsage struct {
	IntervalStart time.Time `json:"interval_start"`
	Read          uint64    `json:"read"`
	Written       uint64    `json:"written"`
	SecondsActive int64     `json:"seconds_active"`
	LastWritten   time.Time `json:"last_written"`
}

// stateTime is the format of times in tor's state file (UTC).
const stateTime = "2006-01-02 15:04:05"

// ParseState reads the accounting lines from tor's state file. It fails
// when there are none: accounting has never been enabled on this relay.
func ParseState(data []byte) (AccountingUsage, error) {
	var u AccountingUsage
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		key, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		val = strings.TrimSpace(val)
		var err error
		switch key {
		case "AccountingBytesReadInInterval":
			u.Read, err = strconv.ParseUint(val, 10, 64)
			found = true
		case "AccountingBytesWrittenInInterval":
			u.Written, err = strconv.ParseUint(val, 10, 64)
			found = true
		case "AccountingSecondsActive":
			u.SecondsActive, err = strconv.ParseInt(val, 10, 64)
		case "AccountingIntervalStart":
			u.IntervalStart, err = time.ParseInLocation(stateTime, val, time.UTC)
			found = true
		case "LastWritten":
			u.LastWritten, err = time.ParseInLocation(stateTime, val, time.UTC)
		}
		if err != nil {
			return u, fmt.Errorf("tor state file: %s: %w", key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return u, fmt.Errorf("tor state file: %w", err)
	}
	if !found {
		return u, fmt.Errorf("tor state file has no accounting data")
	}
	return u, nil
}

// Accounting is the assessment of the current accounting period.
type Accounting struct {
	Enabled bool   `json:"enabled"`
	Rule    string `json:"rule,omitempty"`
	Max     uint64 `json:"max_bytes,omitempty"`
	// Used is what AccountingRule counts against Max.
	Used          uint64    `json:"used_bytes"`
	Read          uint64    `json:"read_bytes"`
	Written       uint64    `json:"written_bytes"`
	PeriodStart   time.Time `json:"period_start"`
	PeriodEnd     time.Time `json:"period_end"`
	SecondsActive int64     `json:"seconds_active"`
	// Projected is Used at the end of the period at the period's average
	// pace so far.
	Projected uint64 `json:"projected_bytes"`
	// ExhaustsAt is when Max is reached at that pace, if before PeriodEnd.
	ExhaustsAt time.Time `json:"exhausts_at,omitzero"`
	// Stale is true when the state file was last written before this
	// period began (tor was not running since): Used counts as 0.
	Stale bool `json:"stale,omitempty"`
}

// Fraction is Used/Max, 0 when accounting is off.
func (a Accounting) Fraction() float64 {
	if a.Max == 0 {
		return 0
	}
	return float64(a.Used) / float64(a.Max)
}

// Exhausted reports whether the limit is reached, so tor hibernates until
// the period ends. Tor already stops accepting new connections a little
// earlier (the soft limit: 95% used, or less than 500 MBytes left).
func (a Accounting) Exhausted() bool { return a.Enabled && a.Used >= a.Max }

// RunsOut reports whether the limit is expected to be reached before the
// period ends.
func (a Accounting) RunsOut() bool { return a.Enabled && !a.ExhaustsAt.IsZero() }

// AssessAccounting compares usage from the state file with the torrc limit.
// now's location must be the relay's local time zone (time.Local on the
// relay), because AccountingStart is local time.
func AssessAccounting(cfg AccountingConfig, u AccountingUsage, now time.Time) Accounting {
	a := Accounting{Enabled: cfg.Max > 0, Rule: cfg.Rule, Max: cfg.Max}
	if !a.Enabled {
		return a
	}
	a.PeriodStart, a.PeriodEnd = cfg.Start.Period(now)
	if !u.LastWritten.IsZero() && u.LastWritten.Before(a.PeriodStart) {
		a.Stale = true
		return a
	}
	a.Read, a.Written, a.SecondsActive = u.Read, u.Written, u.SecondsActive
	switch cfg.Rule {
	case RuleSum:
		a.Used = u.Read + u.Written
	case RuleIn:
		a.Used = u.Read
	case RuleOut:
		a.Used = u.Written
	default:
		a.Used = max(u.Read, u.Written)
	}

	elapsed := now.Sub(a.PeriodStart).Seconds()
	remaining := a.PeriodEnd.Sub(now).Seconds()
	if elapsed <= 0 || remaining <= 0 {
		a.Projected = a.Used
		return a
	}
	pace := float64(a.Used) / elapsed // bytes per second
	a.Projected = a.Used + uint64(pace*remaining)
	switch {
	case a.Used >= a.Max:
		a.ExhaustsAt = now
	case pace > 0:
		left := float64(a.Max-a.Used) / pace
		if left < remaining {
			a.ExhaustsAt = now.Add(time.Duration(left * float64(time.Second))).Truncate(time.Second)
		}
	}
	return a
}
