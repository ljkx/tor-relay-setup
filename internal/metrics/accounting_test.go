package metrics

import (
	"os"
	"testing"
	"time"
)

func TestParseBytes(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
	}{
		{"10 GBytes", 10 << 30},
		{"10 GB", 10 << 30},
		{"10gb", 10 << 30},
		{"1.5 TBytes", 3 << 39},
		{"500 MBytes", 500 << 20},
		{"8 gbits", 1 << 30},
		{"1024", 1024},
		{"4096 bytes", 4096},
		{"2 terabytes # quota", 2 << 40},
		{"1 m", 1 << 20},
	}
	for _, tt := range tests {
		got, err := ParseBytes(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseBytes(%q) = %d, %v; want %d", tt.in, got, err, tt.want)
		}
	}
	for _, bad := range []string{"", "GB", "ten GB", "10 parsecs", "10 k", "-1 GB", "1.2.3 GB", "99999999999 TB"} {
		if _, err := ParseBytes(bad); err == nil {
			t.Errorf("ParseBytes(%q) should fail", bad)
		}
	}
}

func TestParseAccountingStart(t *testing.T) {
	tests := []struct {
		in   string
		want AccountingStart
	}{
		{"", AccountingStart{Unit: "month", Day: 1}},
		{"month 1 00:00", AccountingStart{Unit: "month", Day: 1}},
		{"Month 28 23:59", AccountingStart{Unit: "month", Day: 28, Hour: 23, Minute: 59}},
		{"week 7 6:30", AccountingStart{Unit: "week", Day: 7, Hour: 6, Minute: 30}},
		{"day 10:00", AccountingStart{Unit: "day", Hour: 10}},
	}
	for _, tt := range tests {
		got, err := ParseAccountingStart(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseAccountingStart(%q) = %+v, %v", tt.in, got, err)
		}
	}
	for _, bad := range []string{"month", "month 29 00:00", "month 0 00:00", "week 8 00:00", "day 1 10:00", "day 24:00", "day 10:60", "day 10", "year 1 00:00", "month 1 0000"} {
		if _, err := ParseAccountingStart(bad); err == nil {
			t.Errorf("ParseAccountingStart(%q) should fail", bad)
		}
	}
}

func TestParseAccountingConfig(t *testing.T) {
	c, err := ParseAccountingConfig("10 GBytes", "", "")
	if err != nil || c.Max != 10<<30 || c.Rule != RuleMax || c.Start.Unit != "month" {
		t.Errorf("%+v %v", c, err)
	}
	c, err = ParseAccountingConfig("", "SUM", "day 10:00")
	if err != nil || c.Max != 0 || c.Rule != RuleSum || c.Start.Unit != "day" {
		t.Errorf("%+v %v", c, err)
	}
	for _, args := range [][3]string{{"lots", "", ""}, {"1 GB", "both", ""}, {"1 GB", "", "week 9 00:00"}} {
		if _, err := ParseAccountingConfig(args[0], args[1], args[2]); err == nil {
			t.Errorf("%q should fail", args)
		}
	}
}

func TestAccountingPeriod(t *testing.T) {
	vienna, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		t.Skip("no tz database:", err)
	}
	at := func(y int, m time.Month, d, h, min int) time.Time { return time.Date(y, m, d, h, min, 0, 0, vienna) }
	// Expected ends match tor 0.4.9.13's "Configured hibernation. This
	// interval begins at ... and ends at ..." notices for these settings,
	// started at 2026-10-02 13:19 Europe/Vienna.
	tests := []struct {
		start      string
		now        time.Time
		begin, end time.Time
	}{
		{"day 10:00", at(2026, 10, 2, 13, 19), at(2026, 10, 2, 10, 0), at(2026, 10, 3, 10, 0)},
		{"day 10:00", at(2026, 10, 2, 9, 59), at(2026, 10, 1, 10, 0), at(2026, 10, 2, 10, 0)},
		{"month 3 10:00", at(2026, 10, 2, 13, 19), at(2026, 9, 3, 10, 0), at(2026, 10, 3, 10, 0)},
		{"month 1 00:00", at(2026, 10, 2, 13, 19), at(2026, 10, 1, 0, 0), at(2026, 11, 1, 0, 0)},
		{"month 1 00:00", at(2026, 1, 1, 0, 0), at(2026, 1, 1, 0, 0), at(2026, 2, 1, 0, 0)},
		{"month 15 12:00", at(2026, 1, 3, 8, 0), at(2025, 12, 15, 12, 0), at(2026, 1, 15, 12, 0)},
		{"week 1 10:00", at(2026, 10, 2, 13, 19), at(2026, 9, 28, 10, 0), at(2026, 10, 5, 10, 0)}, // Friday; week starts Monday
		{"week 1 10:00", at(2026, 9, 28, 9, 0), at(2026, 9, 21, 10, 0), at(2026, 9, 28, 10, 0)},   // Monday before the changeover
		{"week 7 00:00", at(2026, 10, 4, 12, 0), at(2026, 10, 4, 0, 0), at(2026, 10, 11, 0, 0)},   // Sunday
	}
	for _, tt := range tests {
		s, err := ParseAccountingStart(tt.start)
		if err != nil {
			t.Fatal(err)
		}
		b, e := s.Period(tt.now)
		if !b.Equal(tt.begin) || !e.Equal(tt.end) {
			t.Errorf("%q at %v: period %v – %v, want %v – %v", tt.start, tt.now, b, e, tt.begin, tt.end)
		}
	}
}

func TestParseRealState(t *testing.T) {
	data, err := os.ReadFile("testdata/tor-state-0.4.9.13.txt")
	if err != nil {
		t.Fatal(err)
	}
	u, err := ParseState(data)
	if err != nil {
		t.Fatal(err)
	}
	want := AccountingUsage{
		IntervalStart: time.Date(2026, 9, 29, 22, 0, 0, 0, time.UTC),
		Read:          40329216, Written: 2846720, SecondsActive: 73,
		LastWritten: time.Date(2026, 10, 2, 11, 25, 50, 0, time.UTC),
	}
	if u != want {
		t.Errorf("got  %+v\nwant %+v", u, want)
	}
	if _, err := ParseState([]byte("# Tor state file\nTorVersion Tor 0.4.9.13\n")); err == nil {
		t.Error("a state file without accounting should fail")
	}
	if _, err := ParseState([]byte("AccountingBytesReadInInterval lots\n")); err == nil {
		t.Error("a malformed counter should fail")
	}
}

func TestAssessAccounting(t *testing.T) {
	month, _ := ParseAccountingStart("month 1 00:00")
	gib := uint64(1 << 30)
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC) // 10 of 31 days into October
	periodStart := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	usage := func(read, written uint64) AccountingUsage {
		return AccountingUsage{IntervalStart: periodStart, Read: read, Written: written, LastWritten: now.Add(-time.Minute)}
	}
	tests := []struct {
		name      string
		cfg       AccountingConfig
		u         AccountingUsage
		used      uint64
		fraction  float64
		projected uint64
		runsOut   bool
		exhausted bool
		exhausts  time.Time
		stale     bool
	}{
		{
			name: "sum on pace", cfg: AccountingConfig{Max: 320 * gib, Rule: RuleSum, Start: month},
			u: usage(60*gib, 40*gib), used: 100 * gib, fraction: 100.0 / 320, projected: 310 * gib,
		},
		{
			name: "max rule counts the larger direction", cfg: AccountingConfig{Max: 100 * gib, Rule: RuleMax, Start: month},
			u: usage(20*gib, 30*gib), used: 30 * gib, fraction: 0.3, projected: 93 * gib,
		},
		{
			name: "in and out", cfg: AccountingConfig{Max: 100 * gib, Rule: RuleIn, Start: month},
			u: usage(20*gib, 30*gib), used: 20 * gib, fraction: 0.2, projected: 62 * gib,
		},
		{
			name: "runs out before the period ends", cfg: AccountingConfig{Max: 100 * gib, Rule: RuleOut, Start: month},
			u: usage(0, 50*gib), used: 50 * gib, fraction: 0.5, projected: 155 * gib, runsOut: true,
			exhausts: now.Add(10 * 24 * time.Hour),
		},
		{
			name: "used up: tor hibernates", cfg: AccountingConfig{Max: 100 * gib, Rule: RuleSum, Start: month},
			u: usage(60*gib, 45*gib), used: 105 * gib, fraction: 1.05, projected: 325500 * gib / 1000, runsOut: true, exhausted: true, exhausts: now,
		},
		{
			name: "stale state from the last period", cfg: AccountingConfig{Max: 100 * gib, Rule: RuleSum, Start: month},
			u:     AccountingUsage{Read: 99 * gib, LastWritten: periodStart.Add(-time.Hour)},
			stale: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AssessAccounting(tt.cfg, tt.u, now)
			if !a.Enabled || a.Used != tt.used || a.Stale != tt.stale {
				t.Fatalf("enabled/used/stale = %v/%d/%v", a.Enabled, a.Used, a.Stale)
			}
			if d := a.Fraction() - tt.fraction; d > 1e-9 || d < -1e-9 {
				t.Errorf("fraction %v, want %v", a.Fraction(), tt.fraction)
			}
			if diff := int64(a.Projected) - int64(tt.projected); diff > 1<<20 || diff < -(1<<20) {
				t.Errorf("projected %d GiB, want %d GiB", a.Projected>>30, tt.projected>>30)
			}
			if a.RunsOut() != tt.runsOut || a.Exhausted() != tt.exhausted || !a.ExhaustsAt.Equal(tt.exhausts) {
				t.Errorf("runsOut/exhausted/at = %v/%v/%v", a.RunsOut(), a.Exhausted(), a.ExhaustsAt)
			}
			if !a.PeriodStart.Equal(periodStart) || !a.PeriodEnd.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
				t.Errorf("period %v – %v", a.PeriodStart, a.PeriodEnd)
			}
		})
	}
	if a := AssessAccounting(AccountingConfig{Rule: RuleMax, Start: month}, usage(1, 1), now); a.Enabled || a.Fraction() != 0 || a.RunsOut() || a.Exhausted() {
		t.Errorf("no AccountingMax means accounting is off: %+v", a)
	}
}

func TestAssessAccountingRealState(t *testing.T) {
	data, _ := os.ReadFile("testdata/tor-state-0.4.9.13.txt")
	u, err := ParseState(data)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseAccountingConfig("10 GBytes", "sum", "month 1 00:00")
	if err != nil {
		t.Fatal(err)
	}
	vienna, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		t.Skip("no tz database:", err)
	}
	now := time.Date(2026, 10, 2, 13, 26, 0, 0, vienna)
	a := AssessAccounting(cfg, u, now)
	if a.Used != 40329216+2846720 || a.Stale || a.RunsOut() {
		t.Errorf("%+v", a)
	}
	if a.Fraction() > 0.005 || a.Projected <= a.Used {
		t.Errorf("fraction %v, projected %d", a.Fraction(), a.Projected)
	}
}
