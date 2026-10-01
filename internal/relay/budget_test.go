package relay

import (
	"errors"
	"math"
	"testing"
)

func TestParseQuota(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr error
	}{
		{"10TB", 9313, nil},
		{"2.5TB", 2328, nil},
		{"5000 GB", 4656, nil},
		{"5000gb", 4656, nil},
		{" 10 t ", 9313, nil},
		{"10TiB", 10240, nil},
		{"10 tib", 10240, nil},
		{"5000GBytes", 5000, nil},
		{"5000 GByte", 5000, nil},
		{"1 TByte", 1024, nil},
		{"1048576 MiB", 1024, nil},
		{"1073741824 KiB", 1024, nil},
		{"1073741824KBytes", 1024, nil},
		{"1.5 GiB", 1, nil},
		{"2G", 1, nil},
		{"1 GiB", 1, nil},
		{"900MB", 0, ErrBelowMinimum},
		{"1GB", 0, ErrBelowMinimum}, // 10^9 bytes is 0.93 GiB
		{"0TB", 0, ErrBelowMinimum},
		{"10 bananas", 0, ErrQuotaFormat},
		{"", 0, ErrQuotaFormat},
		{"TB", 0, ErrQuotaFormat},
		{"10", 0, ErrQuotaFormat},
		{"-5TB", 0, ErrQuotaFormat},
		{"1.TB", 0, ErrQuotaFormat},
		{"1e3GB", 0, ErrQuotaFormat},
		{"10PB", 0, ErrQuotaFormat},
		{"99999999999999TB", 0, ErrQuotaFormat},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseQuota(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseQuota(%q) error = %v, want %v", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ParseQuota(%q) = %d, %v; want %d", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestSteady(t *testing.T) {
	tests := []struct {
		name             string
		quota, headroom  int
		rule             BillingRule
		usable, perDir   int
		rate, burst      int
		belowRecommended bool
		wantBelowMinimum bool
	}{
		{"10TB sum 10%", 9313, 10, RuleSum, 8381, 4190, 1640, 8200, true, false},
		{"10TB out 10%", 9313, 10, RuleOut, 8381, 8381, 3281, 16405, false, false},
		{"10TB max 0%", 9313, 0, RuleMax, 9313, 9313, 3645, 18225, false, false},
		{"20TB sum", 18626, 10, RuleSum, 16763, 8381, 3281, 16405, false, false},
		{"5000GB sum too small", 4656, 10, RuleSum, 4190, 2095, 820, 4100, true, true},
		{"headroom 50", 20000, 50, RuleOut, 10000, 10000, 3914, 19570, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := Steady(tt.quota, tt.headroom, tt.rule)
			if tt.wantBelowMinimum {
				if !errors.Is(err, ErrBelowMinimum) {
					t.Fatalf("error = %v, want ErrBelowMinimum", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			b := plan.Bandwidth
			if plan.UsableGBytes != tt.usable || plan.PerDirectionGBytes != tt.perDir ||
				b.RateKBytes != tt.rate || b.BurstKBytes != tt.burst {
				t.Fatalf("plan = %+v", plan)
			}
			if b.Mode != BandwidthSteady || b.AccountingMaxGBytes != tt.usable || b.AccountingRule != tt.rule {
				t.Errorf("bandwidth = %+v", b)
			}
			if plan.BelowRecommended != tt.belowRecommended {
				t.Errorf("BelowRecommended = %v", plan.BelowRecommended)
			}
			if want := MbitFromKBytes(tt.rate); plan.Mbit != want {
				t.Errorf("Mbit = %v, want %v", plan.Mbit, want)
			}
			if err == nil {
				if verr := b.Validate(); verr != nil {
					t.Errorf("plan bandwidth invalid: %v", verr)
				}
			}
		})
	}
}

func TestSteadyThresholds(t *testing.T) {
	// perDir*1048576/2678400 == 1221 at perDir 3119; 1954 at perDir 4992.
	if _, err := Steady(3119, 0, RuleMax); err != nil {
		t.Errorf("rate 1221 rejected: %v", err)
	}
	if _, err := Steady(3118, 0, RuleMax); !errors.Is(err, ErrBelowMinimum) {
		t.Errorf("rate 1220 accepted: %v", err)
	}
	if p, _ := Steady(4991, 0, RuleMax); !p.BelowRecommended {
		t.Errorf("rate %d not below recommended", p.Bandwidth.RateKBytes)
	}
	if p, _ := Steady(4992, 0, RuleMax); p.BelowRecommended || p.Bandwidth.RateKBytes != 1954 {
		t.Errorf("rate %d below recommended", p.Bandwidth.RateKBytes)
	}
}

func TestSteadyErrors(t *testing.T) {
	for _, tt := range []struct {
		quota, headroom int
		rule            BillingRule
	}{
		{9313, -1, RuleSum},
		{9313, 51, RuleSum},
		{9313, 10, "in"},
		{9313, 10, ""},
		{0, 10, RuleSum},
		{math.MaxInt, 10, RuleSum},
	} {
		if _, err := Steady(tt.quota, tt.headroom, tt.rule); err == nil || errors.Is(err, ErrBelowMinimum) {
			t.Errorf("Steady(%d, %d, %q) error = %v, want argument error", tt.quota, tt.headroom, tt.rule, err)
		}
	}
	if _, err := Steady(1, 50, RuleSum); !errors.Is(err, ErrBelowMinimum) {
		t.Errorf("tiny quota error = %v", err)
	}
}

func TestMbitFromKBytes(t *testing.T) {
	if got := MbitFromKBytes(1221); math.Abs(got-10.002432) > 1e-9 {
		t.Errorf("MbitFromKBytes(1221) = %v", got)
	}
	if got := MbitFromKBytes(0); got != 0 {
		t.Errorf("MbitFromKBytes(0) = %v", got)
	}
}
