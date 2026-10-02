package serve

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/fleet"
)

// demoModel probes the demo fleet once at the clock's time.
func demoModel(t *testing.T, seed uint64, clk *clock) (*fleet.Model, *Demo) {
	t.Helper()
	d := NewDemo(seed, clk.now)
	m := fleet.NewModel(d.Inventory())
	for _, a := range d.Inventory().Addresses() {
		m.Apply(d.Probe(context.Background(), a))
	}
	m.EndRound(clk.now(), clk.now())
	m.SetDirectoryResult(d.Directory(context.Background(), m.Fingerprints(), m.BridgeFingerprints()))
	return m, d
}

func promOf(t *testing.T, m *fleet.Model, now time.Time) string {
	t.Helper()
	var b bytes.Buffer
	if err := m.WritePrometheus(&b, fleet.PrometheusOptions{Now: now}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestDemoIsDeterministic(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	a, _ := demoModel(t, DemoSeed, &clock{t: at})
	b, _ := demoModel(t, DemoSeed, &clock{t: at})
	if pa, pb := promOf(t, a, at), promOf(t, b, at); pa != pb {
		t.Error("the same seed and clock gave different fleets")
	}
	c, _ := demoModel(t, DemoSeed+1, &clock{t: at})
	if promOf(t, a, at) == promOf(t, c, at) {
		t.Error("another seed gave the same fleet")
	}
}

func TestDemoFleetShape(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	m, d := demoModel(t, DemoSeed, clk)
	inv := d.Inventory()
	if len(inv.Entries) != 12 || len(inv.Addresses()) != 7 {
		t.Fatalf("%d relays on %d hosts", len(inv.Entries), len(inv.Addresses()))
	}
	tot := m.Totals()
	if tot.Relays != 12 || tot.HostsUp != 6 || tot.Unreachable != 1 || tot.Running != 11 || tot.Published != 11 {
		t.Errorf("totals %+v", tot)
	}
	roles := map[string]int{}
	var overloaded, accounting, certSoon, legacy int
	countries := map[string]bool{}
	for _, r := range m.Relays() {
		roles[m.Role(r)]++
		if d := m.DirectoryOf(r); d != nil {
			countries[d.Country] = true
			if d.Overloaded(clk.now()) {
				overloaded++
			}
		}
		if r.Probe == nil {
			continue
		}
		if r.Probe.Accounting != nil {
			a := r.Probe.Accounting
			if f := a.Fraction(); f < 0.8 || f > 1 {
				t.Errorf("accounting at %.2f", f)
			}
			accounting++
		}
		if k := r.Probe.Report.Keys; k != nil && k.Offline {
			if left := k.CertExpires.Sub(clk.now()); left <= 0 || left > 7*24*time.Hour {
				t.Errorf("signing cert expires in %v", left)
			}
			certSoon++
		}
		if r.Probe.Sample == nil {
			legacy++
		}
	}
	if roles[fleet.RoleGuard] < 3 || roles[fleet.RoleExit] < 2 || roles[fleet.RoleMiddle] < 2 || roles[fleet.RoleBridge] != 1 {
		t.Errorf("roles %v", roles)
	}
	if overloaded != 1 || accounting != 1 || certSoon != 1 || legacy != 2 || len(countries) < 5 {
		t.Errorf("overloaded %d accounting %d cert %d legacy %d countries %v", overloaded, accounting, certSoon, legacy, countries)
	}
	if len(m.TorVersions()) < 3 {
		t.Errorf("versions %v", m.TorVersions())
	}
	kinds := map[string]bool{}
	for _, it := range m.Attention() {
		kinds[it.Kind] = true
	}
	for _, k := range []string{"unreachable", "version-drift", "relay-warning"} {
		if !kinds[k] {
			t.Errorf("attention lacks %s: %v", k, kinds)
		}
	}
	if tot := m.Totals(); len(tot.History) < 28 {
		t.Errorf("history %d days", len(tot.History))
	}
}

func TestDemoCountersGrowRealistically(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	d := NewDemo(DemoSeed, clk.now)
	m := fleet.NewModel(d.Inventory())
	probe := func() {
		for _, a := range d.Inventory().Addresses() {
			m.Apply(d.Probe(context.Background(), a))
		}
		m.EndRound(clk.now(), clk.now())
	}
	probe()
	first := m.Totals()
	var prevRead float64
	for i := range 30 {
		clk.add(30 * time.Second)
		probe()
		tot := m.Totals()
		if tot.TrafficRead <= prevRead && i > 0 {
			t.Fatalf("fleet counter did not grow at step %d", i)
		}
		prevRead = tot.TrafficRead
	}
	last := m.Totals()
	// 15 minutes of a fleet of a few Gbit/s: hundreds of GB, at a rate the
	// live view agrees with.
	grown := last.TrafficRead - first.TrafficRead
	perSecond := grown / (15 * 60)
	if perSecond < 1e8 || perSecond > 1e9 {
		t.Errorf("fleet reads %.0f B/s", perSecond)
	}
	if last.Read < perSecond*0.7 || last.Read > perSecond*1.3 {
		t.Errorf("live rate %.0f vs counter rate %.0f", last.Read, perSecond)
	}
}
