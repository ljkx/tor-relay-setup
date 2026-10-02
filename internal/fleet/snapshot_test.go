package fleet

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSnapshot(t *testing.T) {
	m := contractFleet(t)
	// A second probe of the guard gives it a live rate.
	guard := m.Relays()[0].Probe
	next := *guard
	s := *guard.Sample
	s.At, s.Read, s.Written = t0.Add(10*time.Second), s.Read+10_000, s.Written+20_000
	next.Sample = &s
	m.Apply(okAt("root@guard.example.net", next))

	snap := m.Snapshot(t0, false)
	if snap.Totals.Relays != 7 || snap.Totals.Running != 5 || snap.Totals.HostsUp != 5 || snap.Totals.Attention == 0 || snap.Totals.Connections != 243 {
		t.Errorf("totals %+v", snap.Totals)
	}
	if len(snap.Hosts) != 7 || snap.Hosts[5].State != HostUnreachable || snap.Hosts[0].Relays != 1 || snap.Hosts[0].Version != "v3.2.0" {
		t.Errorf("hosts %+v", snap.Hosts)
	}
	byNick := map[string]SnapshotRelay{}
	for _, r := range snap.Relays {
		byNick[r.Nickname] = r
	}
	g := byNick["Guard1"]
	if g.ID != "guard.example.net/default" || g.Role != RoleGuard || !g.Fresh || !g.Active || g.LiveRead == nil || *g.LiveRead != 1000 ||
		g.Connections == nil || g.Load == nil || g.Load.OnionskinsProcessed != 70_010 || g.Directory == nil || g.Directory.Country != "de" ||
		g.Family == nil || g.Family.Consistent == nil || !*g.Family.Consistent {
		t.Errorf("guard %+v", g)
	}
	if a := byNick["Acct1"]; a.Accounting == nil || a.Accounting.Used != 1<<39 || a.Keys == nil || a.Keys.CertExpires.IsZero() {
		t.Errorf("accounting relay %+v", a)
	}
	if o := byNick["Over1"]; o.Directory == nil || !o.Directory.Overloaded {
		t.Errorf("overloaded relay %+v", o.Directory)
	}
	b := byNick["Bridge1"]
	if b.Fingerprint != bridgeHashed || b.Role != RoleBridge || b.Bridge == nil || b.Bridge.Transport != "obfs4" || b.Family != nil ||
		b.Directory == nil || !b.Directory.Published {
		t.Errorf("bridge %+v", b)
	}
	if d := byNick["Down1"]; d.Fresh || d.State != "unreachable" || d.Directory != nil {
		t.Errorf("unreachable relay %+v", d)
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{bridgeRealFP, "SECRETCERT", "203.0.113.9"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("the snapshot contains %q", secret)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if keysOf(doc) != "attention directory_updated generated_at hosts last_probe privacy probe_seconds relays tor_versions totals" {
		t.Errorf("top-level keys: %s", keysOf(doc))
	}

	private := m.Snapshot(t0, true)
	for _, r := range private.Relays {
		if r.LiveRead != nil || r.LiveWritten != nil || r.Connections != nil {
			t.Errorf("privacy mode leaks %s's traffic", r.Nickname)
		}
	}
	if !private.Privacy || private.Relays[0].Load == nil {
		t.Error("privacy mode")
	}
	if private.Totals.LiveRead == 0 || private.Totals.Connections != 243 {
		t.Errorf("privacy mode dropped the totals: %+v", private.Totals)
	}
}
