package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalWriteFileBacksUpAndIsAtomic(t *testing.T) {
	root := t.TempDir()
	l := &Local{Root: root, Stamp: "20260101T000000Z"}

	ch, err := l.WriteFile("/etc/tor/torrc", []byte("one\n"), FileOptions{Mode: 0o644, Backup: true})
	if err != nil || !ch.Created {
		t.Fatalf("first write: %+v %v", ch, err)
	}
	ch, err = l.WriteFile("/etc/tor/torrc", []byte("one\n"), FileOptions{Backup: true})
	if err != nil || !ch.Unchanged {
		t.Fatalf("identical write should be unchanged: %+v %v", ch, err)
	}
	ch, err = l.WriteFile("/etc/tor/torrc", []byte("two\n"), FileOptions{Backup: true})
	if err != nil || ch.BackupOf != "/etc/tor/torrc.bak.20260101T000000Z" {
		t.Fatalf("changed write should back up: %+v %v", ch, err)
	}
	backup, _ := os.ReadFile(filepath.Join(root, ch.BackupOf))
	current, _ := os.ReadFile(filepath.Join(root, "/etc/tor/torrc"))
	if string(backup) != "one\n" || string(current) != "two\n" {
		t.Fatalf("backup=%q current=%q", backup, current)
	}

	// A second backup in the same run gets a numeric suffix.
	ch, _ = l.WriteFile("/etc/tor/torrc", []byte("three\n"), FileOptions{Backup: true})
	if ch.BackupOf != "/etc/tor/torrc.bak.20260101T000000Z.1" {
		t.Fatalf("second backup path = %q", ch.BackupOf)
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, "etc/tor/.torrc.tmp-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestLocalStreamCapturesOutputStatusFDAndExitCode(t *testing.T) {
	l := NewLocal()
	var lines, status []string
	res, err := l.Stream(context.Background(), Command{
		Name:     "sh",
		Args:     []string{"-c", "echo out; echo err >&2; echo 'pmstatus:tor:50:Installing' >&3; exit 3"},
		StatusFD: func(s string) { status = append(status, s) },
	}, func(s string) { lines = append(lines, s) })

	if res.ExitCode != 3 || err == nil {
		t.Fatalf("exit=%d err=%v", res.ExitCode, err)
	}
	if !strings.Contains(err.Error(), "status 3") {
		t.Fatalf("error should mention exit status: %v", err)
	}
	if strings.Join(lines, ",") != "out,err" && strings.Join(lines, ",") != "err,out" {
		t.Fatalf("lines = %v", lines)
	}
	if len(status) != 1 || status[0] != "pmstatus:tor:50:Installing" {
		t.Fatalf("status fd lines = %v", status)
	}
}

func TestDryRunRunsReadsButNotWrites(t *testing.T) {
	root := t.TempDir()
	var events []Event
	l := &Local{Root: root, Stamp: "X", Observe: func(e Event) { events = append(events, e) }}
	d := NewDryRun(l)

	res, err := d.Run(context.Background(), Command{Name: "echo", Args: []string{"read"}})
	if err != nil || strings.TrimSpace(res.Output) != "read" {
		t.Fatalf("read-only command should run: %q %v", res.Output, err)
	}
	marker := filepath.Join(root, "ran")
	if _, err := d.Run(context.Background(), Command{Name: "touch", Args: []string{marker}, Mutates: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("mutating command ran during a dry run")
	}
	ch, err := d.WriteFile("/etc/x", []byte("x"), FileOptions{})
	if err != nil || !ch.Created {
		t.Fatalf("dry write: %+v %v", ch, err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/x")); err == nil {
		t.Fatal("file written during a dry run")
	}
	var dry int
	for _, e := range events {
		if e.Dry {
			dry++
		}
	}
	if dry != 2 {
		t.Fatalf("expected 2 dry events, got %d: %+v", dry, events)
	}
}

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"plain":        "plain",
		"":             "''",
		"two words":    "'two words'",
		"it's":         `'it'\''s'`,
		"a=b/c:d":      "a=b/c:d",
		"$(rm -rf /)":  "'$(rm -rf /)'",
		"Tor relay OR": "'Tor relay OR'",
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}
