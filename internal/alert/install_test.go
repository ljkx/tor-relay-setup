package alert

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

const testExe = "/usr/local/bin/tor-relay-setup"

func TestUnits(t *testing.T) {
	service, timer, err := Units(InstallOptions{Executable: testExe})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Type=oneshot\n",
		"ExecStart=/usr/local/bin/tor-relay-setup alert run --config /etc/tor-relay-setup/alerts.toml\n",
		"After=network-online.target\n", "TimeoutStartSec=3min\n", "ProtectSystem=full\n", "ProtectHome=read-only\n",
		"PrivateTmp=yes\n", "PrivateDevices=yes\n", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n",
		"SystemCallArchitectures=native\n",
	} {
		if !strings.Contains(string(service), want) {
			t.Errorf("service lacks %q", want)
		}
	}
	// Settings that would break reading debian-tor's files or sendmail.
	for _, bad := range []string{"\nUser=", "\nDynamicUser=", "\nCapabilityBoundingSet=", "\nNoNewPrivileges=", "\nProtectSystem=strict", "\nMemoryDenyWriteExecute="} {
		if strings.Contains(string(service), bad) {
			t.Errorf("service sets %q", bad)
		}
	}
	for _, want := range []string{"OnBootSec=2min\n", "OnUnitActiveSec=300s\n", "RandomizedDelaySec=30s\n", "WantedBy=timers.target\n", "every 5m0s"} {
		if !strings.Contains(string(timer), want) {
			t.Errorf("timer lacks %q", want)
		}
	}

	_, timer, err = Units(InstallOptions{Executable: testExe, ConfigPath: "/root/alerts.toml", Every: 90 * time.Second})
	if err != nil || !strings.Contains(string(timer), "OnUnitActiveSec=90s\n") {
		t.Errorf("custom interval: %v\n%s", err, timer)
	}
	for _, opt := range []InstallOptions{
		{Executable: testExe, Every: 30 * time.Second},
		{Executable: testExe, Every: 25 * time.Hour},
		{Executable: "tor-relay-setup"},
		{Executable: "/opt/my tools/tor-relay-setup"},
		{Executable: testExe, ConfigPath: "/etc/x;rm -rf /"},
	} {
		if _, _, err := Units(opt); err == nil {
			t.Errorf("%+v should fail", opt)
		}
	}
}

func TestInstallAndUninstall(t *testing.T) {
	fake := host.NewFake()
	var out bytes.Buffer
	if err := Install(context.Background(), fake, InstallOptions{Executable: testExe, Every: 10 * time.Minute}, &out); err != nil {
		t.Fatal(err)
	}
	service, timer, _ := Units(InstallOptions{Executable: testExe, Every: 10 * time.Minute})
	if string(fake.Files[ServicePath]) != string(service) || string(fake.Files[TimerPath]) != string(timer) {
		t.Error("unit files differ from Units")
	}
	if fake.Modes[ServicePath] != 0o644 || fake.Modes[TimerPath] != 0o644 {
		t.Errorf("modes %v %v", fake.Modes[ServicePath], fake.Modes[TimerPath])
	}
	if got := strings.Join(fake.CommandLines(), "; "); got != "systemctl daemon-reload; systemctl enable --now tor-relay-setup-alert.timer" {
		t.Errorf("commands %q", got)
	}
	for _, c := range fake.Commands {
		if !c.Mutates {
			t.Errorf("%s must be marked mutating", c.String())
		}
	}
	if !strings.Contains(out.String(), "wrote "+ServicePath) || !strings.Contains(out.String(), "Alerts run every 10m0s") {
		t.Errorf("output:\n%s", out.String())
	}

	out.Reset()
	fake.Commands = nil
	if err := Uninstall(context.Background(), fake, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.Files[ServicePath]; ok {
		t.Error("service not removed")
	}
	if _, ok := fake.Files[TimerPath]; ok {
		t.Error("timer not removed")
	}
	if got := strings.Join(fake.CommandLines(), "; "); got != "systemctl disable --now tor-relay-setup-alert.timer; systemctl daemon-reload" {
		t.Errorf("commands %q", got)
	}
	out.Reset()
	if err := Uninstall(context.Background(), fake, &out); err != nil || !strings.Contains(out.String(), "not installed") {
		t.Errorf("second uninstall: %v %q", err, out.String())
	}
}

func TestInstallDryRun(t *testing.T) {
	fake := host.NewFake()
	fake.Dry = true
	var out bytes.Buffer
	if err := Install(context.Background(), fake, InstallOptions{Executable: testExe}, &out); err != nil {
		t.Fatal(err)
	}
	if len(fake.Files) != 0 {
		t.Errorf("dry run wrote %v", fake.Files)
	}
	for _, want := range []string{
		"would write " + ServicePath + ":\n# Written by tor-relay-setup", "ExecStart=" + testExe + " alert run",
		"would write " + TimerPath + ":\n", "would run systemctl daemon-reload\n", "would run systemctl enable --now tor-relay-setup-alert.timer\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, out.String())
		}
	}

	// A dry-run uninstall of installed units only reports.
	fake.Dry = false
	fake.Files[ServicePath], fake.Files[TimerPath] = []byte("s"), []byte("t")
	fake.Dry = true
	out.Reset()
	if err := Uninstall(context.Background(), fake, &out); err != nil {
		t.Fatal(err)
	}
	if len(fake.Files) != 2 || !strings.Contains(out.String(), "would remove "+TimerPath) || !strings.Contains(out.String(), "would run systemctl disable --now") {
		t.Errorf("files %v, output:\n%s", fake.Files, out.String())
	}
}
