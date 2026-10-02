package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ljkx/tor-relay-setup/internal/host"
	"github.com/ljkx/tor-relay-setup/internal/serve"
)

func serveConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "etc", "serve.toml")
}

func TestServePasswdFromStdin(t *testing.T) {
	clearRoot(t)
	path := serveConfigPath(t)
	var out, errOut strings.Builder
	code := run([]string{"fleet", "serve", "passwd", "alice", "--config", path, "--stdin"}, strings.NewReader("correct horse battery\n"), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config %v %v", info, err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "correct horse") || strings.Contains(out.String()+errOut.String(), "correct horse") {
		t.Error("the password is stored or printed in clear")
	}
	c, err := serve.Load(serveHost(), path)
	if err != nil || len(c.Users) != 1 || c.Users[0].Name != "alice" || !serve.VerifyPassword(c.Users[0].Hash, "correct horse battery") {
		t.Fatalf("config %+v %v\n%s", c, err, data)
	}
	if !strings.Contains(out.String(), "Saved the password of alice") {
		t.Errorf("stdout %q", out.String())
	}

	// A too-short password changes nothing.
	before, _ := os.ReadFile(path)
	code = run([]string{"fleet", "serve", "passwd", "alice", "--config", path, "--stdin"}, strings.NewReader("short\n"), io.Discard, &errOut)
	after, _ := os.ReadFile(path)
	if code != 1 || string(before) != string(after) {
		t.Errorf("short password: exit %d", code)
	}
}

func TestServePasswdFromTerminal(t *testing.T) {
	clearRoot(t)
	path := serveConfigPath(t)
	origTerm, origRead := stdinIsTerminal, readPassword
	t.Cleanup(func() { stdinIsTerminal, readPassword = origTerm, origRead })

	// Without a terminal and without --stdin it refuses.
	stdinIsTerminal = func(io.Reader) bool { return false }
	var errOut strings.Builder
	if code := run([]string{"fleet", "serve", "passwd", "bob", "--config", path}, strings.NewReader("x\n"), io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "--stdin") {
		t.Errorf("non-terminal: exit %d %q", code, errOut.String())
	}

	stdinIsTerminal = func(io.Reader) bool { return true }
	answers := []string{"first password!", "second password"}
	var prompts []string
	readPassword = func(prompt string) ([]byte, error) {
		prompts = append(prompts, prompt)
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	errOut.Reset()
	if code := run([]string{"fleet", "serve", "passwd", "bob", "--config", path}, strings.NewReader(""), io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "differ") {
		t.Errorf("mismatch: exit %d %q", code, errOut.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("a mismatch wrote the config")
	}
	if len(prompts) != 2 || !strings.Contains(prompts[0], "bob") {
		t.Errorf("prompts %q", prompts)
	}
	answers = []string{"same password!", "same password!"}
	if code := run([]string{"fleet", "serve", "passwd", "bob", "--config", path}, strings.NewReader(""), io.Discard, &errOut); code != 0 {
		t.Fatalf("exit %d %s", code, errOut.String())
	}
	readPassword = func(string) ([]byte, error) { return nil, errors.New("no tty") }
	if code := run([]string{"fleet", "serve", "passwd", "bob", "--config", path}, strings.NewReader(""), io.Discard, io.Discard); code != 1 {
		t.Errorf("read error: exit %d", code)
	}
}

func TestServeToken(t *testing.T) {
	clearRoot(t)
	path := serveConfigPath(t)
	var out, errOut strings.Builder
	if code := run([]string{"fleet", "serve", "token", "--config", path}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	token := strings.TrimSpace(out.String())
	if !strings.HasPrefix(token, "trs_") || strings.Contains(token, "\n") {
		t.Fatalf("stdout %q", out.String())
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), token) || strings.Contains(errOut.String(), token) {
		t.Error("the token itself was stored or printed twice")
	}
	c, err := serve.Load(serveHost(), path)
	if err != nil || c.MetricsTokenSHA256 != serve.TokenSum(token) {
		t.Errorf("config %+v %v", c, err)
	}
	// A new token replaces the old one.
	out.Reset()
	if code := run([]string{"fleet", "serve", "token", "--config", path}, strings.NewReader(""), &out, io.Discard); code != 0 {
		t.Fatal(code)
	}
	if c, _ := serve.Load(serveHost(), path); c.MetricsTokenSHA256 != serve.TokenSum(strings.TrimSpace(out.String())) {
		t.Error("the token was not replaced")
	}
	// A config others can read is never edited.
	_ = os.Chmod(path, 0o644)
	if code := run([]string{"fleet", "serve", "token", "--config", path}, strings.NewReader(""), io.Discard, io.Discard); code != 1 {
		t.Errorf("world-readable config: exit %d", code)
	}
}

func TestServeFlagChecks(t *testing.T) {
	clearRoot(t)
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"fleet", "serve", "frobnicate"}, "unknown fleet serve command"},
		{[]string{"fleet", "serve", "passwd"}, "needs a user name"},
		{[]string{"fleet", "serve", "passwd", "a", "b"}, "unexpected argument"},
		{[]string{"fleet", "status", "--demo"}, "--demo is only used with fleet serve"},
		{[]string{"fleet", "serve", "token", "--demo"}, "--demo is only used with fleet serve"},
		{[]string{"fleet", "serve", "--stdin"}, "--stdin is only used with fleet serve passwd"},
		{[]string{"fleet", "serve", "--only", "x"}, "not used with fleet serve"},
		{[]string{"fleet", "serve", "--json"}, "not used with fleet serve"},
		{[]string{"fleet", "serve", "token", "--inventory", "f.toml"}, "--inventory is not used with fleet serve token"},
		{[]string{"fleet", "bogus"}, "use status, serve, restart"},
	} {
		code, _, errOut := runCLI(t, tt.args...)
		if code != 2 || !strings.Contains(errOut, tt.want) {
			t.Errorf("%q: exit %d %q, want %q", tt.args, code, errOut, tt.want)
		}
	}
	code, out, _ := runCLI(t, "--help")
	if code != 0 || !strings.Contains(out, "fleet serve [--inventory FILE]") || !strings.Contains(out, "fleet serve passwd USER") {
		t.Error("usage lacks fleet serve")
	}
}

func TestFleetServeWiring(t *testing.T) {
	clearRoot(t)
	orig := serveRun
	t.Cleanup(func() { serveRun = orig })
	var got serve.Options
	serveRun = func(_ context.Context, o serve.Options) error { got = o; return nil }

	// --demo without a config: defaults, the demo login, a lively interval.
	if code, _, errOut := runCLI(t, "fleet", "serve", "--demo"); code != 0 {
		t.Fatalf("demo: exit %d %s", code, errOut)
	}
	if !got.Demo || !got.DemoLogin || got.Config.Listen != serve.DefaultListen || got.Config.ProbeInterval.Duration != 10*time.Second ||
		len(got.Inventory.Entries) != 12 || got.Config.MetricsTokenSHA256 != serve.TokenSum(serve.DemoToken) || got.CachePath != "" {
		t.Errorf("demo options %+v", got)
	}

	// Without --demo a missing default config is explained.
	dir := t.TempDir()
	code, _, errOut := runCLI(t, "fleet", "serve", "--config", filepath.Join(dir, "missing.toml"))
	if code != 1 || !strings.Contains(errOut, "missing.toml") {
		t.Errorf("missing config: exit %d %q", code, errOut)
	}

	// A real config with an inventory.
	cache := useCacheDir(t)
	fake := fakeFleet(t)
	fleetHosts(t, fake, false)
	inv := writeInventory(t)
	path := filepath.Join(dir, "serve.toml")
	if err := os.WriteFile(path, []byte("listen = \"127.0.0.1:9851\"\nprivacy = true\nmetrics_token_sha256 = \""+serve.TokenSum("t")+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCLI(t, "fleet", "serve", "--config", path, "--inventory", inv); code != 0 {
		t.Fatalf("serve: exit %d %s", code, errOut)
	}
	if got.Demo || got.Config.Listen != "127.0.0.1:9851" || !got.Config.Privacy || len(got.Inventory.Entries) != 3 || !strings.HasPrefix(got.CachePath, cache) || got.Source == nil {
		t.Errorf("serve options %+v", got)
	}
	if code, _, errOut := runCLI(t, "fleet", "serve", "--config", path); code != 1 || !strings.Contains(errOut, "no inventory") {
		t.Errorf("no inventory: exit %d %q", code, errOut)
	}
	// The config file must be private.
	_ = os.Chmod(path, 0o644)
	if code, _, errOut := runCLI(t, "fleet", "serve", "--config", path, "--inventory", inv); code != 1 || !strings.Contains(errOut, "chmod 600") {
		t.Errorf("readable config: exit %d %q", code, errOut)
	}
}

func serveHost() *host.Local { return host.NewLocal() }
