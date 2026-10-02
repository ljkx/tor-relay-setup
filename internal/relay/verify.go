package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ljkx/tor-relay-setup/internal/host"
)

// ServiceDefaultsTorrc is the defaults file Debian's tor@default.service
// passes to tor (User, DataDirectory, ...).
const ServiceDefaultsTorrc = "/usr/share/tor/tor-service-defaults-torrc"

// ErrTorMissing is returned by Verify when the tor binary is not installed,
// so callers can skip verification (for example before the package lands).
var ErrTorMissing = errors.New("tor command not found; cannot verify torrc")

// verifyDetailLines caps how much tor output a verification error carries.
const verifyDetailLines = 8

// Verify asks tor to validate a torrc for the default instance; see
// VerifyInstance.
func Verify(ctx context.Context, h host.Host, torrcPath string) error {
	return VerifyInstance(ctx, h, DefaultInstance(), torrcPath)
}

// VerifyInstance asks tor to validate the torrc at torrcPath for inst
// without starting a relay. When the instance's defaults file exists it
// mirrors the ExecStartPre check of the instance's unit, so the candidate is
// validated with the same defaults: tor@default.service passes
// tor-service-defaults-torrc and --RunAsDaemon 0; tor@.service first
// replaces @@NAME@@ in tor-service-defaults-torrc-instances (which sets
// RunAsDaemon 0 itself). tor rejects a User that does not exist, so a named
// instance verifies only once tor-instance-create has run. The command is
// read-only, so it also runs during a dry run.
func VerifyInstance(ctx context.Context, h host.Host, inst Instance, torrcPath string) error {
	if _, err := h.LookPath("tor"); err != nil {
		return ErrTorMissing
	}
	inst = inst.OrDefault()
	args := []string{"-f", torrcPath, "--verify-config"}
	if inst.IsDefault() {
		if _, err := h.Stat(inst.DefaultsTorrc); err == nil {
			args = []string{"--defaults-torrc", inst.DefaultsTorrc, "-f", torrcPath, "--RunAsDaemon", "0", "--verify-config"}
		}
	} else if tmpl, err := h.ReadFile(inst.DefaultsTorrc); err == nil {
		defaults, err := instanceDefaults(tmpl, inst.Name)
		if err != nil {
			return err
		}
		defer os.Remove(defaults)
		args = []string{"--defaults-torrc", defaults, "-f", torrcPath, "--verify-config"}
	}
	res, err := h.Run(ctx, host.Command{Name: "tor", Args: args})
	if err == nil && res.ExitCode == 0 {
		return nil
	}

	output, code := res.Output, res.ExitCode
	var exitErr *host.ExitError
	if errors.As(err, &exitErr) {
		if output == "" {
			output = exitErr.Output
		}
		if code == 0 {
			code = exitErr.ExitCode
		}
	} else if err != nil {
		// tor could not run at all (context cancelled, exec failure, ...).
		return fmt.Errorf("verify %s: %w", torrcPath, err)
	}

	detail := usefulTorOutput(output, verifyDetailLines)
	if detail == "" {
		return fmt.Errorf("tor rejected %s (exit status %d)", torrcPath, code)
	}
	return fmt.Errorf("tor rejected %s (exit status %d):\n%s", torrcPath, code, detail)
}

// instanceDefaults writes the defaults torrc tor@NAME.service would build
// (the template with @@NAME@@ replaced, like its sed ExecStartPre) to a
// private temporary file and returns its path; the caller removes it.
func instanceDefaults(tmpl []byte, name string) (string, error) {
	f, err := os.CreateTemp("", "tor-instance-defaults-")
	if err != nil {
		return "", err
	}
	_, err = f.Write(bytes.ReplaceAll(tmpl, []byte("@@NAME@@"), []byte(name)))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// usefulTorOutput returns the last n lines of tor output without the
// "[notice]" chatter (version banners, "Read configuration file ..."), which
// never explains a failure. [warn] and [err] lines are what matter. If only
// notices were printed they are returned rather than nothing.
func usefulTorOutput(output string, n int) string {
	var kept, all []string
	for line := range strings.Lines(output) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		all = append(all, line)
		if !strings.Contains(line, "[notice]") {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		kept = all
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	return strings.Join(kept, "\n")
}
